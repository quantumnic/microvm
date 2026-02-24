/// VirtIO 9P Filesystem Device — host directory passthrough to the guest
///
/// VirtIO device type 9. Implements the 9P2000.L protocol over VirtIO transport,
/// allowing the guest to mount a host directory via:
///   mount -t 9p -o trans=virtio,version=9p2000.L microvm /mnt
///
/// This enables seamless file sharing between host and guest without disk images.
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_VERSION: u32 = 2;
const DEVICE_ID: u32 = 9; // 9P transport
const VENDOR_ID: u32 = 0x554D_4356; // "UMCV"

// Device status bits
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;

// Feature bits
const VIRTIO_9P_MOUNT_TAG: u64 = 1; // bit 0: mount tag available

// 9P2000.L message types
const P9_TVERSION: u8 = 100;
const P9_RVERSION: u8 = 101;
const P9_TATTACH: u8 = 104;
const P9_RATTACH: u8 = 105;
#[allow(dead_code)]
const P9_TLERROR: u8 = 106;
const P9_RLERROR: u8 = 107;
const P9_TSTATFS: u8 = 108;
const P9_RSTATFS: u8 = 109;
const P9_TLOPEN: u8 = 112;
const P9_RLOPEN: u8 = 113;
const P9_TLCREATE: u8 = 114;
const P9_RLCREATE: u8 = 115;
const P9_TREAD: u8 = 116; // 9P2000.L uses Treaddir(40) but also old read
const P9_RREAD: u8 = 117;
const P9_TWRITE: u8 = 118;
const P9_RWRITE: u8 = 119;
const P9_TCLUNK: u8 = 120;
const P9_RCLUNK: u8 = 121;
const P9_TWALK: u8 = 110;
const P9_RWALK: u8 = 111;
const P9_TGETATTR: u8 = 124;
const P9_RGETATTR: u8 = 125;
const P9_TSETATTR: u8 = 126;
const P9_RSETATTR: u8 = 127;
const P9_TREADDIR: u8 = 40;
const P9_RREADDIR: u8 = 41;
const P9_TMKDIR: u8 = 72;
const P9_RMKDIR: u8 = 73;
const P9_TUNLINKAT: u8 = 76;
const P9_RUNLINKAT: u8 = 77;
const P9_TRENAMEAT: u8 = 74;
const P9_RRENAMEAT: u8 = 75;

// 9P QID types
const QID_TYPE_DIR: u8 = 0x80;
const QID_TYPE_FILE: u8 = 0x00;

/// A 9P file identifier (QID)
#[derive(Clone, Debug)]
struct Qid {
    qtype: u8,
    version: u32,
    path: u64,
}

impl Qid {
    fn encode(&self) -> [u8; 13] {
        let mut buf = [0u8; 13];
        buf[0] = self.qtype;
        buf[1..5].copy_from_slice(&self.version.to_le_bytes());
        buf[5..13].copy_from_slice(&self.path.to_le_bytes());
        buf
    }
}

/// A file handle (fid) bound to a path
#[derive(Clone, Debug)]
struct Fid {
    path: PathBuf,
    qid: Qid,
    /// Open file handle for read/write
    open_file: Option<usize>, // index into open_files
}

pub struct Virtio9p {
    // VirtIO transport
    status: u32,
    queue_sel: u32,
    queue_desc: u64,
    queue_driver: u64,
    queue_device: u64,
    queue_num: u32,
    queue_ready: bool,
    last_avail_idx: u16,
    interrupt_status: u32,
    guest_features_sel: u32,
    #[allow(dead_code)]
    guest_features: u64,
    driver_features_sel: u32,
    driver_features: u64,
    notify: bool,

    // 9P state
    root_path: PathBuf,
    mount_tag: String,
    fids: HashMap<u32, Fid>,
    open_files: Vec<Option<fs::File>>,
    next_qid_path: u64,
    /// Maximum message size negotiated
    msize: u32,
}

impl Default for Virtio9p {
    fn default() -> Self {
        Self::new()
    }
}

impl Virtio9p {
    pub fn new() -> Self {
        Self {
            status: 0,
            queue_sel: 0,
            queue_desc: 0,
            queue_driver: 0,
            queue_device: 0,
            queue_num: 256,
            queue_ready: false,
            last_avail_idx: 0,
            interrupt_status: 0,
            guest_features_sel: 0,
            guest_features: 0,
            driver_features_sel: 0,
            driver_features: 0,
            notify: false,

            root_path: PathBuf::new(),
            mount_tag: "microvm".to_string(),
            fids: HashMap::new(),
            open_files: Vec::new(),
            next_qid_path: 1,
            msize: 8192,
        }
    }

    /// Set the host directory to share
    pub fn set_root(&mut self, path: &Path) {
        self.root_path = path.to_path_buf();
    }

    /// Check if a root path is configured (device is active)
    pub fn is_active(&self) -> bool {
        !self.root_path.as_os_str().is_empty()
    }

    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            0x000 => VIRTIO_MAGIC,
            0x004 => VIRTIO_VERSION,
            0x008 => {
                if self.is_active() {
                    DEVICE_ID
                } else {
                    0
                }
            }
            0x00C => VENDOR_ID,
            0x010 => {
                if self.guest_features_sel == 0 {
                    VIRTIO_9P_MOUNT_TAG as u32
                } else if self.guest_features_sel == 1 {
                    1 // VIRTIO_F_VERSION_1
                } else {
                    0
                }
            }
            0x034 => self.queue_num.min(256),
            0x044 => u32::from(self.queue_ready),
            0x060 => self.interrupt_status,
            0x070 => self.status,
            0x0FC => 0x01, // ConfigGeneration
            // Config space: mount tag
            // Offset 0x100+0: tag length (u16 LE)
            // Offset 0x100+2...: tag bytes
            off if off >= 0x100 => {
                let config_off = (off - 0x100) as usize;
                let tag_bytes = self.mount_tag.as_bytes();
                let tag_len = tag_bytes.len() as u16;
                // Build config: [len_lo, len_hi, tag_bytes...]
                let mut config = Vec::with_capacity(2 + tag_bytes.len());
                config.extend_from_slice(&tag_len.to_le_bytes());
                config.extend_from_slice(tag_bytes);

                // Read 4 bytes from config_off
                let mut val = 0u32;
                for i in 0..4 {
                    let idx = config_off + i;
                    let byte = if idx < config.len() { config[idx] } else { 0 };
                    val |= (byte as u32) << (i * 8);
                }
                val
            }
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            0x014 => self.guest_features_sel = val as u32,
            0x020 => {
                if self.driver_features_sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                } else {
                    self.driver_features = (self.driver_features & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            0x024 => self.driver_features_sel = val as u32,
            0x030 => self.queue_sel = val as u32,
            0x038 => self.queue_num = (val as u32).min(256),
            0x044 => self.queue_ready = val & 1 != 0,
            0x050 => {
                if val == 0 {
                    self.notify = true;
                }
            }
            0x064 => self.interrupt_status &= !(val as u32),
            0x070 => {
                self.status = val as u32;
                if val == 0 {
                    self.reset();
                }
            }
            0x080 => {
                self.queue_desc = (self.queue_desc & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
            }
            0x084 => {
                self.queue_desc =
                    (self.queue_desc & 0x0000_0000_FFFF_FFFF) | ((val & 0xFFFF_FFFF) << 32);
            }
            0x090 => {
                self.queue_driver =
                    (self.queue_driver & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
            }
            0x094 => {
                self.queue_driver =
                    (self.queue_driver & 0x0000_0000_FFFF_FFFF) | ((val & 0xFFFF_FFFF) << 32);
            }
            0x0A0 => {
                self.queue_device =
                    (self.queue_device & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
            }
            0x0A4 => {
                self.queue_device =
                    (self.queue_device & 0x0000_0000_FFFF_FFFF) | ((val & 0xFFFF_FFFF) << 32);
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.status = 0;
        self.queue_ready = false;
        self.last_avail_idx = 0;
        self.interrupt_status = 0;
        self.notify = false;
        self.queue_desc = 0;
        self.queue_driver = 0;
        self.queue_device = 0;
        self.driver_features = 0;
        self.fids.clear();
        self.open_files.clear();
        self.next_qid_path = 1;
    }

    pub fn has_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    pub fn needs_processing(&self) -> bool {
        self.notify
            && self.queue_ready
            && (self.status & STATUS_DRIVER_OK) != 0
            && (self.status & STATUS_ACKNOWLEDGE) != 0
            && (self.status & STATUS_DRIVER) != 0
            && (self.status & STATUS_FEATURES_OK) != 0
    }

    /// Allocate a QID path counter
    fn alloc_qid_path(&mut self) -> u64 {
        let p = self.next_qid_path;
        self.next_qid_path += 1;
        p
    }

    /// Build a QID from metadata
    fn make_qid(&mut self, meta: &fs::Metadata) -> Qid {
        let qtype = if meta.is_dir() {
            QID_TYPE_DIR
        } else {
            QID_TYPE_FILE
        };
        Qid {
            qtype,
            version: meta.mtime() as u32,
            path: self.alloc_qid_path(),
        }
    }

    /// Resolve a guest path component against root, preventing escape
    fn resolve_path(&self, base: &Path, name: &str) -> Option<PathBuf> {
        if name == ".." || name.contains('/') || name.contains('\0') {
            // For ".." we allow navigating up but not past root
            if name == ".." {
                let parent = base.parent()?;
                if parent.starts_with(&self.root_path) {
                    return Some(parent.to_path_buf());
                }
                return Some(self.root_path.clone());
            }
            return None;
        }
        let resolved = base.join(name);
        // Ensure we don't escape root
        if resolved.starts_with(&self.root_path) {
            Some(resolved)
        } else {
            None
        }
    }

    /// Allocate or reuse an open file slot
    fn alloc_open_file(&mut self, file: fs::File) -> usize {
        for (i, slot) in self.open_files.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(file);
                return i;
            }
        }
        self.open_files.push(Some(file));
        self.open_files.len() - 1
    }

    /// Handle a 9P request message, return response bytes
    fn handle_9p_message(&mut self, req: &[u8]) -> Vec<u8> {
        if req.len() < 7 {
            return self.encode_error(0, 0, libc::EINVAL as u32);
        }

        let _size = u32::from_le_bytes(req[0..4].try_into().unwrap());
        let msg_type = req[4];
        let tag = u16::from_le_bytes(req[5..7].try_into().unwrap());

        match msg_type {
            P9_TVERSION => self.handle_version(tag, &req[7..]),
            P9_TATTACH => self.handle_attach(tag, &req[7..]),
            P9_TWALK => self.handle_walk(tag, &req[7..]),
            P9_TGETATTR => self.handle_getattr(tag, &req[7..]),
            P9_TSETATTR => self.handle_setattr(tag, &req[7..]),
            P9_TLOPEN => self.handle_lopen(tag, &req[7..]),
            P9_TLCREATE => self.handle_lcreate(tag, &req[7..]),
            P9_TREAD => self.handle_read(tag, &req[7..]),
            P9_TWRITE => self.handle_write(tag, &req[7..]),
            P9_TCLUNK => self.handle_clunk(tag, &req[7..]),
            P9_TSTATFS => self.handle_statfs(tag, &req[7..]),
            P9_TREADDIR => self.handle_readdir(tag, &req[7..]),
            P9_TMKDIR => self.handle_mkdir(tag, &req[7..]),
            P9_TUNLINKAT => self.handle_unlinkat(tag, &req[7..]),
            P9_TRENAMEAT => self.handle_renameat(tag, &req[7..]),
            _ => self.encode_error(tag, msg_type, libc::EOPNOTSUPP as u32),
        }
    }

    fn handle_version(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 6 {
            return self.encode_error(tag, P9_TVERSION, libc::EINVAL as u32);
        }
        let msize = u32::from_le_bytes(data[0..4].try_into().unwrap());
        self.msize = msize.min(65536);

        // Respond with 9P2000.L
        let version = b"9P2000.L";
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]); // size placeholder
        resp.push(P9_RVERSION);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&self.msize.to_le_bytes());
        let vlen = version.len() as u16;
        resp.extend_from_slice(&vlen.to_le_bytes());
        resp.extend_from_slice(version);
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_attach(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 12 {
            return self.encode_error(tag, P9_TATTACH, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        // afid at 4..8, ignored
        // uname, aname: parse but ignore

        let path = self.root_path.clone();
        let meta = match fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => return self.encode_error(tag, P9_TATTACH, libc::ENOENT as u32),
        };

        let qid = self.make_qid(&meta);
        self.fids.insert(
            fid,
            Fid {
                path,
                qid: qid.clone(),
                open_file: None,
            },
        );

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RATTACH);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&qid.encode());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_walk(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 10 {
            return self.encode_error(tag, P9_TWALK, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let newfid = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let nwname = u16::from_le_bytes(data[8..10].try_into().unwrap());

        let base_fid = match self.fids.get(&fid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TWALK, libc::ENOENT as u32),
        };

        let mut current_path = base_fid.path.clone();
        let mut qids = Vec::new();
        let mut offset = 10;

        for _ in 0..nwname {
            if offset + 2 > data.len() {
                return self.encode_error(tag, P9_TWALK, libc::EINVAL as u32);
            }
            let name_len = u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap());
            offset += 2;
            if offset + name_len as usize > data.len() {
                return self.encode_error(tag, P9_TWALK, libc::EINVAL as u32);
            }
            let name =
                String::from_utf8_lossy(&data[offset..offset + name_len as usize]).to_string();
            offset += name_len as usize;

            let resolved = match self.resolve_path(&current_path, &name) {
                Some(p) => p,
                None => return self.encode_error(tag, P9_TWALK, libc::ENOENT as u32),
            };

            let meta = match fs::metadata(&resolved) {
                Ok(m) => m,
                Err(_) => return self.encode_error(tag, P9_TWALK, libc::ENOENT as u32),
            };

            let qid = self.make_qid(&meta);
            qids.push(qid);
            current_path = resolved;
        }

        // Create new fid
        let final_qid = if let Some(last) = qids.last() {
            last.clone()
        } else {
            base_fid.qid.clone()
        };

        self.fids.insert(
            newfid,
            Fid {
                path: current_path,
                qid: final_qid,
                open_file: None,
            },
        );

        // Encode response
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RWALK);
        resp.extend_from_slice(&tag.to_le_bytes());
        let nwqid = qids.len() as u16;
        resp.extend_from_slice(&nwqid.to_le_bytes());
        for qid in &qids {
            resp.extend_from_slice(&qid.encode());
        }
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_getattr(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 12 {
            return self.encode_error(tag, P9_TGETATTR, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let request_mask = u64::from_le_bytes(data[4..12].try_into().unwrap());

        let fid_entry = match self.fids.get(&fid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TGETATTR, libc::ENOENT as u32),
        };

        let meta = match fs::metadata(&fid_entry.path) {
            Ok(m) => m,
            Err(_) => return self.encode_error(tag, P9_TGETATTR, libc::ENOENT as u32),
        };

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RGETATTR);
        resp.extend_from_slice(&tag.to_le_bytes());

        // valid mask — return same as requested
        resp.extend_from_slice(&request_mask.to_le_bytes());
        // qid
        resp.extend_from_slice(&fid_entry.qid.encode());
        // mode
        resp.extend_from_slice(&meta.mode().to_le_bytes());
        // uid, gid
        resp.extend_from_slice(&meta.uid().to_le_bytes());
        resp.extend_from_slice(&meta.gid().to_le_bytes());
        // nlink
        resp.extend_from_slice(&meta.nlink().to_le_bytes());
        // rdev
        resp.extend_from_slice(&meta.rdev().to_le_bytes());
        // size
        resp.extend_from_slice(&meta.size().to_le_bytes());
        // blksize
        resp.extend_from_slice(&meta.blksize().to_le_bytes());
        // blocks
        resp.extend_from_slice(&meta.blocks().to_le_bytes());
        // atime_sec, atime_nsec
        resp.extend_from_slice(&(meta.atime() as u64).to_le_bytes());
        resp.extend_from_slice(&(meta.atime_nsec() as u64).to_le_bytes());
        // mtime_sec, mtime_nsec
        resp.extend_from_slice(&(meta.mtime() as u64).to_le_bytes());
        resp.extend_from_slice(&(meta.mtime_nsec() as u64).to_le_bytes());
        // ctime_sec, ctime_nsec
        resp.extend_from_slice(&(meta.ctime() as u64).to_le_bytes());
        resp.extend_from_slice(&(meta.ctime_nsec() as u64).to_le_bytes());
        // btime (not available on all platforms, use 0)
        resp.extend_from_slice(&0u64.to_le_bytes());
        resp.extend_from_slice(&0u64.to_le_bytes());
        // gen, data_version
        resp.extend_from_slice(&0u64.to_le_bytes());
        resp.extend_from_slice(&0u64.to_le_bytes());

        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_setattr(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 4 {
            return self.encode_error(tag, P9_TSETATTR, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());

        if !self.fids.contains_key(&fid) {
            return self.encode_error(tag, P9_TSETATTR, libc::ENOENT as u32);
        }

        // We accept but mostly ignore setattr for now (read-only friendly)
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RSETATTR);
        resp.extend_from_slice(&tag.to_le_bytes());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_lopen(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 8 {
            return self.encode_error(tag, P9_TLOPEN, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let flags = u32::from_le_bytes(data[4..8].try_into().unwrap());

        let fid_entry = match self.fids.get(&fid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TLOPEN, libc::ENOENT as u32),
        };

        // For directories, we don't need a file handle
        if fid_entry.qid.qtype & QID_TYPE_DIR != 0 {
            let mut resp = Vec::new();
            resp.extend_from_slice(&[0u8; 4]);
            resp.push(P9_RLOPEN);
            resp.extend_from_slice(&tag.to_le_bytes());
            resp.extend_from_slice(&fid_entry.qid.encode());
            resp.extend_from_slice(&0u32.to_le_bytes()); // iounit
            let size = resp.len() as u32;
            resp[0..4].copy_from_slice(&size.to_le_bytes());
            return resp;
        }

        // Open file with appropriate mode
        let write = (flags & (libc::O_WRONLY as u32 | libc::O_RDWR as u32)) != 0;
        let file = if write {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&fid_entry.path)
        } else {
            fs::File::open(&fid_entry.path)
        };

        let file = match file {
            Ok(f) => f,
            Err(e) => {
                return self.encode_error(
                    tag,
                    P9_TLOPEN,
                    e.raw_os_error().unwrap_or(libc::EIO) as u32,
                );
            }
        };

        let file_idx = self.alloc_open_file(file);
        if let Some(f) = self.fids.get_mut(&fid) {
            f.open_file = Some(file_idx);
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RLOPEN);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&fid_entry.qid.encode());
        resp.extend_from_slice(&0u32.to_le_bytes()); // iounit
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_lcreate(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 12 {
            return self.encode_error(tag, P9_TLCREATE, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let name_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        if data.len() < 8 + name_len + 8 {
            return self.encode_error(tag, P9_TLCREATE, libc::EINVAL as u32);
        }
        let name = String::from_utf8_lossy(&data[8..8 + name_len]).to_string();
        // flags at 8+name_len..8+name_len+4, mode at 8+name_len+4..8+name_len+8

        let fid_entry = match self.fids.get(&fid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TLCREATE, libc::ENOENT as u32),
        };

        let new_path = match self.resolve_path(&fid_entry.path, &name) {
            Some(p) => p,
            None => return self.encode_error(tag, P9_TLCREATE, libc::EINVAL as u32),
        };

        let file = match fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&new_path)
        {
            Ok(f) => f,
            Err(e) => {
                return self.encode_error(
                    tag,
                    P9_TLCREATE,
                    e.raw_os_error().unwrap_or(libc::EIO) as u32,
                );
            }
        };

        let meta = match file.metadata() {
            Ok(m) => m,
            Err(_) => return self.encode_error(tag, P9_TLCREATE, libc::EIO as u32),
        };

        let qid = self.make_qid(&meta);
        let file_idx = self.alloc_open_file(file);

        // Update fid to point to new file
        if let Some(f) = self.fids.get_mut(&fid) {
            f.path = new_path;
            f.qid = qid.clone();
            f.open_file = Some(file_idx);
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RLCREATE);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&qid.encode());
        resp.extend_from_slice(&0u32.to_le_bytes()); // iounit
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_read(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 16 {
            return self.encode_error(tag, P9_TREAD, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let offset = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let count = u32::from_le_bytes(data[12..16].try_into().unwrap());

        let fid_entry = match self.fids.get(&fid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TREAD, libc::ENOENT as u32),
        };

        let file_idx = match fid_entry.open_file {
            Some(idx) => idx,
            None => return self.encode_error(tag, P9_TREAD, libc::EBADF as u32),
        };

        let max_read = count.min(self.msize - 11) as usize; // 4(size)+1(type)+2(tag)+4(count)
        let mut buf = vec![0u8; max_read];

        let bytes_read = match self.open_files.get_mut(file_idx) {
            Some(Some(file)) => {
                if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)) {
                    return self.encode_error(
                        tag,
                        P9_TREAD,
                        e.raw_os_error().unwrap_or(libc::EIO) as u32,
                    );
                }
                match file.read(&mut buf) {
                    Ok(n) => n,
                    Err(e) => {
                        return self.encode_error(
                            tag,
                            P9_TREAD,
                            e.raw_os_error().unwrap_or(libc::EIO) as u32,
                        );
                    }
                }
            }
            _ => return self.encode_error(tag, P9_TREAD, libc::EBADF as u32),
        };

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RREAD);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&(bytes_read as u32).to_le_bytes());
        resp.extend_from_slice(&buf[..bytes_read]);
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_write(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 16 {
            return self.encode_error(tag, P9_TWRITE, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let offset = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let count = u32::from_le_bytes(data[12..16].try_into().unwrap());

        let fid_entry = match self.fids.get(&fid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TWRITE, libc::ENOENT as u32),
        };

        let file_idx = match fid_entry.open_file {
            Some(idx) => idx,
            None => return self.encode_error(tag, P9_TWRITE, libc::EBADF as u32),
        };

        let write_data = if data.len() >= 16 + count as usize {
            &data[16..16 + count as usize]
        } else {
            &data[16..]
        };

        let bytes_written = match self.open_files.get_mut(file_idx) {
            Some(Some(file)) => {
                if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)) {
                    return self.encode_error(
                        tag,
                        P9_TWRITE,
                        e.raw_os_error().unwrap_or(libc::EIO) as u32,
                    );
                }
                match file.write(write_data) {
                    Ok(n) => n,
                    Err(e) => {
                        return self.encode_error(
                            tag,
                            P9_TWRITE,
                            e.raw_os_error().unwrap_or(libc::EIO) as u32,
                        );
                    }
                }
            }
            _ => return self.encode_error(tag, P9_TWRITE, libc::EBADF as u32),
        };

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RWRITE);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&(bytes_written as u32).to_le_bytes());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_clunk(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 4 {
            return self.encode_error(tag, P9_TCLUNK, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());

        // Close any open file
        if let Some(entry) = self.fids.remove(&fid) {
            if let Some(file_idx) = entry.open_file {
                if let Some(slot) = self.open_files.get_mut(file_idx) {
                    *slot = None;
                }
            }
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RCLUNK);
        resp.extend_from_slice(&tag.to_le_bytes());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_statfs(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 4 {
            return self.encode_error(tag, P9_TSTATFS, libc::EINVAL as u32);
        }
        // Return a synthetic statfs
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RSTATFS);
        resp.extend_from_slice(&tag.to_le_bytes());
        // type
        resp.extend_from_slice(&0x01021997u32.to_le_bytes()); // V9FS_MAGIC
                                                              // bsize
        resp.extend_from_slice(&4096u32.to_le_bytes());
        // blocks, bfree, bavail
        resp.extend_from_slice(&1048576u64.to_le_bytes());
        resp.extend_from_slice(&524288u64.to_le_bytes());
        resp.extend_from_slice(&524288u64.to_le_bytes());
        // files, ffree
        resp.extend_from_slice(&1000000u64.to_le_bytes());
        resp.extend_from_slice(&500000u64.to_le_bytes());
        // fsid
        resp.extend_from_slice(&0u64.to_le_bytes());
        // namelen
        resp.extend_from_slice(&255u32.to_le_bytes());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_readdir(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 16 {
            return self.encode_error(tag, P9_TREADDIR, libc::EINVAL as u32);
        }
        let fid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let dir_offset = u64::from_le_bytes(data[4..12].try_into().unwrap());
        let count = u32::from_le_bytes(data[12..16].try_into().unwrap());

        let fid_entry = match self.fids.get(&fid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TREADDIR, libc::ENOENT as u32),
        };

        let entries: Vec<_> = match fs::read_dir(&fid_entry.path) {
            Ok(rd) => rd.filter_map(|e| e.ok()).collect(),
            Err(e) => {
                return self.encode_error(
                    tag,
                    P9_TREADDIR,
                    e.raw_os_error().unwrap_or(libc::EIO) as u32,
                );
            }
        };

        let max_data = count.min(self.msize - 11) as usize;
        let mut dir_data = Vec::new();
        let mut idx = 0u64;

        for entry in &entries {
            if idx < dir_offset {
                idx += 1;
                continue;
            }

            let name = entry.file_name();
            let name_bytes = name.as_encoded_bytes();
            let meta = match entry.metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };

            let qtype = if meta.is_dir() {
                QID_TYPE_DIR
            } else {
                QID_TYPE_FILE
            };

            // dirent: qid[13] + offset[8] + type[1] + name_len[2] + name[n]
            let entry_size = 13 + 8 + 1 + 2 + name_bytes.len();
            if dir_data.len() + entry_size > max_data {
                break;
            }

            // qid
            let qid = Qid {
                qtype,
                version: meta.mtime() as u32,
                path: meta.ino(),
            };
            dir_data.extend_from_slice(&qid.encode());
            // offset (next entry index)
            dir_data.extend_from_slice(&(idx + 1).to_le_bytes());
            // type
            dir_data.push(qtype);
            // name
            let nlen = name_bytes.len() as u16;
            dir_data.extend_from_slice(&nlen.to_le_bytes());
            dir_data.extend_from_slice(name_bytes);

            idx += 1;
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RREADDIR);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&(dir_data.len() as u32).to_le_bytes());
        resp.extend_from_slice(&dir_data);
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_mkdir(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 8 {
            return self.encode_error(tag, P9_TMKDIR, libc::EINVAL as u32);
        }
        let dfid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let name_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        if data.len() < 8 + name_len {
            return self.encode_error(tag, P9_TMKDIR, libc::EINVAL as u32);
        }
        let name = String::from_utf8_lossy(&data[8..8 + name_len]).to_string();

        let fid_entry = match self.fids.get(&dfid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TMKDIR, libc::ENOENT as u32),
        };

        let new_path = match self.resolve_path(&fid_entry.path, &name) {
            Some(p) => p,
            None => return self.encode_error(tag, P9_TMKDIR, libc::EINVAL as u32),
        };

        if let Err(e) = fs::create_dir(&new_path) {
            return self.encode_error(tag, P9_TMKDIR, e.raw_os_error().unwrap_or(libc::EIO) as u32);
        }

        let meta = match fs::metadata(&new_path) {
            Ok(m) => m,
            Err(_) => return self.encode_error(tag, P9_TMKDIR, libc::EIO as u32),
        };

        let qid = self.make_qid(&meta);
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RMKDIR);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&qid.encode());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_unlinkat(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 8 {
            return self.encode_error(tag, P9_TUNLINKAT, libc::EINVAL as u32);
        }
        let dfid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let name_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        if data.len() < 8 + name_len {
            return self.encode_error(tag, P9_TUNLINKAT, libc::EINVAL as u32);
        }
        let name = String::from_utf8_lossy(&data[8..8 + name_len]).to_string();

        let fid_entry = match self.fids.get(&dfid) {
            Some(f) => f.clone(),
            None => return self.encode_error(tag, P9_TUNLINKAT, libc::ENOENT as u32),
        };

        let target = match self.resolve_path(&fid_entry.path, &name) {
            Some(p) => p,
            None => return self.encode_error(tag, P9_TUNLINKAT, libc::EINVAL as u32),
        };

        let result = if target.is_dir() {
            fs::remove_dir(&target)
        } else {
            fs::remove_file(&target)
        };

        if let Err(e) = result {
            return self.encode_error(
                tag,
                P9_TUNLINKAT,
                e.raw_os_error().unwrap_or(libc::EIO) as u32,
            );
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RUNLINKAT);
        resp.extend_from_slice(&tag.to_le_bytes());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn handle_renameat(&mut self, tag: u16, data: &[u8]) -> Vec<u8> {
        if data.len() < 8 {
            return self.encode_error(tag, P9_TRENAMEAT, libc::EINVAL as u32);
        }
        let olddirfid = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let oldname_len = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        if data.len() < 8 + oldname_len + 8 {
            return self.encode_error(tag, P9_TRENAMEAT, libc::EINVAL as u32);
        }
        let oldname = String::from_utf8_lossy(&data[8..8 + oldname_len]).to_string();
        let rest = &data[8 + oldname_len..];
        if rest.len() < 8 {
            return self.encode_error(tag, P9_TRENAMEAT, libc::EINVAL as u32);
        }
        let newdirfid = u32::from_le_bytes(rest[0..4].try_into().unwrap());
        let newname_len = u32::from_le_bytes(rest[4..8].try_into().unwrap()) as usize;
        if rest.len() < 8 + newname_len {
            return self.encode_error(tag, P9_TRENAMEAT, libc::EINVAL as u32);
        }
        let newname = String::from_utf8_lossy(&rest[8..8 + newname_len]).to_string();

        let olddir = match self.fids.get(&olddirfid) {
            Some(f) => f.path.clone(),
            None => return self.encode_error(tag, P9_TRENAMEAT, libc::ENOENT as u32),
        };
        let newdir = match self.fids.get(&newdirfid) {
            Some(f) => f.path.clone(),
            None => return self.encode_error(tag, P9_TRENAMEAT, libc::ENOENT as u32),
        };

        let old_path = match self.resolve_path(&olddir, &oldname) {
            Some(p) => p,
            None => return self.encode_error(tag, P9_TRENAMEAT, libc::EINVAL as u32),
        };
        let new_path = match self.resolve_path(&newdir, &newname) {
            Some(p) => p,
            None => return self.encode_error(tag, P9_TRENAMEAT, libc::EINVAL as u32),
        };

        if let Err(e) = fs::rename(&old_path, &new_path) {
            return self.encode_error(
                tag,
                P9_TRENAMEAT,
                e.raw_os_error().unwrap_or(libc::EIO) as u32,
            );
        }

        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RRENAMEAT);
        resp.extend_from_slice(&tag.to_le_bytes());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    fn encode_error(&self, tag: u16, _msg_type: u8, errno: u32) -> Vec<u8> {
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0u8; 4]);
        resp.push(P9_RLERROR);
        resp.extend_from_slice(&tag.to_le_bytes());
        resp.extend_from_slice(&errno.to_le_bytes());
        let size = resp.len() as u32;
        resp[0..4].copy_from_slice(&size.to_le_bytes());
        resp
    }

    /// Process the virtqueue: handle 9P requests
    pub fn process_queue(&mut self, ram: &mut [u8], dram_base: u64) {
        if !self.needs_processing() {
            return;
        }
        self.notify = false;

        let desc_base = self.queue_desc;
        let avail_base = self.queue_driver;
        let used_base = self.queue_device;
        let queue_size = self.queue_num as u16;

        // Read avail index
        let avail_idx_off = (avail_base - dram_base + 2) as usize;
        if avail_idx_off + 2 > ram.len() {
            return;
        }
        let avail_idx = u16::from_le_bytes([ram[avail_idx_off], ram[avail_idx_off + 1]]);

        let mut used_count = 0u16;

        while self.last_avail_idx != avail_idx {
            let ring_idx = (self.last_avail_idx % queue_size) as usize;
            let avail_ring_off = (avail_base - dram_base + 4 + ring_idx as u64 * 2) as usize;
            if avail_ring_off + 2 > ram.len() {
                break;
            }
            let head_desc_idx =
                u16::from_le_bytes([ram[avail_ring_off], ram[avail_ring_off + 1]]) as u64;

            // Walk descriptor chain: collect request data (readable) and find response buffer (writable)
            let mut request_data = Vec::new();
            let mut response_addr = 0u64;
            let mut response_len = 0u32;
            let mut desc_idx = head_desc_idx;

            loop {
                let desc_off = (desc_base - dram_base + desc_idx * 16) as usize;
                if desc_off + 16 > ram.len() {
                    break;
                }
                let buf_addr = u64::from_le_bytes(ram[desc_off..desc_off + 8].try_into().unwrap());
                let buf_len =
                    u32::from_le_bytes(ram[desc_off + 8..desc_off + 12].try_into().unwrap());
                let flags =
                    u16::from_le_bytes(ram[desc_off + 12..desc_off + 14].try_into().unwrap());
                let next =
                    u16::from_le_bytes(ram[desc_off + 14..desc_off + 16].try_into().unwrap());

                let ram_off = (buf_addr - dram_base) as usize;
                if flags & 2 != 0 {
                    // WRITE flag — device writes here (response buffer)
                    response_addr = buf_addr;
                    response_len = buf_len;
                } else {
                    // Read flag — device reads from here (request data)
                    if ram_off + buf_len as usize <= ram.len() {
                        request_data.extend_from_slice(&ram[ram_off..ram_off + buf_len as usize]);
                    }
                }

                if flags & 1 != 0 {
                    // NEXT flag
                    desc_idx = next as u64;
                } else {
                    break;
                }
            }

            // Handle the 9P message
            let response = self.handle_9p_message(&request_data);

            // Write response
            let write_len = response.len().min(response_len as usize);
            let resp_ram_off = (response_addr - dram_base) as usize;
            if resp_ram_off + write_len <= ram.len() {
                ram[resp_ram_off..resp_ram_off + write_len].copy_from_slice(&response[..write_len]);
            }

            // Write used ring entry
            let used_idx_off = (used_base - dram_base + 2) as usize;
            if used_idx_off + 2 > ram.len() {
                break;
            }
            let current_used_idx = u16::from_le_bytes([ram[used_idx_off], ram[used_idx_off + 1]]);
            let used_ring_entry =
                (used_base - dram_base + 4 + (current_used_idx % queue_size) as u64 * 8) as usize;
            if used_ring_entry + 8 > ram.len() {
                break;
            }
            ram[used_ring_entry..used_ring_entry + 4]
                .copy_from_slice(&(head_desc_idx as u32).to_le_bytes());
            ram[used_ring_entry + 4..used_ring_entry + 8]
                .copy_from_slice(&(write_len as u32).to_le_bytes());

            let new_used_idx = current_used_idx.wrapping_add(1);
            ram[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used_idx.to_le_bytes());

            self.last_avail_idx = self.last_avail_idx.wrapping_add(1);
            used_count += 1;
        }

        if used_count > 0 {
            self.interrupt_status |= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_9p_magic_and_id() {
        let mut dev = Virtio9p::new();
        dev.set_root(Path::new("/tmp"));
        assert_eq!(dev.read(0x000), VIRTIO_MAGIC);
        assert_eq!(dev.read(0x004), VIRTIO_VERSION);
        assert_eq!(dev.read(0x008), 9); // device type 9 = 9P transport
        assert_eq!(dev.read(0x00C), VENDOR_ID);
    }

    #[test]
    fn test_virtio_9p_inactive_device_id_zero() {
        let dev = Virtio9p::new();
        assert_eq!(dev.read(0x008), 0, "inactive device should report ID 0");
    }

    #[test]
    fn test_virtio_9p_mount_tag_feature() {
        let dev = Virtio9p::new();
        // Feature page 0 — VIRTIO_9P_MOUNT_TAG
        assert_eq!(dev.read(0x010), 1);
    }

    #[test]
    fn test_virtio_9p_version1_feature() {
        let mut dev = Virtio9p::new();
        // Select feature page 1
        dev.write(0x014, 1);
        assert_eq!(dev.read(0x010), 1, "VIRTIO_F_VERSION_1 must be set");
    }

    #[test]
    fn test_virtio_9p_config_mount_tag() {
        let dev = Virtio9p::new();
        // Read config at 0x100: first 2 bytes = tag length
        let val = dev.read(0x100);
        let tag_len = val & 0xFFFF;
        assert_eq!(tag_len, 7); // "microvm" = 7 chars
                                // Next bytes are 'm', 'i' from "microvm"
        let tag_bytes = ((val >> 16) & 0xFFFF) as u16;
        assert_eq!(tag_bytes & 0xFF, b'm' as u16);
        assert_eq!((tag_bytes >> 8) & 0xFF, b'i' as u16);
    }

    #[test]
    fn test_virtio_9p_status_lifecycle() {
        let mut dev = Virtio9p::new();
        assert_eq!(dev.read(0x070), 0);
        dev.write(0x070, STATUS_ACKNOWLEDGE as u64);
        assert_eq!(dev.read(0x070), STATUS_ACKNOWLEDGE);
        dev.write(0x070, (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u64);
        assert_eq!(dev.read(0x070), STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        dev.write(0x070, 0);
        assert_eq!(dev.read(0x070), 0);
    }

    #[test]
    fn test_virtio_9p_queue_setup() {
        let mut dev = Virtio9p::new();
        dev.write(0x030, 0);
        assert_eq!(dev.read(0x034), 256);
        dev.write(0x038, 128);
        dev.write(0x080, 0x1000);
        dev.write(0x084, 0);
        dev.write(0x044, 1);
        assert_eq!(dev.read(0x044), 1);
    }

    #[test]
    fn test_virtio_9p_interrupt_ack() {
        let mut dev = Virtio9p::new();
        dev.interrupt_status = 1;
        assert!(dev.has_interrupt());
        dev.write(0x064, 1);
        assert!(!dev.has_interrupt());
    }

    #[test]
    fn test_9p_version_message() {
        let mut dev = Virtio9p::new();
        dev.set_root(Path::new("/tmp"));
        // Build Tversion: size[4] + type[1] + tag[2] + msize[4] + version_len[2] + version
        let version = b"9P2000.L";
        let msize: u32 = 8192;
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]); // size placeholder
        req.push(P9_TVERSION);
        req.extend_from_slice(&0xFFFFu16.to_le_bytes()); // NOTAG
        req.extend_from_slice(&msize.to_le_bytes());
        let vlen = version.len() as u16;
        req.extend_from_slice(&vlen.to_le_bytes());
        req.extend_from_slice(version);
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert!(resp.len() >= 7);
        assert_eq!(resp[4], P9_RVERSION);
    }

    #[test]
    fn test_9p_attach_and_walk() {
        let mut dev = Virtio9p::new();
        let tmp = std::env::temp_dir();
        dev.set_root(&tmp);

        // Attach
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TATTACH);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes()); // fid=0
        req.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // afid=NOFID
                                                             // uname
        let uname = b"root";
        req.extend_from_slice(&(uname.len() as u16).to_le_bytes());
        req.extend_from_slice(uname);
        // aname
        let aname = b"";
        req.extend_from_slice(&(aname.len() as u16).to_le_bytes());
        req.extend_from_slice(aname);
        // n_uname
        req.extend_from_slice(&0u32.to_le_bytes());
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert_eq!(resp[4], P9_RATTACH);

        // Walk with 0 names (clone fid)
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TWALK);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes()); // fid=0
        req.extend_from_slice(&1u32.to_le_bytes()); // newfid=1
        req.extend_from_slice(&0u16.to_le_bytes()); // nwname=0
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert_eq!(resp[4], P9_RWALK);
    }

    #[test]
    fn test_9p_getattr() {
        let mut dev = Virtio9p::new();
        let tmp = std::env::temp_dir();
        dev.set_root(&tmp);

        // Attach fid 0
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TATTACH);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        req.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let uname = b"root";
        req.extend_from_slice(&(uname.len() as u16).to_le_bytes());
        req.extend_from_slice(uname);
        let aname = b"";
        req.extend_from_slice(&(aname.len() as u16).to_le_bytes());
        req.extend_from_slice(aname);
        req.extend_from_slice(&0u32.to_le_bytes());
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());
        dev.handle_9p_message(&req);

        // Getattr
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TGETATTR);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes()); // fid=0
        req.extend_from_slice(&0x3FFFu64.to_le_bytes()); // request_mask = all
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert_eq!(resp[4], P9_RGETATTR);
        // Response should be large enough to contain all stat fields
        assert!(resp.len() > 50);
    }

    #[test]
    fn test_9p_clunk() {
        let mut dev = Virtio9p::new();
        dev.set_root(&std::env::temp_dir());

        // Attach fid 0
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TATTACH);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        req.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let uname = b"root";
        req.extend_from_slice(&(uname.len() as u16).to_le_bytes());
        req.extend_from_slice(uname);
        let aname = b"";
        req.extend_from_slice(&(aname.len() as u16).to_le_bytes());
        req.extend_from_slice(aname);
        req.extend_from_slice(&0u32.to_le_bytes());
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());
        dev.handle_9p_message(&req);

        // Clunk fid 0
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TCLUNK);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes()); // fid=0
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert_eq!(resp[4], P9_RCLUNK);
    }

    #[test]
    fn test_9p_statfs() {
        let mut dev = Virtio9p::new();
        dev.set_root(&std::env::temp_dir());

        // Attach fid 0
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TATTACH);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        req.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let uname = b"root";
        req.extend_from_slice(&(uname.len() as u16).to_le_bytes());
        req.extend_from_slice(uname);
        let aname = b"";
        req.extend_from_slice(&(aname.len() as u16).to_le_bytes());
        req.extend_from_slice(aname);
        req.extend_from_slice(&0u32.to_le_bytes());
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());
        dev.handle_9p_message(&req);

        // Statfs
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TSTATFS);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes()); // fid=0
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert_eq!(resp[4], P9_RSTATFS);
    }

    #[test]
    fn test_9p_error_on_bad_fid() {
        let mut dev = Virtio9p::new();
        dev.set_root(&std::env::temp_dir());

        // Try getattr on non-existent fid
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TGETATTR);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&999u32.to_le_bytes());
        req.extend_from_slice(&0x3FFFu64.to_le_bytes());
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert_eq!(resp[4], P9_RLERROR);
    }

    #[test]
    fn test_9p_readdir() {
        let mut dev = Virtio9p::new();
        let tmp = std::env::temp_dir();
        dev.set_root(&tmp);

        // Attach
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TATTACH);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes());
        req.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        let uname = b"root";
        req.extend_from_slice(&(uname.len() as u16).to_le_bytes());
        req.extend_from_slice(uname);
        let aname = b"";
        req.extend_from_slice(&(aname.len() as u16).to_le_bytes());
        req.extend_from_slice(aname);
        req.extend_from_slice(&0u32.to_le_bytes());
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());
        dev.handle_9p_message(&req);

        // Readdir on fid 0
        let mut req = Vec::new();
        req.extend_from_slice(&[0u8; 4]);
        req.push(P9_TREADDIR);
        req.extend_from_slice(&0u16.to_le_bytes());
        req.extend_from_slice(&0u32.to_le_bytes()); // fid=0
        req.extend_from_slice(&0u64.to_le_bytes()); // offset=0
        req.extend_from_slice(&8192u32.to_le_bytes()); // count
        let size = req.len() as u32;
        req[0..4].copy_from_slice(&size.to_le_bytes());

        let resp = dev.handle_9p_message(&req);
        assert_eq!(resp[4], P9_RREADDIR);
    }
}
