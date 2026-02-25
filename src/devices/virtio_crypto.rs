/// VirtIO Crypto Device — hardware cryptographic acceleration
///
/// VirtIO device type 20. Provides symmetric cipher, hash, and MAC operations
/// to the guest via control and data virtqueues.
///
/// Supported algorithms:
/// - Cipher: AES-CBC, AES-CTR, AES-ECB
/// - Hash: SHA-1, SHA-256, SHA-512
/// - MAC: HMAC-SHA-256
///
/// Reference: VirtIO spec v1.2, section 5.9 (crypto device)
const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_VERSION: u32 = 2;
const DEVICE_ID: u32 = 20; // crypto device
const VENDOR_ID: u32 = 0x554D_4356; // "UMCV"

// Device status bits
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;

// Feature bits
const VIRTIO_CRYPTO_F_CIPHER: u64 = 1 << 0;
const VIRTIO_CRYPTO_F_HASH: u64 = 1 << 1;
const VIRTIO_CRYPTO_F_MAC: u64 = 1 << 2;

// Virtqueue indices
const CONTROLQ: u32 = 0;
const DATAQ: u32 = 1;
const NUM_QUEUES: usize = 2;

// Control request opcodes
const VIRTIO_CRYPTO_CIPHER_CREATE_SESSION: u32 = 0x01;
const VIRTIO_CRYPTO_HASH_CREATE_SESSION: u32 = 0x02;
const VIRTIO_CRYPTO_MAC_CREATE_SESSION: u32 = 0x03;
const VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION: u32 = 0x04;
const VIRTIO_CRYPTO_HASH_DESTROY_SESSION: u32 = 0x05;
const VIRTIO_CRYPTO_MAC_DESTROY_SESSION: u32 = 0x06;

// Data request opcodes
const VIRTIO_CRYPTO_CIPHER_ENCRYPT: u32 = 0x01;
const VIRTIO_CRYPTO_CIPHER_DECRYPT: u32 = 0x02;
const VIRTIO_CRYPTO_HASH: u32 = 0x03;
const VIRTIO_CRYPTO_MAC: u32 = 0x04;

// Cipher algorithms
const VIRTIO_CRYPTO_CIPHER_AES_ECB: u32 = 1;
const VIRTIO_CRYPTO_CIPHER_AES_CBC: u32 = 2;
const VIRTIO_CRYPTO_CIPHER_AES_CTR: u32 = 3;

// Hash algorithms
const VIRTIO_CRYPTO_HASH_SHA1: u32 = 1;
const VIRTIO_CRYPTO_HASH_SHA256: u32 = 2;
const VIRTIO_CRYPTO_HASH_SHA512: u32 = 3;

// MAC algorithms
const VIRTIO_CRYPTO_MAC_HMAC_SHA256: u32 = 1;

// Status codes
const VIRTIO_CRYPTO_OK: u8 = 0;
const VIRTIO_CRYPTO_ERR: u8 = 1;
const VIRTIO_CRYPTO_BADMSG: u8 = 2;
#[allow(dead_code)]
const VIRTIO_CRYPTO_NOTSUPP: u8 = 3;
const VIRTIO_CRYPTO_INVSESS: u8 = 4;

// Descriptor flags
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: u32 = 64;

#[derive(Clone, Debug)]
enum SessionType {
    Cipher { algo: u32, key: Vec<u8> },
    Hash { algo: u32 },
    Mac { algo: u32, key: Vec<u8> },
}

struct Virtqueue {
    desc: u64,
    driver: u64,
    device: u64,
    num: u32,
    ready: bool,
    last_avail_idx: u16,
    notify: bool,
}

impl Virtqueue {
    fn new() -> Self {
        Self {
            desc: 0,
            driver: 0,
            device: 0,
            num: QUEUE_SIZE,
            ready: false,
            last_avail_idx: 0,
            notify: false,
        }
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

pub struct VirtioCrypto {
    status: u32,
    queue_sel: u32,
    queues: [Virtqueue; NUM_QUEUES],
    interrupt_status: u32,
    guest_features_sel: u32,
    #[allow(dead_code)]
    guest_features: u64,
    driver_features_sel: u32,
    driver_features: u64,
    /// Active sessions indexed by session ID
    sessions: Vec<Option<SessionType>>,
    /// Next session ID to allocate
    next_session_id: u64,
    /// Config space: max_dataqueues (u32), max_cipher_key_len (u32), max_auth_key_len (u32), max_src_data_len (u64)
    max_dataqueues: u32,
    max_cipher_key_len: u32,
    max_auth_key_len: u32,
}

impl Default for VirtioCrypto {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioCrypto {
    pub fn new() -> Self {
        Self {
            status: 0,
            queue_sel: 0,
            queues: [Virtqueue::new(), Virtqueue::new()],
            interrupt_status: 0,
            guest_features_sel: 0,
            guest_features: 0,
            driver_features_sel: 0,
            driver_features: 0,
            sessions: Vec::new(),
            next_session_id: 0,
            max_dataqueues: 1,
            max_cipher_key_len: 32, // AES-256 max
            max_auth_key_len: 64,   // HMAC-SHA256 key
        }
    }

    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            0x000 => VIRTIO_MAGIC,
            0x004 => VIRTIO_VERSION,
            0x008 => DEVICE_ID,
            0x00C => VENDOR_ID,
            0x010 => {
                // DeviceFeatures
                if self.guest_features_sel == 0 {
                    (VIRTIO_CRYPTO_F_CIPHER | VIRTIO_CRYPTO_F_HASH | VIRTIO_CRYPTO_F_MAC) as u32
                } else if self.guest_features_sel == 1 {
                    1 // VIRTIO_F_VERSION_1
                } else {
                    0
                }
            }
            0x034 => {
                // QueueNumMax
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].num.min(QUEUE_SIZE)
                } else {
                    0
                }
            }
            0x044 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES && self.queues[sel].ready {
                    1
                } else {
                    0
                }
            }
            0x060 => self.interrupt_status,
            0x070 => self.status,
            0x0FC => 0, // ConfigGeneration
            // Config space
            0x100 => self.status & STATUS_DRIVER_OK, // status for crypto config
            0x104 => self.max_dataqueues,
            0x108 => self.max_cipher_key_len,
            0x10C => self.max_auth_key_len,
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
            0x038 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].num = (val as u32).min(QUEUE_SIZE);
                }
            }
            0x044 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].ready = val & 1 != 0;
                }
            }
            0x050 => {
                let qidx = val as u32;
                if (qidx as usize) < NUM_QUEUES {
                    self.queues[qidx as usize].notify = true;
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
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].desc =
                        (self.queues[sel].desc & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            0x084 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].desc = (self.queues[sel].desc & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            0x090 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].driver =
                        (self.queues[sel].driver & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            0x094 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].driver = (self.queues[sel].driver & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            0x0A0 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].device =
                        (self.queues[sel].device & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            0x0A4 => {
                let sel = self.queue_sel as usize;
                if sel < NUM_QUEUES {
                    self.queues[sel].device = (self.queues[sel].device & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.status = 0;
        self.queue_sel = 0;
        for q in &mut self.queues {
            q.reset();
        }
        self.interrupt_status = 0;
        self.driver_features = 0;
        self.sessions.clear();
        self.next_session_id = 0;
    }

    pub fn has_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    fn queue_active(&self, qidx: usize) -> bool {
        qidx < NUM_QUEUES
            && self.queues[qidx].notify
            && self.queues[qidx].ready
            && (self.status & STATUS_DRIVER_OK) != 0
            && (self.status & STATUS_ACKNOWLEDGE) != 0
            && (self.status & STATUS_DRIVER) != 0
            && (self.status & STATUS_FEATURES_OK) != 0
    }

    pub fn needs_processing(&self) -> bool {
        self.queue_active(CONTROLQ as usize) || self.queue_active(DATAQ as usize)
    }

    /// Process both control and data queues
    pub fn process_queues(&mut self, ram: &mut [u8], dram_base: u64) {
        if self.queue_active(CONTROLQ as usize) {
            self.queues[CONTROLQ as usize].notify = false;
            self.process_controlq(ram, dram_base);
        }
        if self.queue_active(DATAQ as usize) {
            self.queues[DATAQ as usize].notify = false;
            self.process_dataq(ram, dram_base);
        }
    }

    fn read_desc(
        ram: &[u8],
        desc_base: u64,
        idx: u16,
        dram_base: u64,
    ) -> Option<(u64, u32, u16, u16)> {
        let off = (desc_base - dram_base + idx as u64 * 16) as usize;
        if off + 16 > ram.len() {
            return None;
        }
        let addr = u64::from_le_bytes(ram[off..off + 8].try_into().unwrap());
        let len = u32::from_le_bytes(ram[off + 8..off + 12].try_into().unwrap());
        let flags = u16::from_le_bytes(ram[off + 12..off + 14].try_into().unwrap());
        let next = u16::from_le_bytes(ram[off + 14..off + 16].try_into().unwrap());
        Some((addr, len, flags, next))
    }

    fn read_avail_idx(ram: &[u8], avail_base: u64, dram_base: u64) -> Option<u16> {
        let off = (avail_base - dram_base + 2) as usize;
        if off + 2 > ram.len() {
            return None;
        }
        Some(u16::from_le_bytes([ram[off], ram[off + 1]]))
    }

    fn read_avail_ring(ram: &[u8], avail_base: u64, ring_idx: u16, dram_base: u64) -> Option<u16> {
        let off = (avail_base - dram_base + 4 + ring_idx as u64 * 2) as usize;
        if off + 2 > ram.len() {
            return None;
        }
        Some(u16::from_le_bytes([ram[off], ram[off + 1]]))
    }

    fn write_used(
        ram: &mut [u8],
        used_base: u64,
        queue_size: u16,
        desc_idx: u16,
        written: u32,
        dram_base: u64,
    ) {
        let used_idx_off = (used_base - dram_base + 2) as usize;
        if used_idx_off + 2 > ram.len() {
            return;
        }
        let current_used_idx = u16::from_le_bytes([ram[used_idx_off], ram[used_idx_off + 1]]);
        let entry_off =
            (used_base - dram_base + 4 + (current_used_idx % queue_size) as u64 * 8) as usize;
        if entry_off + 8 > ram.len() {
            return;
        }
        ram[entry_off..entry_off + 4].copy_from_slice(&(desc_idx as u32).to_le_bytes());
        ram[entry_off + 4..entry_off + 8].copy_from_slice(&written.to_le_bytes());
        let new_used_idx = current_used_idx.wrapping_add(1);
        ram[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used_idx.to_le_bytes());
    }

    /// Collect all descriptors in a chain
    fn collect_chain(
        ram: &[u8],
        desc_base: u64,
        first: u16,
        dram_base: u64,
    ) -> Vec<(u64, u32, u16)> {
        let mut chain = Vec::new();
        let mut idx = first;
        for _ in 0..64 {
            if let Some((addr, len, flags, next)) = Self::read_desc(ram, desc_base, idx, dram_base)
            {
                chain.push((addr, len, flags));
                if flags & VRING_DESC_F_NEXT == 0 {
                    break;
                }
                idx = next;
            } else {
                break;
            }
        }
        chain
    }

    fn ram_read(ram: &[u8], addr: u64, len: u32, dram_base: u64) -> Option<Vec<u8>> {
        let off = (addr - dram_base) as usize;
        let end = off + len as usize;
        if end > ram.len() {
            return None;
        }
        Some(ram[off..end].to_vec())
    }

    fn ram_write(ram: &mut [u8], addr: u64, data: &[u8], dram_base: u64) {
        let off = (addr - dram_base) as usize;
        if off + data.len() <= ram.len() {
            ram[off..off + data.len()].copy_from_slice(data);
        }
    }

    fn process_controlq(&mut self, ram: &mut [u8], dram_base: u64) {
        let q = &self.queues[CONTROLQ as usize];
        let desc_base = q.desc;
        let avail_base = q.driver;
        let used_base = q.device;
        let queue_size = q.num as u16;
        let mut last_avail = q.last_avail_idx;

        let avail_idx = match Self::read_avail_idx(ram, avail_base, dram_base) {
            Some(v) => v,
            None => return,
        };

        let mut used_count = 0u16;

        while last_avail != avail_idx {
            let ring_idx = last_avail % queue_size;
            let first_desc = match Self::read_avail_ring(ram, avail_base, ring_idx, dram_base) {
                Some(v) => v,
                None => break,
            };

            let chain = Self::collect_chain(ram, desc_base, first_desc, dram_base);

            // Control request: first descriptor is the request header (read-only),
            // last descriptor is status byte (device-writable)
            let status = if chain.len() >= 2 {
                let (hdr_addr, hdr_len, _) = chain[0];
                let (_status_addr, _, _status_flags) = chain[chain.len() - 1];

                if hdr_len >= 8 {
                    if let Some(hdr) = Self::ram_read(ram, hdr_addr, hdr_len.min(256), dram_base) {
                        let opcode = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
                        self.handle_control_request(opcode, &hdr, ram, dram_base, &chain)
                    } else {
                        VIRTIO_CRYPTO_ERR
                    }
                } else {
                    VIRTIO_CRYPTO_BADMSG
                }
            } else {
                VIRTIO_CRYPTO_BADMSG
            };

            // Write status to the last writable descriptor
            if let Some(&(addr, _, flags)) = chain.last() {
                if flags & VRING_DESC_F_WRITE != 0 {
                    Self::ram_write(ram, addr, &[status], dram_base);
                }
            }

            Self::write_used(ram, used_base, queue_size, first_desc, 1, dram_base);
            last_avail = last_avail.wrapping_add(1);
            used_count += 1;
        }

        self.queues[CONTROLQ as usize].last_avail_idx = last_avail;
        if used_count > 0 {
            self.interrupt_status |= 1;
        }
    }

    fn handle_control_request(
        &mut self,
        opcode: u32,
        hdr: &[u8],
        ram: &mut [u8],
        dram_base: u64,
        chain: &[(u64, u32, u16)],
    ) -> u8 {
        match opcode {
            VIRTIO_CRYPTO_CIPHER_CREATE_SESSION => {
                // Header: opcode(4) + algo(4) + key_len(4) + ...
                // Key follows in next descriptor or after header
                if hdr.len() < 12 {
                    return VIRTIO_CRYPTO_BADMSG;
                }
                let algo = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
                let key_len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

                // Validate algorithm
                if !matches!(
                    algo,
                    VIRTIO_CRYPTO_CIPHER_AES_ECB
                        | VIRTIO_CRYPTO_CIPHER_AES_CBC
                        | VIRTIO_CRYPTO_CIPHER_AES_CTR
                ) {
                    return VIRTIO_CRYPTO_ERR;
                }

                // Validate key length (AES: 16, 24, or 32 bytes)
                if !matches!(key_len, 16 | 24 | 32) {
                    return VIRTIO_CRYPTO_ERR;
                }

                // Read key from header (after first 12 bytes) or from next descriptor
                let key = if hdr.len() >= 12 + key_len as usize {
                    hdr[12..12 + key_len as usize].to_vec()
                } else if chain.len() >= 3 {
                    // Key might be in second descriptor
                    let (key_addr, kl, _) = chain[1];
                    Self::ram_read(ram, key_addr, kl.min(key_len), dram_base).unwrap_or_default()
                } else {
                    return VIRTIO_CRYPTO_BADMSG;
                };

                let session_id = self.create_session(SessionType::Cipher { algo, key });

                // Write session_id to the writable descriptor (before status)
                // Find the first writable descriptor that has room for session_id
                for &(addr, len, flags) in chain.iter().rev().skip(1) {
                    if flags & VRING_DESC_F_WRITE != 0 && len >= 8 {
                        Self::ram_write(ram, addr, &session_id.to_le_bytes(), dram_base);
                        break;
                    }
                }

                VIRTIO_CRYPTO_OK
            }

            VIRTIO_CRYPTO_HASH_CREATE_SESSION => {
                if hdr.len() < 8 {
                    return VIRTIO_CRYPTO_BADMSG;
                }
                let algo = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
                if !matches!(
                    algo,
                    VIRTIO_CRYPTO_HASH_SHA1 | VIRTIO_CRYPTO_HASH_SHA256 | VIRTIO_CRYPTO_HASH_SHA512
                ) {
                    return VIRTIO_CRYPTO_ERR;
                }

                let session_id = self.create_session(SessionType::Hash { algo });

                for &(addr, len, flags) in chain.iter().rev().skip(1) {
                    if flags & VRING_DESC_F_WRITE != 0 && len >= 8 {
                        Self::ram_write(ram, addr, &session_id.to_le_bytes(), dram_base);
                        break;
                    }
                }

                VIRTIO_CRYPTO_OK
            }

            VIRTIO_CRYPTO_MAC_CREATE_SESSION => {
                if hdr.len() < 12 {
                    return VIRTIO_CRYPTO_BADMSG;
                }
                let algo = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
                let key_len = u32::from_le_bytes(hdr[8..12].try_into().unwrap());

                if algo != VIRTIO_CRYPTO_MAC_HMAC_SHA256 {
                    return VIRTIO_CRYPTO_ERR;
                }

                let key = if hdr.len() >= 12 + key_len as usize {
                    hdr[12..12 + key_len as usize].to_vec()
                } else if chain.len() >= 3 {
                    let (key_addr, kl, _) = chain[1];
                    Self::ram_read(ram, key_addr, kl.min(key_len), dram_base).unwrap_or_default()
                } else {
                    return VIRTIO_CRYPTO_BADMSG;
                };

                let session_id = self.create_session(SessionType::Mac { algo, key });

                for &(addr, len, flags) in chain.iter().rev().skip(1) {
                    if flags & VRING_DESC_F_WRITE != 0 && len >= 8 {
                        Self::ram_write(ram, addr, &session_id.to_le_bytes(), dram_base);
                        break;
                    }
                }

                VIRTIO_CRYPTO_OK
            }

            VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION
            | VIRTIO_CRYPTO_HASH_DESTROY_SESSION
            | VIRTIO_CRYPTO_MAC_DESTROY_SESSION => {
                if hdr.len() < 12 {
                    return VIRTIO_CRYPTO_BADMSG;
                }
                let session_id = u64::from_le_bytes(hdr[4..12].try_into().unwrap());
                if self.destroy_session(session_id) {
                    VIRTIO_CRYPTO_OK
                } else {
                    VIRTIO_CRYPTO_INVSESS
                }
            }

            _ => VIRTIO_CRYPTO_ERR,
        }
    }

    fn create_session(&mut self, session: SessionType) -> u64 {
        let id = self.next_session_id;
        self.next_session_id += 1;

        // Grow sessions vec if needed
        let idx = id as usize;
        if idx >= self.sessions.len() {
            self.sessions.resize(idx + 1, None);
        }
        self.sessions[idx] = Some(session);
        id
    }

    fn destroy_session(&mut self, id: u64) -> bool {
        let idx = id as usize;
        if idx < self.sessions.len() && self.sessions[idx].is_some() {
            self.sessions[idx] = None;
            true
        } else {
            false
        }
    }

    fn process_dataq(&mut self, ram: &mut [u8], dram_base: u64) {
        let q = &self.queues[DATAQ as usize];
        let desc_base = q.desc;
        let avail_base = q.driver;
        let used_base = q.device;
        let queue_size = q.num as u16;
        let mut last_avail = q.last_avail_idx;

        let avail_idx = match Self::read_avail_idx(ram, avail_base, dram_base) {
            Some(v) => v,
            None => return,
        };

        let mut used_count = 0u16;

        while last_avail != avail_idx {
            let ring_idx = last_avail % queue_size;
            let first_desc = match Self::read_avail_ring(ram, avail_base, ring_idx, dram_base) {
                Some(v) => v,
                None => break,
            };

            let chain = Self::collect_chain(ram, desc_base, first_desc, dram_base);
            let mut total_written = 0u32;

            // Data request format: header(read) + input_data(read) + output_data(write) + status(write)
            if chain.len() >= 3 {
                let (hdr_addr, hdr_len, _) = chain[0];
                if hdr_len >= 12 {
                    if let Some(hdr) = Self::ram_read(ram, hdr_addr, hdr_len.min(256), dram_base) {
                        let opcode = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
                        let session_id = u64::from_le_bytes(hdr[4..12].try_into().unwrap());

                        // Collect input data from read-only descriptors (skip header)
                        let mut input_data = Vec::new();
                        for &(addr, len, flags) in &chain[1..] {
                            if flags & VRING_DESC_F_WRITE == 0 {
                                if let Some(data) = Self::ram_read(ram, addr, len, dram_base) {
                                    input_data.extend_from_slice(&data);
                                }
                            }
                        }

                        let (output, status) =
                            self.handle_data_request(opcode, session_id, &input_data, &hdr);

                        // Write output to first writable descriptor(s), status to last
                        let mut output_written = false;
                        for &(addr, len, flags) in &chain[1..chain.len() - 1] {
                            if flags & VRING_DESC_F_WRITE != 0 && !output_written {
                                let write_len = output.len().min(len as usize);
                                Self::ram_write(ram, addr, &output[..write_len], dram_base);
                                total_written += write_len as u32;
                                output_written = true;
                            }
                        }

                        // Write status to last descriptor
                        if let Some(&(addr, _, flags)) = chain.last() {
                            if flags & VRING_DESC_F_WRITE != 0 {
                                Self::ram_write(ram, addr, &[status], dram_base);
                                total_written += 1;
                            }
                        }
                    }
                }
            }

            Self::write_used(
                ram,
                used_base,
                queue_size,
                first_desc,
                total_written,
                dram_base,
            );
            last_avail = last_avail.wrapping_add(1);
            used_count += 1;
        }

        self.queues[DATAQ as usize].last_avail_idx = last_avail;
        if used_count > 0 {
            self.interrupt_status |= 1;
        }
    }

    fn handle_data_request(
        &self,
        opcode: u32,
        session_id: u64,
        input: &[u8],
        hdr: &[u8],
    ) -> (Vec<u8>, u8) {
        let idx = session_id as usize;
        let session = if idx < self.sessions.len() {
            self.sessions[idx].as_ref()
        } else {
            None
        };

        let session = match session {
            Some(s) => s,
            None => return (Vec::new(), VIRTIO_CRYPTO_INVSESS),
        };

        match (opcode, session) {
            (VIRTIO_CRYPTO_CIPHER_ENCRYPT, SessionType::Cipher { algo, key }) => {
                // Read IV from header (after session_id, at offset 12)
                let iv = if hdr.len() >= 28 {
                    &hdr[12..28]
                } else {
                    &[0u8; 16]
                };
                let output = aes_cipher_op(true, *algo, key, iv, input);
                (output, VIRTIO_CRYPTO_OK)
            }
            (VIRTIO_CRYPTO_CIPHER_DECRYPT, SessionType::Cipher { algo, key }) => {
                let iv = if hdr.len() >= 28 {
                    &hdr[12..28]
                } else {
                    &[0u8; 16]
                };
                let output = aes_cipher_op(false, *algo, key, iv, input);
                (output, VIRTIO_CRYPTO_OK)
            }
            (VIRTIO_CRYPTO_HASH, SessionType::Hash { algo }) => {
                let output = compute_hash(*algo, input);
                (output, VIRTIO_CRYPTO_OK)
            }
            (VIRTIO_CRYPTO_MAC, SessionType::Mac { algo, key }) => {
                let output = compute_mac(*algo, key, input);
                (output, VIRTIO_CRYPTO_OK)
            }
            _ => (Vec::new(), VIRTIO_CRYPTO_ERR),
        }
    }
}

// ============================================================
// Software crypto implementations (pure Rust, no dependencies)
// ============================================================

/// AES S-box
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box
const INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES round constants
const RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

#[allow(dead_code)]
fn xtime(a: u8) -> u8 {
    if a & 0x80 != 0 {
        (a << 1) ^ 0x1b
    } else {
        a << 1
    }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

fn aes_key_expand(key: &[u8]) -> Vec<[u8; 16]> {
    let nk = key.len() / 4; // 4, 6, or 8
    let nr = nk + 6; // 10, 12, or 14
    let total_words = 4 * (nr + 1);

    let mut w = vec![0u32; total_words];
    for i in 0..nk {
        w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
    }

    for i in nk..total_words {
        let mut temp = w[i - 1];
        if i % nk == 0 {
            // RotWord + SubWord + Rcon
            temp = temp.rotate_left(8);
            let bytes = temp.to_be_bytes();
            temp = u32::from_be_bytes([
                SBOX[bytes[0] as usize],
                SBOX[bytes[1] as usize],
                SBOX[bytes[2] as usize],
                SBOX[bytes[3] as usize],
            ]);
            temp ^= (RCON[i / nk] as u32) << 24;
        } else if nk > 6 && i % nk == 4 {
            let bytes = temp.to_be_bytes();
            temp = u32::from_be_bytes([
                SBOX[bytes[0] as usize],
                SBOX[bytes[1] as usize],
                SBOX[bytes[2] as usize],
                SBOX[bytes[3] as usize],
            ]);
        }
        w[i] = w[i - nk] ^ temp;
    }

    // Convert to round keys
    let mut round_keys = Vec::with_capacity(nr + 1);
    for r in 0..=nr {
        let mut rk = [0u8; 16];
        for j in 0..4 {
            let bytes = w[r * 4 + j].to_be_bytes();
            rk[j * 4..j * 4 + 4].copy_from_slice(&bytes);
        }
        round_keys.push(rk);
    }
    round_keys
}

fn aes_encrypt_block(block: &[u8; 16], round_keys: &[[u8; 16]]) -> [u8; 16] {
    let nr = round_keys.len() - 1;
    let mut state = *block;

    // AddRoundKey(0)
    for i in 0..16 {
        state[i] ^= round_keys[0][i];
    }

    for rk in &round_keys[1..nr] {
        // SubBytes
        for i in 0..16 {
            state[i] = SBOX[state[i] as usize];
        }
        // ShiftRows
        let tmp = state;
        state[1] = tmp[5];
        state[5] = tmp[9];
        state[9] = tmp[13];
        state[13] = tmp[1];
        state[2] = tmp[10];
        state[6] = tmp[14];
        state[10] = tmp[2];
        state[14] = tmp[6];
        state[3] = tmp[15];
        state[7] = tmp[3];
        state[11] = tmp[7];
        state[15] = tmp[11];
        // MixColumns
        for col in 0..4 {
            let c = col * 4;
            let a0 = state[c];
            let a1 = state[c + 1];
            let a2 = state[c + 2];
            let a3 = state[c + 3];
            state[c] = gmul(2, a0) ^ gmul(3, a1) ^ a2 ^ a3;
            state[c + 1] = a0 ^ gmul(2, a1) ^ gmul(3, a2) ^ a3;
            state[c + 2] = a0 ^ a1 ^ gmul(2, a2) ^ gmul(3, a3);
            state[c + 3] = gmul(3, a0) ^ a1 ^ a2 ^ gmul(2, a3);
        }
        // AddRoundKey
        for i in 0..16 {
            state[i] ^= rk[i];
        }
    }

    // Final round (no MixColumns)
    for i in 0..16 {
        state[i] = SBOX[state[i] as usize];
    }
    let tmp = state;
    state[1] = tmp[5];
    state[5] = tmp[9];
    state[9] = tmp[13];
    state[13] = tmp[1];
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];
    state[3] = tmp[15];
    state[7] = tmp[3];
    state[11] = tmp[7];
    state[15] = tmp[11];
    for i in 0..16 {
        state[i] ^= round_keys[nr][i];
    }

    state
}

fn aes_decrypt_block(block: &[u8; 16], round_keys: &[[u8; 16]]) -> [u8; 16] {
    let nr = round_keys.len() - 1;
    let mut state = *block;

    // AddRoundKey(nr)
    for i in 0..16 {
        state[i] ^= round_keys[nr][i];
    }

    for round in (1..nr).rev() {
        // InvShiftRows
        let tmp = state;
        state[1] = tmp[13];
        state[5] = tmp[1];
        state[9] = tmp[5];
        state[13] = tmp[9];
        state[2] = tmp[10];
        state[6] = tmp[14];
        state[10] = tmp[2];
        state[14] = tmp[6];
        state[3] = tmp[7];
        state[7] = tmp[11];
        state[11] = tmp[15];
        state[15] = tmp[3];
        // InvSubBytes
        for i in 0..16 {
            state[i] = INV_SBOX[state[i] as usize];
        }
        // AddRoundKey
        for i in 0..16 {
            state[i] ^= round_keys[round][i];
        }
        // InvMixColumns
        for col in 0..4 {
            let c = col * 4;
            let a0 = state[c];
            let a1 = state[c + 1];
            let a2 = state[c + 2];
            let a3 = state[c + 3];
            state[c] = gmul(0x0e, a0) ^ gmul(0x0b, a1) ^ gmul(0x0d, a2) ^ gmul(0x09, a3);
            state[c + 1] = gmul(0x09, a0) ^ gmul(0x0e, a1) ^ gmul(0x0b, a2) ^ gmul(0x0d, a3);
            state[c + 2] = gmul(0x0d, a0) ^ gmul(0x09, a1) ^ gmul(0x0e, a2) ^ gmul(0x0b, a3);
            state[c + 3] = gmul(0x0b, a0) ^ gmul(0x0d, a1) ^ gmul(0x09, a2) ^ gmul(0x0e, a3);
        }
    }

    // Final round (no InvMixColumns)
    let tmp = state;
    state[1] = tmp[13];
    state[5] = tmp[1];
    state[9] = tmp[5];
    state[13] = tmp[9];
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];
    state[3] = tmp[7];
    state[7] = tmp[11];
    state[11] = tmp[15];
    state[15] = tmp[3];
    for i in 0..16 {
        state[i] = INV_SBOX[state[i] as usize];
    }
    for i in 0..16 {
        state[i] ^= round_keys[0][i];
    }

    state
}

fn aes_cipher_op(encrypt: bool, algo: u32, key: &[u8], iv: &[u8], input: &[u8]) -> Vec<u8> {
    if input.is_empty() {
        return Vec::new();
    }

    let round_keys = aes_key_expand(key);
    let mut output = Vec::with_capacity(input.len());

    // Pad input to block boundary with PKCS7-style zero padding
    let padded_len = input.len().div_ceil(16) * 16;
    let mut padded = input.to_vec();
    padded.resize(padded_len, 0);

    match algo {
        VIRTIO_CRYPTO_CIPHER_AES_ECB => {
            for chunk in padded.chunks(16) {
                let block: [u8; 16] = chunk.try_into().unwrap();
                let result = if encrypt {
                    aes_encrypt_block(&block, &round_keys)
                } else {
                    aes_decrypt_block(&block, &round_keys)
                };
                output.extend_from_slice(&result);
            }
        }
        VIRTIO_CRYPTO_CIPHER_AES_CBC => {
            let mut prev = [0u8; 16];
            prev.copy_from_slice(&iv[..16.min(iv.len())]);

            if encrypt {
                for chunk in padded.chunks(16) {
                    let mut block = [0u8; 16];
                    for i in 0..16 {
                        block[i] = chunk[i] ^ prev[i];
                    }
                    let enc = aes_encrypt_block(&block, &round_keys);
                    prev = enc;
                    output.extend_from_slice(&enc);
                }
            } else {
                for chunk in padded.chunks(16) {
                    let block: [u8; 16] = chunk.try_into().unwrap();
                    let dec = aes_decrypt_block(&block, &round_keys);
                    let mut plain = [0u8; 16];
                    for i in 0..16 {
                        plain[i] = dec[i] ^ prev[i];
                    }
                    prev = block;
                    output.extend_from_slice(&plain);
                }
            }
        }
        VIRTIO_CRYPTO_CIPHER_AES_CTR => {
            let mut counter = [0u8; 16];
            counter.copy_from_slice(&iv[..16.min(iv.len())]);

            for chunk in padded.chunks(16) {
                let keystream = aes_encrypt_block(&counter, &round_keys);
                for i in 0..chunk.len() {
                    output.push(chunk[i] ^ keystream[i]);
                }
                // Increment counter (big-endian, last 4 bytes)
                for i in (0..16).rev() {
                    counter[i] = counter[i].wrapping_add(1);
                    if counter[i] != 0 {
                        break;
                    }
                }
            }
        }
        _ => {
            // Unknown algorithm — return zeros
            output.resize(padded_len, 0);
        }
    }

    // Truncate to input length
    output.truncate(input.len());
    output
}

// SHA-256 implementation
fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    // Padding
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

// SHA-1 implementation
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        h0 = h0.wrapping_add(a);
        h1 = h1.wrapping_add(b);
        h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d);
        h4 = h4.wrapping_add(e);
    }

    let mut result = [0u8; 20];
    result[0..4].copy_from_slice(&h0.to_be_bytes());
    result[4..8].copy_from_slice(&h1.to_be_bytes());
    result[8..12].copy_from_slice(&h2.to_be_bytes());
    result[12..16].copy_from_slice(&h3.to_be_bytes());
    result[16..20].copy_from_slice(&h4.to_be_bytes());
    result
}

// SHA-512 implementation
fn sha512(data: &[u8]) -> [u8; 64] {
    const K: [u64; 80] = [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ];

    let mut h: [u64; 8] = [
        0x6a09e667f3bcc908,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];

    let bit_len = (data.len() as u128) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 128 != 112 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in msg.chunks(128) {
        let mut w = [0u64; 80];
        for i in 0..16 {
            w[i] = u64::from_be_bytes(chunk[i * 8..i * 8 + 8].try_into().unwrap());
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;

        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut result = [0u8; 64];
    for i in 0..8 {
        result[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

fn compute_hash(algo: u32, data: &[u8]) -> Vec<u8> {
    match algo {
        VIRTIO_CRYPTO_HASH_SHA1 => sha1(data).to_vec(),
        VIRTIO_CRYPTO_HASH_SHA256 => sha256(data).to_vec(),
        VIRTIO_CRYPTO_HASH_SHA512 => sha512(data).to_vec(),
        _ => Vec::new(),
    }
}

fn compute_mac(algo: u32, key: &[u8], data: &[u8]) -> Vec<u8> {
    match algo {
        VIRTIO_CRYPTO_MAC_HMAC_SHA256 => hmac_sha256(key, data).to_vec(),
        _ => Vec::new(),
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let block_size = 64;

    // If key is longer than block size, hash it
    let key_block = if key.len() > block_size {
        let h = sha256(key);
        let mut kb = [0u8; 64];
        kb[..32].copy_from_slice(&h);
        kb
    } else {
        let mut kb = [0u8; 64];
        kb[..key.len()].copy_from_slice(key);
        kb
    };

    // Inner: key XOR ipad
    let mut inner = Vec::with_capacity(block_size + data.len());
    for &kb in key_block.iter().take(block_size) {
        inner.push(kb ^ 0x36);
    }
    inner.extend_from_slice(data);
    let inner_hash = sha256(&inner);

    // Outer: key XOR opad
    let mut outer = Vec::with_capacity(block_size + 32);
    for &kb in key_block.iter().take(block_size) {
        outer.push(kb ^ 0x5c);
    }
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_crypto_magic_and_id() {
        let crypto = VirtioCrypto::new();
        assert_eq!(crypto.read(0x000), VIRTIO_MAGIC);
        assert_eq!(crypto.read(0x004), VIRTIO_VERSION);
        assert_eq!(crypto.read(0x008), 20); // device type 20 = crypto
        assert_eq!(crypto.read(0x00C), VENDOR_ID);
    }

    #[test]
    fn test_virtio_crypto_features() {
        let mut crypto = VirtioCrypto::new();
        // Page 0: cipher + hash + mac
        crypto.write(0x014, 0);
        let f = crypto.read(0x010);
        assert!(f & 1 != 0, "CIPHER feature");
        assert!(f & 2 != 0, "HASH feature");
        assert!(f & 4 != 0, "MAC feature");
        // Page 1: VERSION_1
        crypto.write(0x014, 1);
        assert_eq!(crypto.read(0x010), 1);
    }

    #[test]
    fn test_virtio_crypto_status_lifecycle() {
        let mut crypto = VirtioCrypto::new();
        assert_eq!(crypto.read(0x070), 0);
        crypto.write(0x070, STATUS_ACKNOWLEDGE as u64);
        assert_eq!(crypto.read(0x070), STATUS_ACKNOWLEDGE);
        crypto.write(0x070, (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u64);
        assert_eq!(crypto.read(0x070), STATUS_ACKNOWLEDGE | STATUS_DRIVER);
        crypto.write(0x070, 0);
        assert_eq!(crypto.read(0x070), 0);
    }

    #[test]
    fn test_virtio_crypto_two_queues() {
        let mut crypto = VirtioCrypto::new();
        // Control queue
        crypto.write(0x030, 0);
        assert_eq!(crypto.read(0x034), QUEUE_SIZE);
        // Data queue
        crypto.write(0x030, 1);
        assert_eq!(crypto.read(0x034), QUEUE_SIZE);
        // Invalid queue
        crypto.write(0x030, 2);
        assert_eq!(crypto.read(0x034), 0);
    }

    #[test]
    fn test_virtio_crypto_queue_setup() {
        let mut crypto = VirtioCrypto::new();
        crypto.write(0x030, 0);
        crypto.write(0x038, 32);
        crypto.write(0x080, 0x1000);
        crypto.write(0x084, 0);
        crypto.write(0x090, 0x2000);
        crypto.write(0x094, 0);
        crypto.write(0x0A0, 0x3000);
        crypto.write(0x0A4, 0);
        crypto.write(0x044, 1);
        assert_eq!(crypto.read(0x044), 1);
    }

    #[test]
    fn test_virtio_crypto_interrupt_ack() {
        let mut crypto = VirtioCrypto::new();
        crypto.interrupt_status = 1;
        assert!(crypto.has_interrupt());
        crypto.write(0x064, 1);
        assert!(!crypto.has_interrupt());
    }

    #[test]
    fn test_virtio_crypto_config_space() {
        let crypto = VirtioCrypto::new();
        assert_eq!(crypto.read(0x104), 1); // max_dataqueues
        assert_eq!(crypto.read(0x108), 32); // max_cipher_key_len
        assert_eq!(crypto.read(0x10C), 64); // max_auth_key_len
    }

    #[test]
    fn test_virtio_crypto_session_create_destroy() {
        let mut crypto = VirtioCrypto::new();
        let id0 = crypto.create_session(SessionType::Cipher {
            algo: VIRTIO_CRYPTO_CIPHER_AES_CBC,
            key: vec![0u8; 16],
        });
        assert_eq!(id0, 0);
        let id1 = crypto.create_session(SessionType::Hash {
            algo: VIRTIO_CRYPTO_HASH_SHA256,
        });
        assert_eq!(id1, 1);
        assert!(crypto.destroy_session(id0));
        assert!(!crypto.destroy_session(id0)); // already destroyed
        assert!(crypto.destroy_session(id1));
        assert!(!crypto.destroy_session(99)); // never existed
    }

    #[test]
    fn test_aes_ecb_encrypt_decrypt() {
        let key = [0u8; 16]; // AES-128 zero key
        let plaintext = [0u8; 16]; // zero block
        let round_keys = aes_key_expand(&key);
        let ciphertext = aes_encrypt_block(&plaintext, &round_keys);
        // AES-128 with zero key and zero plaintext = known value
        assert_eq!(
            ciphertext,
            [
                0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
                0x2b, 0x2e
            ]
        );
        let decrypted = aes_decrypt_block(&ciphertext, &round_keys);
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_aes_cbc_encrypt_decrypt() {
        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let iv = [0u8; 16];
        let plaintext = b"Hello, World!!!!"; // exactly 16 bytes

        let encrypted = aes_cipher_op(true, VIRTIO_CRYPTO_CIPHER_AES_CBC, &key, &iv, plaintext);
        let decrypted = aes_cipher_op(false, VIRTIO_CRYPTO_CIPHER_AES_CBC, &key, &iv, &encrypted);
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn test_aes_ctr_encrypt_decrypt() {
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let plaintext = b"CTR mode test data that is longer than one block!!!";

        let encrypted = aes_cipher_op(true, VIRTIO_CRYPTO_CIPHER_AES_CTR, &key, &iv, plaintext);
        assert_ne!(&encrypted[..], &plaintext[..]);
        let decrypted = aes_cipher_op(false, VIRTIO_CRYPTO_CIPHER_AES_CTR, &key, &iv, &encrypted);
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_aes_256_ecb() {
        let key = [0u8; 32]; // AES-256 zero key
        let plaintext = [0u8; 16];
        let round_keys = aes_key_expand(&key);
        assert_eq!(round_keys.len(), 15); // 14 rounds + 1
        let ct = aes_encrypt_block(&plaintext, &round_keys);
        let pt = aes_decrypt_block(&ct, &round_keys);
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha256_abc() {
        let hash = sha256(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_empty() {
        let hash = sha1(b"");
        let expected = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha1_abc() {
        let hash = sha1(b"abc");
        let expected = [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ];
        assert_eq!(hash, expected);
    }

    #[test]
    fn test_sha512_empty() {
        let hash = sha512(b"");
        // First 8 bytes of SHA-512("")
        assert_eq!(hash[0], 0xcf);
        assert_eq!(hash[1], 0x83);
        assert_eq!(hash[2], 0xe1);
        assert_eq!(hash[3], 0x35);
    }

    #[test]
    fn test_sha512_abc() {
        let hash = sha512(b"abc");
        // Known first bytes
        assert_eq!(hash[0], 0xdd);
        assert_eq!(hash[1], 0xaf);
        assert_eq!(hash[2], 0x35);
        assert_eq!(hash[3], 0xa1);
    }

    #[test]
    fn test_hmac_sha256() {
        // RFC 4231 Test Case 2
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = hmac_sha256(key, data);
        let expected = [
            0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95,
            0x75, 0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9,
            0x64, 0xec, 0x38, 0x43,
        ];
        assert_eq!(mac, expected);
    }

    #[test]
    fn test_data_request_cipher_encrypt() {
        let mut crypto = VirtioCrypto::new();
        let sid = crypto.create_session(SessionType::Cipher {
            algo: VIRTIO_CRYPTO_CIPHER_AES_ECB,
            key: vec![0u8; 16],
        });

        let mut hdr = vec![0u8; 28];
        hdr[0..4].copy_from_slice(&VIRTIO_CRYPTO_CIPHER_ENCRYPT.to_le_bytes());
        hdr[4..12].copy_from_slice(&sid.to_le_bytes());

        let input = [0u8; 16];
        let (output, status) =
            crypto.handle_data_request(VIRTIO_CRYPTO_CIPHER_ENCRYPT, sid, &input, &hdr);
        assert_eq!(status, VIRTIO_CRYPTO_OK);
        assert_eq!(output.len(), 16);
        // AES-ECB(zero key, zero block) = known ciphertext
        assert_eq!(output[0], 0x66);
        assert_eq!(output[1], 0xe9);
    }

    #[test]
    fn test_data_request_hash() {
        let mut crypto = VirtioCrypto::new();
        let sid = crypto.create_session(SessionType::Hash {
            algo: VIRTIO_CRYPTO_HASH_SHA256,
        });

        let (output, status) =
            crypto.handle_data_request(VIRTIO_CRYPTO_HASH, sid, b"abc", &[0u8; 12]);
        assert_eq!(status, VIRTIO_CRYPTO_OK);
        assert_eq!(output.len(), 32);
        assert_eq!(output[0], 0xba); // SHA-256("abc") first byte
    }

    #[test]
    fn test_data_request_mac() {
        let mut crypto = VirtioCrypto::new();
        let sid = crypto.create_session(SessionType::Mac {
            algo: VIRTIO_CRYPTO_MAC_HMAC_SHA256,
            key: b"Jefe".to_vec(),
        });

        let (output, status) = crypto.handle_data_request(
            VIRTIO_CRYPTO_MAC,
            sid,
            b"what do ya want for nothing?",
            &[0u8; 12],
        );
        assert_eq!(status, VIRTIO_CRYPTO_OK);
        assert_eq!(output.len(), 32);
        assert_eq!(output[0], 0x5b); // HMAC-SHA256 first byte
    }

    #[test]
    fn test_data_request_invalid_session() {
        let crypto = VirtioCrypto::new();
        let (_, status) = crypto.handle_data_request(VIRTIO_CRYPTO_HASH, 999, b"test", &[0u8; 12]);
        assert_eq!(status, VIRTIO_CRYPTO_INVSESS);
    }

    #[test]
    fn test_data_request_wrong_opcode_for_session() {
        let mut crypto = VirtioCrypto::new();
        let sid = crypto.create_session(SessionType::Hash {
            algo: VIRTIO_CRYPTO_HASH_SHA256,
        });
        // Try cipher encrypt on a hash session
        let (_, status) =
            crypto.handle_data_request(VIRTIO_CRYPTO_CIPHER_ENCRYPT, sid, b"test", &[0u8; 28]);
        assert_eq!(status, VIRTIO_CRYPTO_ERR);
    }

    #[test]
    fn test_virtio_crypto_reset() {
        let mut crypto = VirtioCrypto::new();
        crypto.create_session(SessionType::Hash {
            algo: VIRTIO_CRYPTO_HASH_SHA256,
        });
        crypto.write(0x070, (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u64);
        crypto.interrupt_status = 1;

        // Reset
        crypto.write(0x070, 0);
        assert_eq!(crypto.read(0x070), 0);
        assert!(!crypto.has_interrupt());
        assert!(crypto.sessions.is_empty());
    }

    #[test]
    fn test_aes_ecb_roundtrip_multiblock() {
        let key = [0x01u8; 16];
        let plaintext = [0x42u8; 48]; // 3 blocks
        let encrypted = aes_cipher_op(
            true,
            VIRTIO_CRYPTO_CIPHER_AES_ECB,
            &key,
            &[0u8; 16],
            &plaintext,
        );
        let decrypted = aes_cipher_op(
            false,
            VIRTIO_CRYPTO_CIPHER_AES_ECB,
            &key,
            &[0u8; 16],
            &encrypted,
        );
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    #[test]
    fn test_virtio_crypto_version1_feature() {
        let mut crypto = VirtioCrypto::new();
        crypto.write(0x014, 1);
        assert_eq!(crypto.read(0x010), 1, "VIRTIO_F_VERSION_1 must be set");
    }
}
