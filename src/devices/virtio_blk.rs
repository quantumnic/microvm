/// VirtIO MMIO Block Device (v2)
///
/// Implements the VirtIO over MMIO transport with a block device backend.
/// Reference: VirtIO spec v1.1, sections 2 (basic facilities), 4.2 (MMIO),
/// and 5.2 (block device).
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

// VirtIO MMIO register offsets
const MAGIC_VALUE: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR_ID: u64 = 0x00C;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_AVAIL_LOW: u64 = 0x090;
const QUEUE_AVAIL_HIGH: u64 = 0x094;
const QUEUE_USED_LOW: u64 = 0x0A0;
const QUEUE_USED_HIGH: u64 = 0x0A4;
const CONFIG_GENERATION: u64 = 0x0FC;
// Config space starts at 0x100
const CONFIG_BASE: u64 = 0x100;
const CONFIG_CAPACITY_HI: u64 = 0x104;

// VirtIO device status bits
#[allow(dead_code)]
const STATUS_ACKNOWLEDGE: u32 = 1;
#[allow(dead_code)]
const STATUS_DRIVER: u32 = 2;
const STATUS_DRIVER_OK: u32 = 4;
#[allow(dead_code)]
const STATUS_FEATURES_OK: u32 = 8;

// VirtIO block request types
const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;

// Virtqueue descriptor flags
const VRING_DESC_F_NEXT: u16 = 1;
#[allow(dead_code)]
const VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: u32 = 128;
const SECTOR_SIZE: u64 = 512;

/// VirtIO queue state
struct Virtqueue {
    /// Queue size (number of descriptors)
    num: u32,
    /// Ready flag
    ready: bool,
    /// Descriptor table physical address
    desc_addr: u64,
    /// Available ring physical address
    avail_addr: u64,
    /// Used ring physical address
    used_addr: u64,
    /// Last seen available index
    last_avail_idx: u16,
}

impl Virtqueue {
    fn new() -> Self {
        Self {
            num: 0,
            ready: false,
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            last_avail_idx: 0,
        }
    }
}

/// VirtIO MMIO Block Device
pub struct VirtioBlk {
    /// Backing file for disk image
    disk: Option<File>,
    /// Disk size in bytes
    disk_size: u64,
    /// Device status register
    status: u32,
    /// Device feature selection
    device_features_sel: u32,
    /// Driver feature selection
    driver_features_sel: u32,
    /// Driver features (accepted)
    driver_features: [u32; 2],
    /// Queue selection
    queue_sel: u32,
    /// Virtqueues (block device has 1)
    queues: [Virtqueue; 1],
    /// Interrupt status
    interrupt_status: u32,
    /// Whether an interrupt is pending
    irq_pending: bool,
}

impl Default for VirtioBlk {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioBlk {
    pub fn new() -> Self {
        Self {
            disk: None,
            disk_size: 0,
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            queues: [Virtqueue::new()],
            interrupt_status: 0,
            irq_pending: false,
        }
    }

    /// Attach a disk image file
    pub fn attach_disk(&mut self, path: &std::path::Path) -> std::io::Result<()> {
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let size = file.metadata()?.len();
        self.disk_size = size;
        self.disk = Some(file);
        log::info!(
            "VirtIO block: attached {} ({} bytes, {} sectors)",
            path.display(),
            size,
            size / SECTOR_SIZE
        );
        Ok(())
    }

    /// Check if interrupt is pending
    pub fn has_interrupt(&self) -> bool {
        self.irq_pending
    }

    /// Clear interrupt
    #[allow(dead_code)]
    pub fn clear_interrupt(&mut self) {
        self.irq_pending = false;
    }

    fn queue(&self) -> &Virtqueue {
        &self.queues[0]
    }

    fn queue_mut(&mut self) -> &mut Virtqueue {
        &mut self.queues[0]
    }

    pub fn read(&self, offset: u64) -> u64 {
        match offset {
            MAGIC_VALUE => 0x74726976, // "virt" in little-endian
            VERSION => 2,              // VirtIO MMIO v2
            DEVICE_ID => {
                if self.disk.is_some() {
                    2
                } else {
                    0
                } // 2 = block device
            }
            VENDOR_ID => 0x554D4551, // "QEMU" (compatible)
            DEVICE_FEATURES => {
                match self.device_features_sel {
                    0 => {
                        // Feature bits 0-31
                        0 // No special features for now
                    }
                    1 => {
                        // Feature bits 32-63
                        1 // VIRTIO_F_VERSION_1 (bit 32, reported as bit 0 of selector 1)
                    }
                    _ => 0,
                }
            }
            QUEUE_NUM_MAX => QUEUE_SIZE as u64,
            QUEUE_READY => {
                if self.queue_sel == 0 {
                    self.queue().ready as u64
                } else {
                    0
                }
            }
            INTERRUPT_STATUS => self.interrupt_status as u64,
            STATUS => self.status as u64,
            CONFIG_GENERATION => 0,
            // Block device config: capacity (u64 at offset 0x100)
            CONFIG_BASE => self.disk_size / SECTOR_SIZE, // low 32 bits
            CONFIG_CAPACITY_HI => (self.disk_size / SECTOR_SIZE) >> 32, // high 32 bits
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            DEVICE_FEATURES_SEL => self.device_features_sel = val as u32,
            DRIVER_FEATURES => {
                let sel = self.driver_features_sel as usize;
                if sel < 2 {
                    self.driver_features[sel] = val as u32;
                }
            }
            DRIVER_FEATURES_SEL => self.driver_features_sel = val as u32,
            QUEUE_SEL => self.queue_sel = val as u32,
            QUEUE_NUM => {
                if self.queue_sel == 0 {
                    self.queue_mut().num = val as u32;
                }
            }
            QUEUE_READY => {
                if self.queue_sel == 0 {
                    self.queue_mut().ready = val != 0;
                }
            }
            QUEUE_NOTIFY => {
                // Guest is notifying us — process the queue
                // We can't access bus memory directly here, so set a flag
                // The VM loop will call process_queue with bus access
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !(val as u32);
                if self.interrupt_status == 0 {
                    self.irq_pending = false;
                }
            }
            STATUS => {
                self.status = val as u32;
                if val == 0 {
                    // Device reset
                    self.reset();
                }
            }
            QUEUE_DESC_LOW => {
                if self.queue_sel == 0 {
                    let q = self.queue_mut();
                    q.desc_addr = (q.desc_addr & 0xFFFFFFFF00000000) | (val & 0xFFFFFFFF);
                }
            }
            QUEUE_DESC_HIGH => {
                if self.queue_sel == 0 {
                    let q = self.queue_mut();
                    q.desc_addr = (q.desc_addr & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32);
                }
            }
            QUEUE_AVAIL_LOW => {
                if self.queue_sel == 0 {
                    let q = self.queue_mut();
                    q.avail_addr = (q.avail_addr & 0xFFFFFFFF00000000) | (val & 0xFFFFFFFF);
                }
            }
            QUEUE_AVAIL_HIGH => {
                if self.queue_sel == 0 {
                    let q = self.queue_mut();
                    q.avail_addr = (q.avail_addr & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32);
                }
            }
            QUEUE_USED_LOW => {
                if self.queue_sel == 0 {
                    let q = self.queue_mut();
                    q.used_addr = (q.used_addr & 0xFFFFFFFF00000000) | (val & 0xFFFFFFFF);
                }
            }
            QUEUE_USED_HIGH => {
                if self.queue_sel == 0 {
                    let q = self.queue_mut();
                    q.used_addr = (q.used_addr & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32);
                }
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.status = 0;
        self.interrupt_status = 0;
        self.irq_pending = false;
        self.queues[0] = Virtqueue::new();
    }

    /// Check if queue notification is pending and should be processed
    pub fn needs_processing(&self) -> bool {
        self.queues[0].ready && self.disk.is_some() && (self.status & STATUS_DRIVER_OK) != 0
    }

    /// Process pending virtqueue requests. Needs raw access to guest RAM.
    /// `ram` is the guest RAM slice starting at DRAM_BASE offset 0.
    /// Returns true if any work was done.
    pub fn process_queue(&mut self, ram: &mut [u8], dram_base: u64) -> bool {
        if !self.needs_processing() {
            return false;
        }

        let q = &self.queues[0];
        let desc_addr = q.desc_addr;
        let avail_addr = q.avail_addr;
        let used_addr = q.used_addr;
        let num = q.num;
        let mut last_avail = q.last_avail_idx;

        // Read available ring index
        let avail_idx = read_u16(ram, avail_addr + 2, dram_base);
        if avail_idx == last_avail {
            return false; // Nothing new
        }

        let mut did_work = false;

        while last_avail != avail_idx {
            let ring_idx = (last_avail as u32 % num) as u64;
            let desc_idx = read_u16(ram, avail_addr + 4 + ring_idx * 2, dram_base) as u64;

            // Process descriptor chain
            let written = self.process_descriptor_chain(ram, dram_base, desc_addr, desc_idx, num);

            // Write to used ring
            let used_idx = read_u16(ram, used_addr + 2, dram_base);
            let used_ring_idx = (used_idx as u32 % num) as u64;
            let used_elem_addr = used_addr + 4 + used_ring_idx * 8;
            write_u32(ram, used_elem_addr, dram_base, desc_idx as u32);
            write_u32(ram, used_elem_addr + 4, dram_base, written as u32);
            write_u16(ram, used_addr + 2, dram_base, used_idx.wrapping_add(1));

            last_avail = last_avail.wrapping_add(1);
            did_work = true;
        }

        self.queues[0].last_avail_idx = last_avail;

        if did_work {
            self.interrupt_status |= 1; // Used buffer notification
            self.irq_pending = true;
        }

        did_work
    }

    fn process_descriptor_chain(
        &mut self,
        ram: &mut [u8],
        dram_base: u64,
        desc_base: u64,
        first_desc: u64,
        _num: u32,
    ) -> u64 {
        // VirtIO block request structure:
        // Descriptor 0: virtio_blk_req header (type, reserved, sector) — 16 bytes, read-only
        // Descriptor 1: data buffer — read or write depending on request
        // Descriptor 2: status byte — 1 byte, write-only

        // Read header descriptor
        let header_desc = read_descriptor(ram, dram_base, desc_base, first_desc);
        if header_desc.len < 16 {
            return 0;
        }

        // Read the header
        let req_type = read_u32(ram, header_desc.addr, dram_base);
        let _reserved = read_u32(ram, header_desc.addr + 4, dram_base);
        let sector = read_u64(ram, header_desc.addr + 8, dram_base);

        if header_desc.flags & VRING_DESC_F_NEXT == 0 {
            return 0;
        }

        // Read data descriptor
        let data_desc = read_descriptor(ram, dram_base, desc_base, header_desc.next as u64);
        let data_len = data_desc.len as u64;

        // Find status descriptor
        let status_desc_idx = if data_desc.flags & VRING_DESC_F_NEXT != 0 {
            data_desc.next as u64
        } else {
            return 0;
        };
        let status_desc = read_descriptor(ram, dram_base, desc_base, status_desc_idx);

        let mut status: u8 = 0; // VIRTIO_BLK_S_OK

        match req_type {
            VIRTIO_BLK_T_IN => {
                // Read from disk
                if let Some(ref mut disk) = self.disk {
                    let offset = sector * SECTOR_SIZE;
                    if disk.seek(SeekFrom::Start(offset)).is_ok() {
                        let ram_offset = addr_to_ram_offset(data_desc.addr, dram_base);
                        if let Some(buf) = ram.get_mut(ram_offset..ram_offset + data_len as usize) {
                            if disk.read_exact(buf).is_err() {
                                // Partial read or error — zero-fill
                                buf.fill(0);
                                status = 1; // VIRTIO_BLK_S_IOERR
                            }
                        } else {
                            status = 1;
                        }
                    } else {
                        status = 1;
                    }
                } else {
                    status = 1;
                }
            }
            VIRTIO_BLK_T_OUT => {
                // Write to disk
                if let Some(ref mut disk) = self.disk {
                    let offset = sector * SECTOR_SIZE;
                    if disk.seek(SeekFrom::Start(offset)).is_ok() {
                        let ram_offset = addr_to_ram_offset(data_desc.addr, dram_base);
                        if let Some(buf) = ram.get(ram_offset..ram_offset + data_len as usize) {
                            if disk.write_all(buf).is_err() {
                                status = 1;
                            }
                        } else {
                            status = 1;
                        }
                    } else {
                        status = 1;
                    }
                } else {
                    status = 1;
                }
            }
            _ => {
                status = 2; // VIRTIO_BLK_S_UNSUPP
            }
        }

        // Write status
        let status_offset = addr_to_ram_offset(status_desc.addr, dram_base);
        if status_offset < ram.len() {
            ram[status_offset] = status;
        }

        data_len + 1 // bytes written to device-writable descriptors
    }
}

struct Descriptor {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

fn read_descriptor(ram: &[u8], dram_base: u64, desc_base: u64, idx: u64) -> Descriptor {
    let addr = desc_base + idx * 16;
    Descriptor {
        addr: read_u64(ram, addr, dram_base),
        len: read_u32(ram, addr + 8, dram_base),
        flags: read_u16(ram, addr + 12, dram_base),
        next: read_u16(ram, addr + 14, dram_base),
    }
}

fn addr_to_ram_offset(addr: u64, dram_base: u64) -> usize {
    addr.wrapping_sub(dram_base) as usize
}

fn read_u16(ram: &[u8], addr: u64, dram_base: u64) -> u16 {
    let off = addr_to_ram_offset(addr, dram_base);
    if off + 1 < ram.len() {
        u16::from_le_bytes([ram[off], ram[off + 1]])
    } else {
        0
    }
}

fn read_u32(ram: &[u8], addr: u64, dram_base: u64) -> u32 {
    let off = addr_to_ram_offset(addr, dram_base);
    if off + 3 < ram.len() {
        u32::from_le_bytes([ram[off], ram[off + 1], ram[off + 2], ram[off + 3]])
    } else {
        0
    }
}

fn read_u64(ram: &[u8], addr: u64, dram_base: u64) -> u64 {
    let off = addr_to_ram_offset(addr, dram_base);
    if off + 7 < ram.len() {
        u64::from_le_bytes([
            ram[off],
            ram[off + 1],
            ram[off + 2],
            ram[off + 3],
            ram[off + 4],
            ram[off + 5],
            ram[off + 6],
            ram[off + 7],
        ])
    } else {
        0
    }
}

fn write_u16(ram: &mut [u8], addr: u64, dram_base: u64, val: u16) {
    let off = addr_to_ram_offset(addr, dram_base);
    if off + 1 < ram.len() {
        let bytes = val.to_le_bytes();
        ram[off] = bytes[0];
        ram[off + 1] = bytes[1];
    }
}

fn write_u32(ram: &mut [u8], addr: u64, dram_base: u64, val: u32) {
    let off = addr_to_ram_offset(addr, dram_base);
    if off + 3 < ram.len() {
        let bytes = val.to_le_bytes();
        ram[off..off + 4].copy_from_slice(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_blk_magic() {
        let blk = VirtioBlk::new();
        assert_eq!(blk.read(MAGIC_VALUE), 0x74726976);
    }

    #[test]
    fn test_virtio_blk_version() {
        let blk = VirtioBlk::new();
        assert_eq!(blk.read(VERSION), 2);
    }

    #[test]
    fn test_virtio_blk_no_disk_device_id_zero() {
        let blk = VirtioBlk::new();
        // No disk attached → device ID 0 (no device)
        assert_eq!(blk.read(DEVICE_ID), 0);
    }

    #[test]
    fn test_virtio_blk_status_reset() {
        let mut blk = VirtioBlk::new();
        blk.write(STATUS, STATUS_ACKNOWLEDGE as u64);
        assert_eq!(blk.read(STATUS), STATUS_ACKNOWLEDGE as u64);
        blk.write(STATUS, 0); // Reset
        assert_eq!(blk.read(STATUS), 0);
    }

    #[test]
    fn test_virtio_blk_queue_setup() {
        let mut blk = VirtioBlk::new();
        blk.write(QUEUE_SEL, 0);
        assert_eq!(blk.read(QUEUE_NUM_MAX), QUEUE_SIZE as u64);
        blk.write(QUEUE_NUM, 64);
        blk.write(QUEUE_DESC_LOW, 0x80010000);
        blk.write(QUEUE_DESC_HIGH, 0);
        blk.write(QUEUE_AVAIL_LOW, 0x80020000);
        blk.write(QUEUE_AVAIL_HIGH, 0);
        blk.write(QUEUE_USED_LOW, 0x80030000);
        blk.write(QUEUE_USED_HIGH, 0);
        blk.write(QUEUE_READY, 1);
        assert_eq!(blk.read(QUEUE_READY), 1);
    }

    #[test]
    fn test_virtio_blk_interrupt_ack() {
        let mut blk = VirtioBlk::new();
        blk.interrupt_status = 1;
        blk.irq_pending = true;
        assert_eq!(blk.read(INTERRUPT_STATUS), 1);
        blk.write(INTERRUPT_ACK, 1);
        assert_eq!(blk.read(INTERRUPT_STATUS), 0);
        assert!(!blk.has_interrupt());
    }
}
