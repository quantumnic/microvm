//! VirtIO Balloon device (type 5) — dynamic memory ballooning
//!
//! Allows the host to request memory from the guest (inflate) or return it (deflate).
//! The guest writes page frame numbers (4KiB pages) to virtqueues.
//!
//! Config space:
//!   0x00: num_pages (u32, R) — requested number of 4KiB pages to balloon
//!   0x04: actual (u32, RW) — actual number of pages currently ballooned
//!
//! Virtqueues:
//!   0: inflateq — guest returns pages to host
//!   1: deflateq — host returns pages to guest
//!
//! Feature bits:
//!   bit 2: VIRTIO_BALLOON_F_DEFLATE_ON_OOM — deflate on out-of-memory

const VIRTIO_BALLOON_F_DEFLATE_ON_OOM: u32 = 1 << 2;

/// VirtIO MMIO register offsets
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
const QUEUE_DRIVER_LOW: u64 = 0x090;
const QUEUE_DRIVER_HIGH: u64 = 0x094;
const QUEUE_DEVICE_LOW: u64 = 0x0A0;
const QUEUE_DEVICE_HIGH: u64 = 0x0A4;
const CONFIG_BASE: u64 = 0x100;

const NUM_QUEUES: usize = 2;
const QUEUE_SIZE: u16 = 128;

#[derive(Clone)]
struct Virtqueue {
    desc_addr: u64,
    driver_addr: u64,
    device_addr: u64,
    num: u16,
    ready: bool,
    /// Last index we processed in the available ring
    last_avail_idx: u16,
}

impl Default for Virtqueue {
    fn default() -> Self {
        Self {
            desc_addr: 0,
            driver_addr: 0,
            device_addr: 0,
            num: QUEUE_SIZE,
            ready: false,
            last_avail_idx: 0,
        }
    }
}

pub struct VirtioBalloon {
    /// Selected device feature page
    features_sel: u32,
    /// Driver-acknowledged feature bits
    driver_features: u64,
    /// Driver feature selection page
    driver_features_sel: u32,
    /// Device status register
    status: u32,
    /// Currently selected queue index
    queue_sel: u32,
    /// Virtqueues: [inflateq, deflateq]
    queues: [Virtqueue; NUM_QUEUES],
    /// Interrupt status (bit 0 = used buffer notification)
    interrupt_status: u32,
    /// Requested number of 4KiB pages to balloon (host sets this)
    num_pages: u32,
    /// Actual number of pages currently ballooned (guest reports this)
    actual: u32,
    /// Ballooned page frame numbers (for tracking)
    ballooned_pfns: Vec<u32>,
    /// Queue notification pending (set on QUEUE_NOTIFY write)
    notify_pending: [bool; NUM_QUEUES],
}

impl Default for VirtioBalloon {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioBalloon {
    pub fn new() -> Self {
        Self {
            features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            status: 0,
            queue_sel: 0,
            queues: [Virtqueue::default(), Virtqueue::default()],
            interrupt_status: 0,
            num_pages: 0,
            actual: 0,
            ballooned_pfns: Vec::new(),
            notify_pending: [false; NUM_QUEUES],
        }
    }

    /// Set the requested number of 4KiB pages to balloon
    #[allow(dead_code)]
    pub fn set_num_pages(&mut self, pages: u32) {
        self.num_pages = pages;
    }

    /// Get current balloon size in pages
    #[allow(dead_code)]
    pub fn actual_pages(&self) -> u32 {
        self.actual
    }

    /// Get list of ballooned PFNs
    #[allow(dead_code)]
    pub fn ballooned_pfns(&self) -> &[u32] {
        &self.ballooned_pfns
    }

    pub fn has_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    pub fn needs_processing(&self) -> bool {
        self.notify_pending[0] || self.notify_pending[1]
    }

    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => 0x7472_6976, // "virt"
            VERSION => 2,               // VirtIO MMIO v2
            DEVICE_ID => 5,             // Balloon
            VENDOR_ID => 0x554D_4356,   // "MCVU"
            DEVICE_FEATURES => {
                if self.features_sel == 0 {
                    VIRTIO_BALLOON_F_DEFLATE_ON_OOM
                } else {
                    0
                }
            }
            QUEUE_NUM_MAX => QUEUE_SIZE as u32,
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].ready as u32
                } else {
                    0
                }
            }
            INTERRUPT_STATUS => self.interrupt_status,
            STATUS => self.status,
            // Config space: num_pages (0x100) and actual (0x104)
            CONFIG_BASE => self.num_pages,
            0x104 => self.actual,
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            DEVICE_FEATURES_SEL => self.features_sel = val as u32,
            DRIVER_FEATURES => {
                if self.driver_features_sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                } else {
                    self.driver_features = (self.driver_features & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            DRIVER_FEATURES_SEL => self.driver_features_sel = val as u32,
            QUEUE_SEL => self.queue_sel = val as u32,
            QUEUE_NUM => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].num = (val as u16).min(QUEUE_SIZE);
                }
            }
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].ready = val & 1 != 0;
                }
            }
            QUEUE_NOTIFY => {
                let qi = val as usize;
                if qi < NUM_QUEUES {
                    self.notify_pending[qi] = true;
                }
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !(val as u32);
            }
            STATUS => {
                self.status = val as u32;
                if self.status == 0 {
                    // Device reset
                    self.queues = [Virtqueue::default(), Virtqueue::default()];
                    self.interrupt_status = 0;
                    self.notify_pending = [false; NUM_QUEUES];
                }
            }
            QUEUE_DESC_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].desc_addr =
                        (self.queues[qi].desc_addr & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            QUEUE_DESC_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].desc_addr = (self.queues[qi].desc_addr & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            QUEUE_DRIVER_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].driver_addr =
                        (self.queues[qi].driver_addr & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            QUEUE_DRIVER_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].driver_addr = (self.queues[qi].driver_addr
                        & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            QUEUE_DEVICE_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].device_addr =
                        (self.queues[qi].device_addr & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            QUEUE_DEVICE_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].device_addr = (self.queues[qi].device_addr
                        & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            // Config space write: actual (0x104)
            0x104 => self.actual = val as u32,
            _ => {}
        }
    }

    /// Process inflate queue (queue 0): guest gives pages to host
    fn process_inflate(&mut self, ram: &mut [u8], dram_base: u64) {
        let q = &mut self.queues[0];
        if !q.ready || q.desc_addr == 0 {
            return;
        }

        let avail_base = q.driver_addr;
        let used_base = q.device_addr;
        let qsize = q.num as u64;

        // Read available ring index
        let avail_idx_off = (avail_base + 2 - dram_base) as usize;
        if avail_idx_off + 1 >= ram.len() {
            return;
        }
        let avail_idx = u16::from_le_bytes([ram[avail_idx_off], ram[avail_idx_off + 1]]);

        while q.last_avail_idx != avail_idx {
            let ring_off =
                (avail_base + 4 + (q.last_avail_idx as u64 % qsize) * 2 - dram_base) as usize;
            if ring_off + 1 >= ram.len() {
                break;
            }
            let desc_idx = u16::from_le_bytes([ram[ring_off], ram[ring_off + 1]]);

            // Read descriptor
            let desc_off = (q.desc_addr + desc_idx as u64 * 16 - dram_base) as usize;
            if desc_off + 15 >= ram.len() {
                break;
            }
            let addr = u64::from_le_bytes(ram[desc_off..desc_off + 8].try_into().unwrap());
            let len = u32::from_le_bytes(ram[desc_off + 8..desc_off + 12].try_into().unwrap());

            // Each entry is an array of u32 PFNs (4 bytes each)
            let buf_off = (addr - dram_base) as usize;
            let num_pfns = len as usize / 4;
            for i in 0..num_pfns {
                let pfn_off = buf_off + i * 4;
                if pfn_off + 3 < ram.len() {
                    let pfn = u32::from_le_bytes(ram[pfn_off..pfn_off + 4].try_into().unwrap());
                    self.ballooned_pfns.push(pfn);
                }
            }

            // Write to used ring
            let used_idx_off = (used_base + 2 - dram_base) as usize;
            if used_idx_off + 1 >= ram.len() {
                break;
            }
            let used_idx = u16::from_le_bytes([ram[used_idx_off], ram[used_idx_off + 1]]);
            let used_ring_off =
                (used_base + 4 + (used_idx as u64 % qsize) * 8 - dram_base) as usize;
            if used_ring_off + 7 < ram.len() {
                ram[used_ring_off..used_ring_off + 4]
                    .copy_from_slice(&(desc_idx as u32).to_le_bytes());
                ram[used_ring_off + 4..used_ring_off + 8].copy_from_slice(&len.to_le_bytes());
            }
            let new_used_idx = used_idx.wrapping_add(1);
            ram[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used_idx.to_le_bytes());

            q.last_avail_idx = q.last_avail_idx.wrapping_add(1);
        }

        self.actual = self.ballooned_pfns.len() as u32;
        self.interrupt_status |= 1;
    }

    /// Process deflate queue (queue 1): host returns pages to guest
    fn process_deflate(&mut self, ram: &mut [u8], dram_base: u64) {
        let q = &mut self.queues[1];
        if !q.ready || q.desc_addr == 0 {
            return;
        }

        let avail_base = q.driver_addr;
        let used_base = q.device_addr;
        let qsize = q.num as u64;

        let avail_idx_off = (avail_base + 2 - dram_base) as usize;
        if avail_idx_off + 1 >= ram.len() {
            return;
        }
        let avail_idx = u16::from_le_bytes([ram[avail_idx_off], ram[avail_idx_off + 1]]);

        while q.last_avail_idx != avail_idx {
            let ring_off =
                (avail_base + 4 + (q.last_avail_idx as u64 % qsize) * 2 - dram_base) as usize;
            if ring_off + 1 >= ram.len() {
                break;
            }
            let desc_idx = u16::from_le_bytes([ram[ring_off], ram[ring_off + 1]]);

            let desc_off = (q.desc_addr + desc_idx as u64 * 16 - dram_base) as usize;
            if desc_off + 15 >= ram.len() {
                break;
            }
            let addr = u64::from_le_bytes(ram[desc_off..desc_off + 8].try_into().unwrap());
            let len = u32::from_le_bytes(ram[desc_off + 8..desc_off + 12].try_into().unwrap());

            // Remove returned PFNs from ballooned list
            let buf_off = (addr - dram_base) as usize;
            let num_pfns = len as usize / 4;
            for i in 0..num_pfns {
                let pfn_off = buf_off + i * 4;
                if pfn_off + 3 < ram.len() {
                    let pfn = u32::from_le_bytes(ram[pfn_off..pfn_off + 4].try_into().unwrap());
                    self.ballooned_pfns.retain(|&p| p != pfn);
                }
            }

            // Write to used ring
            let used_idx_off = (used_base + 2 - dram_base) as usize;
            if used_idx_off + 1 >= ram.len() {
                break;
            }
            let used_idx = u16::from_le_bytes([ram[used_idx_off], ram[used_idx_off + 1]]);
            let used_ring_off =
                (used_base + 4 + (used_idx as u64 % qsize) * 8 - dram_base) as usize;
            if used_ring_off + 7 < ram.len() {
                ram[used_ring_off..used_ring_off + 4]
                    .copy_from_slice(&(desc_idx as u32).to_le_bytes());
                ram[used_ring_off + 4..used_ring_off + 8].copy_from_slice(&len.to_le_bytes());
            }
            let new_used_idx = used_idx.wrapping_add(1);
            ram[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used_idx.to_le_bytes());

            q.last_avail_idx = q.last_avail_idx.wrapping_add(1);
        }

        self.actual = self.ballooned_pfns.len() as u32;
        self.interrupt_status |= 1;
    }

    /// Process pending queue notifications
    pub fn process_queues(&mut self, ram: &mut [u8], dram_base: u64) {
        if self.notify_pending[0] {
            self.notify_pending[0] = false;
            self.process_inflate(ram, dram_base);
        }
        if self.notify_pending[1] {
            self.notify_pending[1] = false;
            self.process_deflate(ram, dram_base);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn balloon_magic_and_device_id() {
        let dev = VirtioBalloon::new();
        assert_eq!(dev.read(MAGIC_VALUE), 0x7472_6976);
        assert_eq!(dev.read(VERSION), 2);
        assert_eq!(dev.read(DEVICE_ID), 5);
        assert_eq!(dev.read(VENDOR_ID), 0x554D_4356);
    }

    #[test]
    fn balloon_features() {
        let mut dev = VirtioBalloon::new();
        dev.write(DEVICE_FEATURES_SEL, 0);
        let features = dev.read(DEVICE_FEATURES);
        assert!(features & VIRTIO_BALLOON_F_DEFLATE_ON_OOM != 0);
        dev.write(DEVICE_FEATURES_SEL, 1);
        assert_eq!(dev.read(DEVICE_FEATURES), 0);
    }

    #[test]
    fn balloon_config_space() {
        let mut dev = VirtioBalloon::new();
        // num_pages readable
        dev.set_num_pages(256);
        assert_eq!(dev.read(CONFIG_BASE), 256);
        // actual writable
        dev.write(0x104, 100);
        assert_eq!(dev.read(0x104), 100);
    }

    #[test]
    fn balloon_queue_setup() {
        let mut dev = VirtioBalloon::new();
        // Select inflateq
        dev.write(QUEUE_SEL, 0);
        assert_eq!(dev.read(QUEUE_NUM_MAX), QUEUE_SIZE as u32);
        dev.write(QUEUE_NUM, 64);
        dev.write(QUEUE_DESC_LOW, 0x1000);
        dev.write(QUEUE_DESC_HIGH, 0);
        dev.write(QUEUE_DRIVER_LOW, 0x2000);
        dev.write(QUEUE_DRIVER_HIGH, 0);
        dev.write(QUEUE_DEVICE_LOW, 0x3000);
        dev.write(QUEUE_DEVICE_HIGH, 0);
        dev.write(QUEUE_READY, 1);
        assert_eq!(dev.read(QUEUE_READY), 1);
    }

    #[test]
    fn balloon_status_lifecycle() {
        let mut dev = VirtioBalloon::new();
        dev.write(STATUS, 1); // ACKNOWLEDGE
        assert_eq!(dev.read(STATUS), 1);
        dev.write(STATUS, 3); // DRIVER
        assert_eq!(dev.read(STATUS), 3);
        dev.write(STATUS, 11); // FEATURES_OK
        assert_eq!(dev.read(STATUS), 11);
        dev.write(STATUS, 15); // DRIVER_OK
        assert_eq!(dev.read(STATUS), 15);
        // Reset
        dev.write(STATUS, 0);
        assert_eq!(dev.read(STATUS), 0);
    }

    #[test]
    fn balloon_interrupt_ack() {
        let mut dev = VirtioBalloon::new();
        dev.interrupt_status = 0x03;
        assert!(dev.has_interrupt());
        dev.write(INTERRUPT_ACK, 0x01);
        assert_eq!(dev.read(INTERRUPT_STATUS), 0x02);
        dev.write(INTERRUPT_ACK, 0x02);
        assert!(!dev.has_interrupt());
    }

    #[test]
    fn balloon_driver_features() {
        let mut dev = VirtioBalloon::new();
        dev.write(DRIVER_FEATURES_SEL, 0);
        dev.write(DRIVER_FEATURES, VIRTIO_BALLOON_F_DEFLATE_ON_OOM as u64);
        assert_eq!(
            dev.driver_features & 0xFFFF_FFFF,
            VIRTIO_BALLOON_F_DEFLATE_ON_OOM as u64
        );
    }

    #[test]
    fn balloon_inflate_pfns() {
        let dram_base: u64 = 0x8000_0000;
        let mut ram = vec![0u8; 0x10000];
        let mut dev = VirtioBalloon::new();

        // Set up inflateq (queue 0)
        let desc_addr = dram_base + 0x1000;
        let avail_addr = dram_base + 0x2000;
        let used_addr = dram_base + 0x3000;
        let data_addr = dram_base + 0x4000;

        dev.write(QUEUE_SEL, 0);
        dev.write(QUEUE_NUM, 128);
        dev.write(QUEUE_DESC_LOW, desc_addr as u64);
        dev.write(QUEUE_DESC_HIGH, 0);
        dev.write(QUEUE_DRIVER_LOW, avail_addr as u64);
        dev.write(QUEUE_DRIVER_HIGH, 0);
        dev.write(QUEUE_DEVICE_LOW, used_addr as u64);
        dev.write(QUEUE_DEVICE_HIGH, 0);
        dev.write(QUEUE_READY, 1);
        dev.write(STATUS, 15);

        // Write 3 PFNs into data buffer
        let data_off = (data_addr - dram_base) as usize;
        ram[data_off..data_off + 4].copy_from_slice(&100u32.to_le_bytes());
        ram[data_off + 4..data_off + 8].copy_from_slice(&200u32.to_le_bytes());
        ram[data_off + 8..data_off + 12].copy_from_slice(&300u32.to_le_bytes());

        // Set up descriptor: points to data buffer with 3 PFNs (12 bytes)
        let desc_off = (desc_addr - dram_base) as usize;
        ram[desc_off..desc_off + 8].copy_from_slice(&data_addr.to_le_bytes());
        ram[desc_off + 8..desc_off + 12].copy_from_slice(&12u32.to_le_bytes()); // len=12
        ram[desc_off + 12..desc_off + 14].copy_from_slice(&0u16.to_le_bytes()); // flags=0
        ram[desc_off + 14..desc_off + 16].copy_from_slice(&0u16.to_le_bytes()); // next=0

        // Set up available ring: flags(2) + idx(2) + ring entries
        let avail_off = (avail_addr - dram_base) as usize;
        ram[avail_off..avail_off + 2].copy_from_slice(&0u16.to_le_bytes()); // flags
        ram[avail_off + 2..avail_off + 4].copy_from_slice(&1u16.to_le_bytes()); // idx=1
        ram[avail_off + 4..avail_off + 6].copy_from_slice(&0u16.to_le_bytes()); // ring[0]=desc 0

        // Initialize used ring
        let used_off = (used_addr - dram_base) as usize;
        ram[used_off..used_off + 4].copy_from_slice(&0u32.to_le_bytes());

        // Notify and process
        dev.write(QUEUE_NOTIFY, 0);
        dev.process_queues(&mut ram, dram_base);

        assert_eq!(dev.actual_pages(), 3);
        assert_eq!(dev.ballooned_pfns(), &[100, 200, 300]);
        assert!(dev.has_interrupt());
    }

    #[test]
    fn balloon_deflate_pfns() {
        let dram_base: u64 = 0x8000_0000;
        let mut ram = vec![0u8; 0x10000];
        let mut dev = VirtioBalloon::new();

        // Pre-populate ballooned PFNs
        dev.ballooned_pfns = vec![100, 200, 300, 400];
        dev.actual = 4;

        // Set up deflateq (queue 1)
        let desc_addr = dram_base + 0x1000;
        let avail_addr = dram_base + 0x2000;
        let used_addr = dram_base + 0x3000;
        let data_addr = dram_base + 0x4000;

        dev.write(QUEUE_SEL, 1);
        dev.write(QUEUE_NUM, 128);
        dev.write(QUEUE_DESC_LOW, desc_addr as u64);
        dev.write(QUEUE_DESC_HIGH, 0);
        dev.write(QUEUE_DRIVER_LOW, avail_addr as u64);
        dev.write(QUEUE_DRIVER_HIGH, 0);
        dev.write(QUEUE_DEVICE_LOW, used_addr as u64);
        dev.write(QUEUE_DEVICE_HIGH, 0);
        dev.write(QUEUE_READY, 1);
        dev.write(STATUS, 15);

        // Return PFNs 200 and 300
        let data_off = (data_addr - dram_base) as usize;
        ram[data_off..data_off + 4].copy_from_slice(&200u32.to_le_bytes());
        ram[data_off + 4..data_off + 8].copy_from_slice(&300u32.to_le_bytes());

        let desc_off = (desc_addr - dram_base) as usize;
        ram[desc_off..desc_off + 8].copy_from_slice(&data_addr.to_le_bytes());
        ram[desc_off + 8..desc_off + 12].copy_from_slice(&8u32.to_le_bytes());
        ram[desc_off + 12..desc_off + 14].copy_from_slice(&0u16.to_le_bytes());
        ram[desc_off + 14..desc_off + 16].copy_from_slice(&0u16.to_le_bytes());

        let avail_off = (avail_addr - dram_base) as usize;
        ram[avail_off..avail_off + 2].copy_from_slice(&0u16.to_le_bytes());
        ram[avail_off + 2..avail_off + 4].copy_from_slice(&1u16.to_le_bytes());
        ram[avail_off + 4..avail_off + 6].copy_from_slice(&0u16.to_le_bytes());

        let used_off = (used_addr - dram_base) as usize;
        ram[used_off..used_off + 4].copy_from_slice(&0u32.to_le_bytes());

        dev.write(QUEUE_NOTIFY, 1);
        dev.process_queues(&mut ram, dram_base);

        assert_eq!(dev.actual_pages(), 2);
        assert_eq!(dev.ballooned_pfns(), &[100, 400]);
        assert!(dev.has_interrupt());
    }

    #[test]
    fn balloon_reset_clears_state() {
        let mut dev = VirtioBalloon::new();
        dev.write(STATUS, 15);
        dev.write(QUEUE_SEL, 0);
        dev.write(QUEUE_READY, 1);
        dev.interrupt_status = 1;

        // Reset
        dev.write(STATUS, 0);
        assert_eq!(dev.read(STATUS), 0);
        assert_eq!(dev.read(INTERRUPT_STATUS), 0);
        dev.write(QUEUE_SEL, 0);
        assert_eq!(dev.read(QUEUE_READY), 0);
    }

    #[test]
    fn balloon_no_processing_without_notify() {
        let dev = VirtioBalloon::new();
        assert!(!dev.needs_processing());
        assert!(!dev.has_interrupt());
    }

    #[test]
    fn balloon_set_num_pages() {
        let mut dev = VirtioBalloon::new();
        dev.set_num_pages(1024);
        assert_eq!(dev.read(CONFIG_BASE), 1024);
        dev.set_num_pages(0);
        assert_eq!(dev.read(CONFIG_BASE), 0);
    }

    #[test]
    fn balloon_queue_sel_out_of_range() {
        let mut dev = VirtioBalloon::new();
        dev.write(QUEUE_SEL, 5);
        assert_eq!(dev.read(QUEUE_READY), 0);
        assert_eq!(dev.read(QUEUE_NUM_MAX), QUEUE_SIZE as u32);
    }

    #[test]
    fn balloon_multiple_inflate_batches() {
        let dram_base: u64 = 0x8000_0000;
        let mut ram = vec![0u8; 0x10000];
        let mut dev = VirtioBalloon::new();

        let desc_addr = dram_base + 0x1000;
        let avail_addr = dram_base + 0x2000;
        let used_addr = dram_base + 0x3000;
        let data_addr1 = dram_base + 0x4000;
        let data_addr2 = dram_base + 0x5000;

        dev.write(QUEUE_SEL, 0);
        dev.write(QUEUE_NUM, 128);
        dev.write(QUEUE_DESC_LOW, desc_addr as u64);
        dev.write(QUEUE_DESC_HIGH, 0);
        dev.write(QUEUE_DRIVER_LOW, avail_addr as u64);
        dev.write(QUEUE_DRIVER_HIGH, 0);
        dev.write(QUEUE_DEVICE_LOW, used_addr as u64);
        dev.write(QUEUE_DEVICE_HIGH, 0);
        dev.write(QUEUE_READY, 1);
        dev.write(STATUS, 15);

        // First batch: 2 PFNs
        let off = (data_addr1 - dram_base) as usize;
        ram[off..off + 4].copy_from_slice(&10u32.to_le_bytes());
        ram[off + 4..off + 8].copy_from_slice(&20u32.to_le_bytes());

        let desc_off = (desc_addr - dram_base) as usize;
        ram[desc_off..desc_off + 8].copy_from_slice(&data_addr1.to_le_bytes());
        ram[desc_off + 8..desc_off + 12].copy_from_slice(&8u32.to_le_bytes());
        ram[desc_off + 12..desc_off + 16].copy_from_slice(&0u32.to_le_bytes());

        let avail_off = (avail_addr - dram_base) as usize;
        ram[avail_off..avail_off + 2].copy_from_slice(&0u16.to_le_bytes());
        ram[avail_off + 2..avail_off + 4].copy_from_slice(&1u16.to_le_bytes());
        ram[avail_off + 4..avail_off + 6].copy_from_slice(&0u16.to_le_bytes());

        let used_off = (used_addr - dram_base) as usize;
        ram[used_off..used_off + 4].copy_from_slice(&0u32.to_le_bytes());

        dev.write(QUEUE_NOTIFY, 0);
        dev.process_queues(&mut ram, dram_base);
        assert_eq!(dev.actual_pages(), 2);
        dev.write(INTERRUPT_ACK, 1);

        // Second batch: 1 PFN using desc index 1
        let off2 = (data_addr2 - dram_base) as usize;
        ram[off2..off2 + 4].copy_from_slice(&30u32.to_le_bytes());

        let desc_off2 = (desc_addr - dram_base) as usize + 16; // desc[1]
        ram[desc_off2..desc_off2 + 8].copy_from_slice(&data_addr2.to_le_bytes());
        ram[desc_off2 + 8..desc_off2 + 12].copy_from_slice(&4u32.to_le_bytes());
        ram[desc_off2 + 12..desc_off2 + 16].copy_from_slice(&0u32.to_le_bytes());

        ram[avail_off + 2..avail_off + 4].copy_from_slice(&2u16.to_le_bytes()); // idx=2
        ram[avail_off + 6..avail_off + 8].copy_from_slice(&1u16.to_le_bytes()); // ring[1]=desc 1

        dev.write(QUEUE_NOTIFY, 0);
        dev.process_queues(&mut ram, dram_base);
        assert_eq!(dev.actual_pages(), 3);
        assert_eq!(dev.ballooned_pfns(), &[10, 20, 30]);
    }

    #[test]
    fn balloon_high_addr_queue_setup() {
        let mut dev = VirtioBalloon::new();
        dev.write(QUEUE_SEL, 0);
        dev.write(QUEUE_DESC_LOW, 0xDEAD_BEEF);
        dev.write(QUEUE_DESC_HIGH, 0x0000_0001);
        assert_eq!(dev.queues[0].desc_addr, 0x0000_0001_DEAD_BEEF);
    }
}
