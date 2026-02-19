/// VirtIO MMIO Console Device (v2)
///
/// Implements a VirtIO console (device ID 3) over MMIO transport.
/// Provides a `hvc0` console for Linux guests — alternative to 16550 UART.
/// Uses two virtqueues: receiveq (0) for host→guest, transmitq (1) for guest→host.
///
/// Reference: VirtIO spec v1.2, sections 2 (basic facilities), 4.2 (MMIO),
/// and 5.3 (console device).
use std::collections::VecDeque;
use std::io::Write;

// VirtIO MMIO register offsets (same as block device)
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
// Console config space at 0x100
const CONFIG_COLS: u64 = 0x100; // u16
const CONFIG_ROWS: u64 = 0x102; // u16
const CONFIG_MAX_NR_PORTS: u64 = 0x104; // u32
const CONFIG_EMERG_WR: u64 = 0x108; // u32

// Feature bits
const VIRTIO_CONSOLE_F_SIZE: u32 = 1 << 0; // Console size (cols/rows) available
const VIRTIO_CONSOLE_F_EMERG_WRITE: u32 = 1 << 2; // Emergency write supported

// VirtIO status bits
const STATUS_DRIVER_OK: u32 = 4;

// Virtqueue descriptor flags
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: u32 = 64;
const NUM_QUEUES: usize = 2; // receiveq (0) + transmitq (1)

/// VirtIO queue state
struct Virtqueue {
    num: u32,
    ready: bool,
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
    last_avail_idx: u16,
    /// Notification pending (set on QUEUE_NOTIFY write)
    notified: bool,
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
            notified: false,
        }
    }
}

/// VirtIO MMIO Console Device
pub struct VirtioConsole {
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
    /// Virtqueues: [0] = receiveq, [1] = transmitq
    queues: [Virtqueue; NUM_QUEUES],
    /// Interrupt status
    interrupt_status: u32,
    /// Whether an interrupt is pending
    irq_pending: bool,
    /// Input buffer (host → guest), fed via push_byte()
    input_buf: VecDeque<u8>,
}

impl Default for VirtioConsole {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioConsole {
    pub fn new() -> Self {
        Self {
            status: 0,
            device_features_sel: 0,
            driver_features_sel: 0,
            driver_features: [0; 2],
            queue_sel: 0,
            queues: [Virtqueue::new(), Virtqueue::new()],
            interrupt_status: 0,
            irq_pending: false,
            input_buf: VecDeque::new(),
        }
    }

    /// Push a byte from the host into the console input buffer (for guest to read)
    #[allow(dead_code)]
    pub fn push_byte(&mut self, b: u8) {
        self.input_buf.push_back(b);
    }

    /// Check if interrupt is pending
    pub fn has_interrupt(&self) -> bool {
        self.irq_pending
    }

    fn queue(&self, idx: usize) -> &Virtqueue {
        &self.queues[idx.min(NUM_QUEUES - 1)]
    }

    fn queue_mut(&mut self, idx: usize) -> &mut Virtqueue {
        &mut self.queues[idx.min(NUM_QUEUES - 1)]
    }

    fn selected_queue(&self) -> usize {
        (self.queue_sel as usize).min(NUM_QUEUES - 1)
    }

    pub fn read(&self, offset: u64) -> u64 {
        match offset {
            MAGIC_VALUE => 0x74726976, // "virt"
            VERSION => 2,
            DEVICE_ID => 3, // Console device
            VENDOR_ID => 0x554D4551,
            DEVICE_FEATURES => match self.device_features_sel {
                0 => (VIRTIO_CONSOLE_F_SIZE | VIRTIO_CONSOLE_F_EMERG_WRITE) as u64,
                1 => 1, // VIRTIO_F_VERSION_1
                _ => 0,
            },
            QUEUE_NUM_MAX => QUEUE_SIZE as u64,
            QUEUE_READY => {
                let idx = self.selected_queue();
                self.queue(idx).ready as u64
            }
            INTERRUPT_STATUS => self.interrupt_status as u64,
            STATUS => self.status as u64,
            CONFIG_GENERATION => 0,
            // Console config: cols=80, rows=24
            CONFIG_COLS => 80,
            CONFIG_ROWS => 24,
            CONFIG_MAX_NR_PORTS => 1,
            CONFIG_EMERG_WR => 0,
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
                let idx = self.selected_queue();
                self.queue_mut(idx).num = val as u32;
            }
            QUEUE_READY => {
                let idx = self.selected_queue();
                self.queue_mut(idx).ready = val != 0;
            }
            QUEUE_NOTIFY => {
                let q_idx = val as usize;
                if q_idx < NUM_QUEUES {
                    self.queues[q_idx].notified = true;
                }
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
                    self.reset();
                }
            }
            QUEUE_DESC_LOW => {
                let idx = self.selected_queue();
                let q = self.queue_mut(idx);
                q.desc_addr = (q.desc_addr & 0xFFFFFFFF_00000000) | (val & 0xFFFFFFFF);
            }
            QUEUE_DESC_HIGH => {
                let idx = self.selected_queue();
                let q = self.queue_mut(idx);
                q.desc_addr = (q.desc_addr & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32);
            }
            QUEUE_AVAIL_LOW => {
                let idx = self.selected_queue();
                let q = self.queue_mut(idx);
                q.avail_addr = (q.avail_addr & 0xFFFFFFFF_00000000) | (val & 0xFFFFFFFF);
            }
            QUEUE_AVAIL_HIGH => {
                let idx = self.selected_queue();
                let q = self.queue_mut(idx);
                q.avail_addr = (q.avail_addr & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32);
            }
            QUEUE_USED_LOW => {
                let idx = self.selected_queue();
                let q = self.queue_mut(idx);
                q.used_addr = (q.used_addr & 0xFFFFFFFF_00000000) | (val & 0xFFFFFFFF);
            }
            QUEUE_USED_HIGH => {
                let idx = self.selected_queue();
                let q = self.queue_mut(idx);
                q.used_addr = (q.used_addr & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32);
            }
            CONFIG_EMERG_WR => {
                // Emergency write — output a single character immediately
                let ch = val as u8;
                let mut stdout = std::io::stdout().lock();
                let _ = stdout.write_all(&[ch]);
                let _ = stdout.flush();
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.status = 0;
        self.interrupt_status = 0;
        self.irq_pending = false;
        self.queues = [Virtqueue::new(), Virtqueue::new()];
        self.input_buf.clear();
    }

    /// Check if transmitq needs processing
    pub fn needs_processing(&self) -> bool {
        let driver_ok = (self.status & STATUS_DRIVER_OK) != 0;
        let tx_notified = self.queues[1].notified;
        let rx_has_data = !self.input_buf.is_empty() && self.queues[0].ready;
        driver_ok && (tx_notified || rx_has_data)
    }

    /// Process pending virtqueue requests.
    /// `ram` is the guest RAM slice, `dram_base` is the physical base address of RAM.
    pub fn process_queues(&mut self, ram: &mut [u8], dram_base: u64) {
        if (self.status & STATUS_DRIVER_OK) == 0 {
            return;
        }

        // Process transmitq (queue 1): guest → host output
        if self.queues[1].notified && self.queues[1].ready {
            self.queues[1].notified = false;
            self.process_transmitq(ram, dram_base);
        }

        // Process receiveq (queue 0): host → guest input
        if !self.input_buf.is_empty() && self.queues[0].ready {
            self.process_receiveq(ram, dram_base);
        }
    }

    /// Process transmitq: read data from guest and write to stdout
    fn process_transmitq(&mut self, ram: &mut [u8], dram_base: u64) {
        let q = &self.queues[1];
        let desc_addr = q.desc_addr;
        let avail_addr = q.avail_addr;
        let used_addr = q.used_addr;
        let num = q.num;
        let mut last_avail = q.last_avail_idx;

        let avail_idx = read_u16(ram, avail_addr + 2, dram_base);
        if avail_idx == last_avail {
            return;
        }

        let mut stdout = std::io::stdout().lock();
        let mut did_work = false;

        while last_avail != avail_idx {
            let ring_idx = (last_avail as u32 % num) as u64;
            let first_desc_idx = read_u16(ram, avail_addr + 4 + ring_idx * 2, dram_base) as u64;

            let mut total_written = 0u32;
            let mut desc_idx = first_desc_idx;

            // Walk the descriptor chain
            loop {
                let desc = read_descriptor(ram, dram_base, desc_addr, desc_idx);

                // Transmit descriptors are read-only (data from guest)
                if desc.flags & VRING_DESC_F_WRITE == 0 {
                    let off = addr_to_ram_offset(desc.addr, dram_base);
                    let end = off + desc.len as usize;
                    if end <= ram.len() {
                        let _ = stdout.write_all(&ram[off..end]);
                    }
                }
                total_written += desc.len;

                if desc.flags & VRING_DESC_F_NEXT != 0 {
                    desc_idx = desc.next as u64;
                } else {
                    break;
                }
            }

            // Update used ring
            let used_idx = read_u16(ram, used_addr + 2, dram_base);
            let used_ring_idx = (used_idx as u32 % num) as u64;
            let used_elem_addr = used_addr + 4 + used_ring_idx * 8;
            write_u32(ram, used_elem_addr, dram_base, first_desc_idx as u32);
            write_u32(ram, used_elem_addr + 4, dram_base, total_written);
            write_u16(ram, used_addr + 2, dram_base, used_idx.wrapping_add(1));

            last_avail = last_avail.wrapping_add(1);
            did_work = true;
        }

        let _ = stdout.flush();
        self.queues[1].last_avail_idx = last_avail;

        if did_work {
            self.interrupt_status |= 1;
            self.irq_pending = true;
        }
    }

    /// Process receiveq: write input data to guest buffers
    fn process_receiveq(&mut self, ram: &mut [u8], dram_base: u64) {
        if self.input_buf.is_empty() {
            return;
        }

        let q = &self.queues[0];
        let desc_addr = q.desc_addr;
        let avail_addr = q.avail_addr;
        let used_addr = q.used_addr;
        let num = q.num;
        let mut last_avail = q.last_avail_idx;

        let avail_idx = read_u16(ram, avail_addr + 2, dram_base);
        let mut did_work = false;

        while last_avail != avail_idx && !self.input_buf.is_empty() {
            let ring_idx = (last_avail as u32 % num) as u64;
            let first_desc_idx = read_u16(ram, avail_addr + 4 + ring_idx * 2, dram_base) as u64;

            let mut total_written = 0u32;
            let mut desc_idx = first_desc_idx;

            // Walk the descriptor chain, fill writable buffers with input data
            loop {
                let desc = read_descriptor(ram, dram_base, desc_addr, desc_idx);

                if desc.flags & VRING_DESC_F_WRITE != 0 {
                    let off = addr_to_ram_offset(desc.addr, dram_base);
                    let max_bytes = desc.len as usize;
                    let mut written = 0usize;
                    while written < max_bytes {
                        if let Some(b) = self.input_buf.pop_front() {
                            if off + written < ram.len() {
                                ram[off + written] = b;
                            }
                            written += 1;
                        } else {
                            break;
                        }
                    }
                    total_written += written as u32;
                }

                if desc.flags & VRING_DESC_F_NEXT != 0 {
                    desc_idx = desc.next as u64;
                } else {
                    break;
                }
            }

            // Update used ring
            let used_idx = read_u16(ram, used_addr + 2, dram_base);
            let used_ring_idx = (used_idx as u32 % num) as u64;
            let used_elem_addr = used_addr + 4 + used_ring_idx * 8;
            write_u32(ram, used_elem_addr, dram_base, first_desc_idx as u32);
            write_u32(ram, used_elem_addr + 4, dram_base, total_written);
            write_u16(ram, used_addr + 2, dram_base, used_idx.wrapping_add(1));

            last_avail = last_avail.wrapping_add(1);
            did_work = true;
        }

        self.queues[0].last_avail_idx = last_avail;

        if did_work {
            self.interrupt_status |= 1;
            self.irq_pending = true;
        }
    }
}

// --- Helper functions (same pattern as virtio_blk) ---

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
    fn test_virtio_console_magic() {
        let con = VirtioConsole::new();
        assert_eq!(con.read(MAGIC_VALUE), 0x74726976);
    }

    #[test]
    fn test_virtio_console_device_id() {
        let con = VirtioConsole::new();
        assert_eq!(con.read(DEVICE_ID), 3); // Console device
    }

    #[test]
    fn test_virtio_console_version() {
        let con = VirtioConsole::new();
        assert_eq!(con.read(VERSION), 2);
    }

    #[test]
    fn test_virtio_console_features() {
        let mut con = VirtioConsole::new();
        con.write(DEVICE_FEATURES_SEL, 0);
        let feats = con.read(DEVICE_FEATURES) as u32;
        assert!(feats & VIRTIO_CONSOLE_F_SIZE != 0);
        assert!(feats & VIRTIO_CONSOLE_F_EMERG_WRITE != 0);

        con.write(DEVICE_FEATURES_SEL, 1);
        assert_eq!(con.read(DEVICE_FEATURES), 1); // VIRTIO_F_VERSION_1
    }

    #[test]
    fn test_virtio_console_config() {
        let con = VirtioConsole::new();
        assert_eq!(con.read(CONFIG_COLS), 80);
        assert_eq!(con.read(CONFIG_ROWS), 24);
        assert_eq!(con.read(CONFIG_MAX_NR_PORTS), 1);
    }

    #[test]
    fn test_virtio_console_status_reset() {
        let mut con = VirtioConsole::new();
        con.write(STATUS, 1);
        assert_eq!(con.read(STATUS), 1);
        con.push_byte(b'x');
        con.write(STATUS, 0); // Reset
        assert_eq!(con.read(STATUS), 0);
        assert!(!con.has_interrupt());
    }

    #[test]
    fn test_virtio_console_queue_setup() {
        let mut con = VirtioConsole::new();
        // Set up receiveq (queue 0)
        con.write(QUEUE_SEL, 0);
        assert_eq!(con.read(QUEUE_NUM_MAX), QUEUE_SIZE as u64);
        con.write(QUEUE_NUM, 32);
        con.write(QUEUE_DESC_LOW, 0x80010000);
        con.write(QUEUE_DESC_HIGH, 0);
        con.write(QUEUE_READY, 1);
        assert_eq!(con.read(QUEUE_READY), 1);

        // Set up transmitq (queue 1)
        con.write(QUEUE_SEL, 1);
        con.write(QUEUE_NUM, 32);
        con.write(QUEUE_DESC_LOW, 0x80020000);
        con.write(QUEUE_DESC_HIGH, 0);
        con.write(QUEUE_READY, 1);
        assert_eq!(con.read(QUEUE_READY), 1);
    }

    #[test]
    fn test_virtio_console_interrupt_ack() {
        let mut con = VirtioConsole::new();
        con.interrupt_status = 1;
        con.irq_pending = true;
        assert!(con.has_interrupt());
        assert_eq!(con.read(INTERRUPT_STATUS), 1);
        con.write(INTERRUPT_ACK, 1);
        assert!(!con.has_interrupt());
        assert_eq!(con.read(INTERRUPT_STATUS), 0);
    }

    #[test]
    fn test_virtio_console_input_buffer() {
        let mut con = VirtioConsole::new();
        con.push_byte(b'H');
        con.push_byte(b'i');
        assert!(!con.input_buf.is_empty());
        assert_eq!(con.input_buf.len(), 2);
    }
}
