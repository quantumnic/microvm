/// VirtIO Input Device — keyboard and mouse input for the guest
///
/// VirtIO device type 18. Provides evdev-compatible input events
/// (keyboard, relative mouse, sync) to the guest via eventq (virtqueue 0).
/// The guest can set LED state via statusq (virtqueue 1).
///
/// Input events follow Linux's `struct input_event` format (type, code, value).
/// The config space exposes device name, serial, and supported event bitmaps
/// via a subsel/devsel protocol.
use std::collections::VecDeque;

const VIRTIO_MAGIC: u32 = 0x7472_6976; // "virt"
const VIRTIO_VERSION: u32 = 2; // non-legacy MMIO
const DEVICE_ID: u32 = 18; // input device
const VENDOR_ID: u32 = 0x554D_4356; // "UMCV"

// Device status bits
const STATUS_ACKNOWLEDGE: u32 = 1;
const STATUS_DRIVER: u32 = 2;
const STATUS_FEATURES_OK: u32 = 8;
const STATUS_DRIVER_OK: u32 = 4;

// Config select values (written to offset 0x100)
#[allow(dead_code)]
const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;

// Linux input event types
#[allow(dead_code)]
pub const EV_SYN: u16 = 0x00;
#[allow(dead_code)]
pub const EV_KEY: u16 = 0x01;
#[allow(dead_code)]
pub const EV_REL: u16 = 0x02;

// Relative axes
#[allow(dead_code)]
pub const REL_X: u16 = 0x00;
#[allow(dead_code)]
pub const REL_Y: u16 = 0x01;

/// A single input event (matches Linux struct input_event layout for virtio)
#[derive(Clone, Copy, Debug)]
pub struct InputEvent {
    pub event_type: u16,
    pub code: u16,
    pub value: u32,
}

impl InputEvent {
    /// Encode as 8-byte virtio_input_event (le16 type, le16 code, le32 value)
    pub fn to_bytes(self) -> [u8; 8] {
        let mut buf = [0u8; 8];
        buf[0..2].copy_from_slice(&self.event_type.to_le_bytes());
        buf[2..4].copy_from_slice(&self.code.to_le_bytes());
        buf[4..8].copy_from_slice(&self.value.to_le_bytes());
        buf
    }
}

pub struct VirtioInput {
    // Device status
    status: u32,
    // Selected queue (0 = eventq, 1 = statusq)
    queue_sel: u32,
    // Queue descriptors, driver, device areas (2 queues)
    queue_desc: [u64; 2],
    queue_driver: [u64; 2],
    queue_device: [u64; 2],
    queue_num: [u32; 2],
    queue_ready: [bool; 2],
    last_avail_idx: [u16; 2],
    // Interrupt status
    interrupt_status: u32,
    // Feature negotiation
    guest_features_sel: u32,
    #[allow(dead_code)]
    guest_features: u64,
    driver_features_sel: u32,
    driver_features: u64,
    // Queue notify flags
    notify: [bool; 2],
    // Config space select/subsel for config reads
    cfg_select: u8,
    cfg_subsel: u8,
    // Pending input events
    event_queue: VecDeque<InputEvent>,
}

impl Default for VirtioInput {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioInput {
    pub fn new() -> Self {
        Self {
            status: 0,
            queue_sel: 0,
            queue_desc: [0; 2],
            queue_driver: [0; 2],
            queue_device: [0; 2],
            queue_num: [256; 2],
            queue_ready: [false; 2],
            last_avail_idx: [0; 2],
            interrupt_status: 0,
            guest_features_sel: 0,
            guest_features: 0,
            driver_features_sel: 0,
            driver_features: 0,
            notify: [false; 2],
            cfg_select: 0,
            cfg_subsel: 0,
            event_queue: VecDeque::new(),
        }
    }

    /// Push a key press or release event (evdev keycode)
    #[allow(dead_code)]
    pub fn push_key(&mut self, code: u16, pressed: bool) {
        self.event_queue.push_back(InputEvent {
            event_type: EV_KEY,
            code,
            value: if pressed { 1 } else { 0 },
        });
        // SYN_REPORT
        self.event_queue.push_back(InputEvent {
            event_type: EV_SYN,
            code: 0,
            value: 0,
        });
    }

    /// Push a relative mouse movement event
    #[allow(dead_code)]
    pub fn push_rel_mouse(&mut self, dx: i32, dy: i32) {
        if dx != 0 {
            self.event_queue.push_back(InputEvent {
                event_type: EV_REL,
                code: REL_X,
                value: dx as u32,
            });
        }
        if dy != 0 {
            self.event_queue.push_back(InputEvent {
                event_type: EV_REL,
                code: REL_Y,
                value: dy as u32,
            });
        }
        if dx != 0 || dy != 0 {
            self.event_queue.push_back(InputEvent {
                event_type: EV_SYN,
                code: 0,
                value: 0,
            });
        }
    }

    /// Get the config data for current cfg_select/cfg_subsel
    fn config_data(&self) -> &[u8] {
        match self.cfg_select {
            VIRTIO_INPUT_CFG_ID_NAME => b"microvm-input",
            VIRTIO_INPUT_CFG_ID_SERIAL => b"microvm-0",
            VIRTIO_INPUT_CFG_ID_DEVIDS => {
                // struct virtio_input_devids: bustype(u16), vendor(u16), product(u16), version(u16)
                // BUS_VIRTUAL=0x06, vendor=0, product=1, version=1
                static DEVIDS: [u8; 8] = [0x06, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00];
                &DEVIDS
            }
            VIRTIO_INPUT_CFG_PROP_BITS => &[],
            VIRTIO_INPUT_CFG_EV_BITS => {
                match self.cfg_subsel {
                    0 => {
                        // EV_SYN bitmap — bit 0 (EV_SYN=0, EV_KEY=1, EV_REL=2)
                        // Bitmap of supported event types: bits 0,1,2 → 0x07
                        static EV_TYPES: [u8; 1] = [0x07];
                        &EV_TYPES
                    }
                    1 => {
                        // EV_KEY bitmap — which keys are supported
                        // Support keys 1-127 (standard PC keyboard range)
                        // Bitmap: 128 bits = 16 bytes, all set except bit 0
                        static KEY_BITS: [u8; 16] = [
                            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                            0xFF, 0xFF, 0xFF, 0xFF,
                        ];
                        &KEY_BITS
                    }
                    2 => {
                        // EV_REL bitmap — REL_X (bit 0), REL_Y (bit 1)
                        static REL_BITS: [u8; 1] = [0x03];
                        &REL_BITS
                    }
                    _ => &[],
                }
            }
            VIRTIO_INPUT_CFG_ABS_INFO => &[], // No absolute axes
            _ => &[],
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
                if self.guest_features_sel == 1 {
                    1 // VIRTIO_F_VERSION_1
                } else {
                    0
                }
            }
            0x034 => {
                // QueueNumMax
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_num[q].min(256)
                } else {
                    0
                }
            }
            0x044 => {
                let q = self.queue_sel as usize;
                if q < 2 && self.queue_ready[q] {
                    1
                } else {
                    0
                }
            }
            0x060 => self.interrupt_status,
            0x070 => self.status,
            0x0FC => 0x01, // ConfigGeneration
            // Config space: offset 0x100 = select, 0x101 = subsel, 0x102 = size, 0x108.. = data
            0x100 => self.cfg_select as u32,
            0x104 => {
                // Byte at 0x101 (subsel) and 0x102 (size) packed
                // Actually MMIO reads are 32-bit aligned; size is at offset 0x102
                // For simplicity: return subsel in low byte
                self.cfg_subsel as u32
            }
            0x108 => {
                // Size of config data
                let data = self.config_data();
                data.len() as u32
            }
            // Config data starts at 0x10C (offset 12 within config space)
            offset @ 0x10C..=0x1FF => {
                let data = self.config_data();
                let idx = (offset - 0x10C) as usize;
                if idx + 4 <= data.len() {
                    u32::from_le_bytes(data[idx..idx + 4].try_into().unwrap())
                } else if idx < data.len() {
                    let mut buf = [0u8; 4];
                    let remaining = data.len() - idx;
                    buf[..remaining].copy_from_slice(&data[idx..]);
                    u32::from_le_bytes(buf)
                } else {
                    0
                }
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
            0x038 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_num[q] = (val as u32).min(256);
                }
            }
            0x044 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_ready[q] = val & 1 != 0;
                }
            }
            0x050 => {
                // QueueNotify
                let q = val as usize;
                if q < 2 {
                    self.notify[q] = true;
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
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_desc[q] =
                        (self.queue_desc[q] & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            0x084 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_desc[q] =
                        (self.queue_desc[q] & 0x0000_0000_FFFF_FFFF) | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            0x090 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_driver[q] =
                        (self.queue_driver[q] & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            0x094 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_driver[q] = (self.queue_driver[q] & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            0x0A0 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_device[q] =
                        (self.queue_device[q] & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            0x0A4 => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queue_device[q] = (self.queue_device[q] & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            // Config space writes
            0x100 => self.cfg_select = val as u8,
            0x104 => self.cfg_subsel = val as u8,
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.status = 0;
        self.queue_ready = [false; 2];
        self.last_avail_idx = [0; 2];
        self.interrupt_status = 0;
        self.notify = [false; 2];
        self.queue_desc = [0; 2];
        self.queue_driver = [0; 2];
        self.queue_device = [0; 2];
        self.driver_features = 0;
        self.event_queue.clear();
    }

    pub fn has_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    fn is_driver_ok(&self) -> bool {
        (self.status & STATUS_DRIVER_OK) != 0
            && (self.status & STATUS_ACKNOWLEDGE) != 0
            && (self.status & STATUS_DRIVER) != 0
            && (self.status & STATUS_FEATURES_OK) != 0
    }

    /// Process eventq: deliver pending input events to the guest
    pub fn process_eventq(&mut self, ram: &mut [u8], dram_base: u64) {
        if !self.is_driver_ok() || !self.queue_ready[0] || self.event_queue.is_empty() {
            return;
        }

        let desc_base = self.queue_desc[0];
        let avail_base = self.queue_driver[0];
        let used_base = self.queue_device[0];
        let queue_size = self.queue_num[0] as u16;

        // Read avail index
        let avail_idx_off = (avail_base - dram_base + 2) as usize;
        if avail_idx_off + 2 > ram.len() {
            return;
        }
        let avail_idx = u16::from_le_bytes([ram[avail_idx_off], ram[avail_idx_off + 1]]);

        let mut used_count = 0u16;

        while !self.event_queue.is_empty() && self.last_avail_idx[0] != avail_idx {
            let ring_idx = (self.last_avail_idx[0] % queue_size) as usize;
            let avail_ring_off = (avail_base - dram_base + 4 + ring_idx as u64 * 2) as usize;
            if avail_ring_off + 2 > ram.len() {
                break;
            }
            let desc_idx =
                u16::from_le_bytes([ram[avail_ring_off], ram[avail_ring_off + 1]]) as u64;

            // Read descriptor
            let desc_off = (desc_base - dram_base + desc_idx * 16) as usize;
            if desc_off + 16 > ram.len() {
                break;
            }
            let buf_addr = u64::from_le_bytes(ram[desc_off..desc_off + 8].try_into().unwrap());
            let buf_len = u32::from_le_bytes(ram[desc_off + 8..desc_off + 12].try_into().unwrap());
            let flags = u16::from_le_bytes(ram[desc_off + 12..desc_off + 14].try_into().unwrap());

            // Must be device-writable (flag bit 1)
            if flags & 2 == 0 || buf_len < 8 {
                self.last_avail_idx[0] = self.last_avail_idx[0].wrapping_add(1);
                continue;
            }

            let event = self.event_queue.pop_front().unwrap();
            let event_bytes = event.to_bytes();
            let ram_off = (buf_addr - dram_base) as usize;
            if ram_off + 8 <= ram.len() {
                ram[ram_off..ram_off + 8].copy_from_slice(&event_bytes);
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
                .copy_from_slice(&(desc_idx as u32).to_le_bytes());
            ram[used_ring_entry + 4..used_ring_entry + 8].copy_from_slice(&8u32.to_le_bytes());

            let new_used_idx = current_used_idx.wrapping_add(1);
            ram[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used_idx.to_le_bytes());

            self.last_avail_idx[0] = self.last_avail_idx[0].wrapping_add(1);
            used_count += 1;
        }

        if used_count > 0 {
            self.interrupt_status |= 1;
        }
    }

    /// Process statusq: read LED status updates from the guest (consumed and ignored)
    #[allow(dead_code)]
    pub fn process_statusq(&mut self, ram: &mut [u8], dram_base: u64) {
        if !self.is_driver_ok() || !self.queue_ready[1] || !self.notify[1] {
            return;
        }
        self.notify[1] = false;

        let avail_base = self.queue_driver[1];
        let used_base = self.queue_device[1];
        let queue_size = self.queue_num[1] as u16;

        let avail_idx_off = (avail_base - dram_base + 2) as usize;
        if avail_idx_off + 2 > ram.len() {
            return;
        }
        let avail_idx = u16::from_le_bytes([ram[avail_idx_off], ram[avail_idx_off + 1]]);

        while self.last_avail_idx[1] != avail_idx {
            let ring_idx = (self.last_avail_idx[1] % queue_size) as usize;
            let avail_ring_off = (avail_base - dram_base + 4 + ring_idx as u64 * 2) as usize;
            if avail_ring_off + 2 > ram.len() {
                break;
            }
            let desc_idx =
                u16::from_le_bytes([ram[avail_ring_off], ram[avail_ring_off + 1]]) as u64;

            // Write used ring entry (we consume but ignore the LED status)
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
                .copy_from_slice(&(desc_idx as u32).to_le_bytes());
            ram[used_ring_entry + 4..used_ring_entry + 8].copy_from_slice(&0u32.to_le_bytes());

            let new_used_idx = current_used_idx.wrapping_add(1);
            ram[used_idx_off..used_idx_off + 2].copy_from_slice(&new_used_idx.to_le_bytes());

            self.last_avail_idx[1] = self.last_avail_idx[1].wrapping_add(1);
        }
    }

    /// Check if there are pending events to deliver
    pub fn has_pending_events(&self) -> bool {
        !self.event_queue.is_empty()
    }

    /// Number of pending events
    #[allow(dead_code)]
    pub fn pending_event_count(&self) -> usize {
        self.event_queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_virtio_input_magic_and_id() {
        let input = VirtioInput::new();
        assert_eq!(input.read(0x000), VIRTIO_MAGIC);
        assert_eq!(input.read(0x004), VIRTIO_VERSION);
        assert_eq!(input.read(0x008), 18); // device type 18 = input
        assert_eq!(input.read(0x00C), VENDOR_ID);
    }

    #[test]
    fn test_virtio_input_status_lifecycle() {
        let mut input = VirtioInput::new();
        assert_eq!(input.read(0x070), 0);

        input.write(0x070, STATUS_ACKNOWLEDGE as u64);
        assert_eq!(input.read(0x070), STATUS_ACKNOWLEDGE);

        input.write(0x070, (STATUS_ACKNOWLEDGE | STATUS_DRIVER) as u64);
        assert_eq!(input.read(0x070), STATUS_ACKNOWLEDGE | STATUS_DRIVER);

        // Reset
        input.write(0x070, 0);
        assert_eq!(input.read(0x070), 0);
    }

    #[test]
    fn test_virtio_input_version1_feature() {
        let mut input = VirtioInput::new();
        input.write(0x014, 0);
        assert_eq!(input.read(0x010), 0);
        input.write(0x014, 1);
        assert_eq!(input.read(0x010), 1, "VIRTIO_F_VERSION_1 must be set");
    }

    #[test]
    fn test_virtio_input_queue_setup_two_queues() {
        let mut input = VirtioInput::new();
        // Queue 0 (eventq)
        input.write(0x030, 0);
        assert_eq!(input.read(0x034), 256);
        input.write(0x038, 128);
        input.write(0x080, 0x1000);
        input.write(0x084, 0);
        input.write(0x044, 1);
        assert_eq!(input.read(0x044), 1);

        // Queue 1 (statusq)
        input.write(0x030, 1);
        assert_eq!(input.read(0x034), 256);
        input.write(0x038, 64);
        input.write(0x080, 0x2000);
        input.write(0x084, 0);
        input.write(0x044, 1);
        assert_eq!(input.read(0x044), 1);

        // Queue 2 (does not exist)
        input.write(0x030, 2);
        assert_eq!(input.read(0x034), 0);
    }

    #[test]
    fn test_virtio_input_interrupt_ack() {
        let mut input = VirtioInput::new();
        input.interrupt_status = 1;
        assert!(input.has_interrupt());
        input.write(0x064, 1);
        assert!(!input.has_interrupt());
    }

    #[test]
    fn test_virtio_input_config_name() {
        let mut input = VirtioInput::new();
        input.write(0x100, VIRTIO_INPUT_CFG_ID_NAME as u64);
        // Size should be length of "microvm-input" = 13
        assert_eq!(input.read(0x108), 13);
        // First 4 bytes: "micr"
        let first4 = input.read(0x10C);
        assert_eq!(&first4.to_le_bytes(), b"micr");
    }

    #[test]
    fn test_virtio_input_config_serial() {
        let mut input = VirtioInput::new();
        input.write(0x100, VIRTIO_INPUT_CFG_ID_SERIAL as u64);
        assert_eq!(input.read(0x108), 9); // "microvm-0"
    }

    #[test]
    fn test_virtio_input_config_devids() {
        let mut input = VirtioInput::new();
        input.write(0x100, VIRTIO_INPUT_CFG_ID_DEVIDS as u64);
        assert_eq!(input.read(0x108), 8);
        let first4 = input.read(0x10C);
        // bustype=0x0006 (BUS_VIRTUAL), vendor=0x0000
        assert_eq!(first4, 0x0000_0006);
    }

    #[test]
    fn test_virtio_input_config_ev_bits() {
        let mut input = VirtioInput::new();
        // Event types bitmap (subsel=0 for EV_SYN page)
        input.write(0x100, VIRTIO_INPUT_CFG_EV_BITS as u64);
        input.write(0x104, 0); // subsel=0 → event type bitmap
        assert_eq!(input.read(0x108), 1); // 1 byte
        let ev_types = input.read(0x10C) & 0xFF;
        assert_eq!(ev_types, 0x07); // EV_SYN | EV_KEY | EV_REL

        // Key bitmap (subsel=1)
        input.write(0x104, 1);
        assert_eq!(input.read(0x108), 16); // 16 bytes = 128 key bits

        // Rel bitmap (subsel=2)
        input.write(0x104, 2);
        assert_eq!(input.read(0x108), 1);
        let rel_bits = input.read(0x10C) & 0xFF;
        assert_eq!(rel_bits, 0x03); // REL_X | REL_Y
    }

    #[test]
    fn test_virtio_input_push_key_events() {
        let mut input = VirtioInput::new();
        assert!(!input.has_pending_events());
        assert_eq!(input.pending_event_count(), 0);

        // Press key 30 (KEY_A)
        input.push_key(30, true);
        assert!(input.has_pending_events());
        assert_eq!(input.pending_event_count(), 2); // KEY + SYN

        // Release
        input.push_key(30, false);
        assert_eq!(input.pending_event_count(), 4); // 2 more

        // Check event contents
        let ev = input.event_queue.pop_front().unwrap();
        assert_eq!(ev.event_type, EV_KEY);
        assert_eq!(ev.code, 30);
        assert_eq!(ev.value, 1);

        let syn = input.event_queue.pop_front().unwrap();
        assert_eq!(syn.event_type, EV_SYN);
    }

    #[test]
    fn test_virtio_input_push_mouse_events() {
        let mut input = VirtioInput::new();
        input.push_rel_mouse(10, -5);
        assert_eq!(input.pending_event_count(), 3); // REL_X + REL_Y + SYN

        let ev_x = input.event_queue.pop_front().unwrap();
        assert_eq!(ev_x.event_type, EV_REL);
        assert_eq!(ev_x.code, REL_X);
        assert_eq!(ev_x.value, 10u32);

        let ev_y = input.event_queue.pop_front().unwrap();
        assert_eq!(ev_y.event_type, EV_REL);
        assert_eq!(ev_y.code, REL_Y);
        assert_eq!(ev_y.value, (-5i32) as u32);
    }

    #[test]
    fn test_virtio_input_push_mouse_zero_noop() {
        let mut input = VirtioInput::new();
        input.push_rel_mouse(0, 0);
        assert_eq!(input.pending_event_count(), 0);
    }

    #[test]
    fn test_virtio_input_event_to_bytes() {
        let ev = InputEvent {
            event_type: EV_KEY,
            code: 30,
            value: 1,
        };
        let bytes = ev.to_bytes();
        assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), EV_KEY);
        assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 30);
        assert_eq!(
            u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            1
        );
    }

    #[test]
    fn test_virtio_input_reset_clears_events() {
        let mut input = VirtioInput::new();
        input.push_key(30, true);
        assert!(input.has_pending_events());
        input.write(0x070, 0); // reset
        assert!(!input.has_pending_events());
    }

    #[test]
    fn test_virtio_input_config_unset() {
        let mut input = VirtioInput::new();
        input.write(0x100, VIRTIO_INPUT_CFG_UNSET as u64);
        assert_eq!(input.read(0x108), 0); // no data
    }

    #[test]
    fn test_virtio_input_config_prop_bits() {
        let mut input = VirtioInput::new();
        input.write(0x100, VIRTIO_INPUT_CFG_PROP_BITS as u64);
        assert_eq!(input.read(0x108), 0); // no properties
    }

    #[test]
    fn test_virtio_input_config_abs_info() {
        let mut input = VirtioInput::new();
        input.write(0x100, VIRTIO_INPUT_CFG_ABS_INFO as u64);
        assert_eq!(input.read(0x108), 0); // no absolute axes
    }
}
