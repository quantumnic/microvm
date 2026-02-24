pub mod ram;
pub mod rom;

use crate::devices::{
    clint::Clint, plic::Plic, rtc::GoldfishRtc, syscon::Syscon, uart::Uart, virtio_9p::Virtio9p,
    virtio_blk::VirtioBlk, virtio_console::VirtioConsole, virtio_net::VirtioNet,
    virtio_rng::VirtioRng,
};

/// SBI HSM hart start request: (target_hart, start_addr, opaque)
#[derive(Debug, Clone)]
pub struct HartStartRequest {
    pub hart_id: usize,
    pub start_addr: u64,
    pub opaque: u64,
}

/// Remote TLB flush request from SBI RFENCE
#[derive(Debug, Clone)]
pub struct TlbFlushRequest {
    pub hart_id: usize,
    pub start_addr: Option<u64>, // None = flush all
    pub size: u64,
}

// Memory map
pub const UART_BASE: u64 = 0x1000_0000;
pub const UART_SIZE: u64 = 0x100;
pub const VIRTIO0_BASE: u64 = 0x1000_1000; // VirtIO block
pub const VIRTIO0_SIZE: u64 = 0x1000;
pub const VIRTIO1_BASE: u64 = 0x1000_2000; // VirtIO console
pub const VIRTIO1_SIZE: u64 = 0x1000;
pub const VIRTIO2_BASE: u64 = 0x1000_3000; // VirtIO RNG
pub const VIRTIO2_SIZE: u64 = 0x1000;
pub const VIRTIO3_BASE: u64 = 0x1000_4000; // VirtIO Net
pub const VIRTIO3_SIZE: u64 = 0x1000;
pub const VIRTIO4_BASE: u64 = 0x1000_7000; // VirtIO 9P
pub const VIRTIO4_SIZE: u64 = 0x1000;
pub const RTC_BASE: u64 = 0x1000_5000; // Goldfish RTC
pub const RTC_SIZE: u64 = 0x1000;
pub const SYSCON_BASE: u64 = 0x1000_6000; // Syscon (poweroff/reboot)
pub const SYSCON_SIZE: u64 = 0x1000;
pub const CLINT_BASE: u64 = 0x0200_0000;
pub const CLINT_SIZE: u64 = 0x10000;
pub const PLIC_BASE: u64 = 0x0C00_0000;
pub const PLIC_SIZE: u64 = 0x400000;
pub const DRAM_BASE: u64 = 0x8000_0000;

/// Physical memory bus with MMIO dispatch
pub struct Bus {
    pub ram: ram::Ram,
    pub uart: Uart,
    pub clint: Clint,
    pub plic: Plic,
    pub virtio_blk: VirtioBlk,
    pub virtio_console: VirtioConsole,
    pub virtio_rng: VirtioRng,
    pub virtio_net: VirtioNet,
    pub virtio_9p: Virtio9p,
    pub rtc: GoldfishRtc,
    pub syscon: Syscon,
    /// Pending hart start requests from SBI HSM
    pub hart_start_queue: Vec<HartStartRequest>,
    /// Pending remote TLB flush requests from SBI RFENCE
    pub tlb_flush_queue: Vec<TlbFlushRequest>,
    /// Hart states visible to SBI hart_get_status (synced by VM loop)
    pub hart_states: Vec<u64>,
    /// Number of harts in the system (for SBI validation)
    pub num_harts: usize,
}

impl Bus {
    pub fn new(ram_size: u64) -> Self {
        Self {
            ram: ram::Ram::new(ram_size),
            uart: Uart::new(),
            clint: Clint::new(),
            plic: Plic::new(),
            virtio_blk: VirtioBlk::new(),
            virtio_console: VirtioConsole::new(),
            virtio_rng: VirtioRng::new(),
            virtio_net: VirtioNet::new(),
            virtio_9p: Virtio9p::new(),
            rtc: GoldfishRtc::new(),
            syscon: Syscon::new(),
            hart_start_queue: Vec::new(),
            tlb_flush_queue: Vec::new(),
            hart_states: Vec::new(),
            num_harts: 1,
        }
    }

    /// Route a physical address to the correct MMIO device or RAM.
    /// Returns (device_id, offset) where device_id:
    ///   0=RAM, 1=UART, 2=VirtIO blk, 3=CLINT, 4=PLIC,
    ///   5=VirtIO console, 6=VirtIO RNG, 7=VirtIO Net, 8=RTC, 9=Syscon, 10=VirtIO 9P, 0xFF=unmapped
    #[inline(always)]
    fn route(&self, addr: u64) -> (u8, u64) {
        if addr >= DRAM_BASE {
            let offset = addr - DRAM_BASE;
            if offset < self.ram.size() {
                return (0, offset);
            }
        }
        if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
            return (1, addr - UART_BASE);
        }
        if (VIRTIO0_BASE..VIRTIO0_BASE + VIRTIO0_SIZE).contains(&addr) {
            return (2, addr - VIRTIO0_BASE);
        }
        if (VIRTIO1_BASE..VIRTIO1_BASE + VIRTIO1_SIZE).contains(&addr) {
            return (5, addr - VIRTIO1_BASE);
        }
        if (VIRTIO2_BASE..VIRTIO2_BASE + VIRTIO2_SIZE).contains(&addr) {
            return (6, addr - VIRTIO2_BASE);
        }
        if (VIRTIO3_BASE..VIRTIO3_BASE + VIRTIO3_SIZE).contains(&addr) {
            return (7, addr - VIRTIO3_BASE);
        }
        if (VIRTIO4_BASE..VIRTIO4_BASE + VIRTIO4_SIZE).contains(&addr) {
            return (10, addr - VIRTIO4_BASE);
        }
        if (RTC_BASE..RTC_BASE + RTC_SIZE).contains(&addr) {
            return (8, addr - RTC_BASE);
        }
        if (SYSCON_BASE..SYSCON_BASE + SYSCON_SIZE).contains(&addr) {
            return (9, addr - SYSCON_BASE);
        }
        if (CLINT_BASE..CLINT_BASE + CLINT_SIZE).contains(&addr) {
            return (3, addr - CLINT_BASE);
        }
        if (PLIC_BASE..PLIC_BASE + PLIC_SIZE).contains(&addr) {
            return (4, addr - PLIC_BASE);
        }
        (0xFF, 0)
    }

    pub fn read8(&mut self, addr: u64) -> u8 {
        match self.route(addr) {
            (0, off) => self.ram.read8(off),
            (1, off) => self.uart.read_mut(off) as u8,
            (2, off) => self.virtio_blk.read(off) as u8,
            (3, off) => self.clint.read(off) as u8,
            (4, off) => self.plic.read(off) as u8,
            (5, off) => self.virtio_console.read(off) as u8,
            (6, off) => self.virtio_rng.read(off) as u8,
            (7, off) => self.virtio_net.read(off) as u8,
            (8, off) => self.rtc.read(off) as u8,
            (9, off) => self.syscon.read(off) as u8,
            (10, off) => self.virtio_9p.read(off) as u8,
            _ => {
                log::trace!("Bus: unmapped read8 at {:#010x}", addr);
                0
            }
        }
    }

    /// Fast instruction fetch: returns (raw32_or_16, is_compressed).
    /// Bypasses device routing — only valid for DRAM physical addresses.
    /// Falls back to standard read path for non-DRAM addresses.
    #[inline]
    pub fn fetch_insn(&mut self, phys_pc: u64) -> (u32, bool) {
        if phys_pc >= DRAM_BASE {
            let off = (phys_pc - DRAM_BASE) as usize;
            let ram_slice = self.ram.as_slice();
            if off + 1 < ram_slice.len() {
                let lo = u16::from_le_bytes([ram_slice[off], ram_slice[off + 1]]);
                if lo & 0x03 != 0x03 {
                    // Compressed 16-bit instruction
                    return (lo as u32, true);
                }
                if off + 3 < ram_slice.len() {
                    let raw32 = u32::from_le_bytes([
                        ram_slice[off],
                        ram_slice[off + 1],
                        ram_slice[off + 2],
                        ram_slice[off + 3],
                    ]);
                    return (raw32, false);
                }
            }
        }
        // Fallback for non-DRAM (e.g., boot ROM)
        let raw16 = self.read16(phys_pc);
        if raw16 & 0x03 != 0x03 {
            (raw16 as u32, true)
        } else {
            (self.read32(phys_pc), false)
        }
    }

    pub fn read16(&mut self, addr: u64) -> u16 {
        match self.route(addr) {
            (0, off) => {
                let lo = self.ram.read8(off) as u16;
                let hi = self.ram.read8(off + 1) as u16;
                lo | (hi << 8)
            }
            _ => {
                let lo = self.read8(addr) as u16;
                let hi = self.read8(addr + 1) as u16;
                lo | (hi << 8)
            }
        }
    }

    pub fn read32(&mut self, addr: u64) -> u32 {
        match self.route(addr) {
            (0, off) => self.ram.read32(off),
            (1, off) => self.uart.read_mut(off) as u32,
            (2, off) => self.virtio_blk.read(off) as u32,
            (3, off) => self.clint.read(off) as u32,
            (4, off) => self.plic.read(off) as u32,
            (5, off) => self.virtio_console.read(off) as u32,
            (6, off) => self.virtio_rng.read(off),
            (7, off) => self.virtio_net.read(off),
            (8, off) => self.rtc.read(off),
            (9, off) => self.syscon.read(off),
            (10, off) => self.virtio_9p.read(off),
            _ => {
                log::trace!("Bus: unmapped read32 at {:#010x}", addr);
                0
            }
        }
    }

    pub fn read64(&mut self, addr: u64) -> u64 {
        match self.route(addr) {
            (0, off) => self.ram.read64(off),
            (3, off) => self.clint.read(off),
            _ => {
                let lo = self.read32(addr) as u64;
                let hi = self.read32(addr + 4) as u64;
                lo | (hi << 32)
            }
        }
    }

    pub fn write8(&mut self, addr: u64, val: u8) {
        match self.route(addr) {
            (0, off) => self.ram.write8(off, val),
            (1, off) => self.uart.write(off, val as u64),
            (2, off) => self.virtio_blk.write(off, val as u64),
            (3, off) => self.clint.write(off, val as u64),
            (4, off) => self.plic.write(off, val as u64),
            (5, off) => self.virtio_console.write(off, val as u64),
            (6, off) => self.virtio_rng.write(off, val as u64),
            (7, off) => self.virtio_net.write(off, val as u64),
            (8, off) => self.rtc.write(off, val as u64),
            (9, off) => self.syscon.write(off, val as u64),
            (10, off) => self.virtio_9p.write(off, val as u64),
            _ => {
                log::trace!("Bus: unmapped write8 at {:#010x} val={:#04x}", addr, val);
            }
        }
    }

    pub fn write16(&mut self, addr: u64, val: u16) {
        match self.route(addr) {
            (0, off) => {
                self.ram.write8(off, val as u8);
                self.ram.write8(off + 1, (val >> 8) as u8);
            }
            _ => {
                self.write8(addr, val as u8);
                self.write8(addr + 1, (val >> 8) as u8);
            }
        }
    }

    pub fn write32(&mut self, addr: u64, val: u32) {
        match self.route(addr) {
            (0, off) => self.ram.write32(off, val),
            (1, off) => self.uart.write(off, val as u64),
            (2, off) => self.virtio_blk.write(off, val as u64),
            (3, off) => self.clint.write(off, val as u64),
            (4, off) => self.plic.write(off, val as u64),
            (5, off) => self.virtio_console.write(off, val as u64),
            (6, off) => self.virtio_rng.write(off, val as u64),
            (7, off) => self.virtio_net.write(off, val as u64),
            (8, off) => self.rtc.write(off, val as u64),
            (9, off) => self.syscon.write(off, val as u64),
            (10, off) => self.virtio_9p.write(off, val as u64),
            _ => {
                log::trace!("Bus: unmapped write32 at {:#010x} val={:#010x}", addr, val);
            }
        }
    }

    pub fn write64(&mut self, addr: u64, val: u64) {
        match self.route(addr) {
            (0, off) => self.ram.write64(off, val),
            (3, off) => self.clint.write(off, val),
            _ => {
                self.write32(addr, val as u32);
                self.write32(addr + 4, (val >> 32) as u32);
            }
        }
    }

    /// Load binary data into RAM at given offset from DRAM_BASE
    pub fn load_binary(&mut self, data: &[u8], offset: u64) {
        self.ram.load(data, offset);
    }

    /// Get raw RAM slice for VirtIO DMA access
    #[allow(dead_code)]
    pub fn ram_slice_mut(&mut self) -> &mut [u8] {
        self.ram.as_mut_slice()
    }
}
