pub mod ram;
pub mod rom;

use crate::devices::{clint::Clint, plic::Plic, uart::Uart, virtio_blk::VirtioBlk};

// Memory map
pub const UART_BASE: u64 = 0x1000_0000;
pub const UART_SIZE: u64 = 0x100;
pub const VIRTIO0_BASE: u64 = 0x1000_1000;
pub const VIRTIO0_SIZE: u64 = 0x1000;
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
}

impl Bus {
    pub fn new(ram_size: u64) -> Self {
        Self {
            ram: ram::Ram::new(ram_size),
            uart: Uart::new(),
            clint: Clint::new(),
            plic: Plic::new(),
            virtio_blk: VirtioBlk::new(),
        }
    }

    /// Route a physical address to the correct MMIO device or RAM.
    /// Returns (device_id, offset) where device_id:
    ///   0=RAM, 1=UART, 2=VirtIO, 3=CLINT, 4=PLIC, 0xFF=unmapped
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
            _ => 0,
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
            _ => 0,
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
            _ => {}
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
            _ => {}
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
