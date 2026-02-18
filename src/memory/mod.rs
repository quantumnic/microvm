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

    pub fn read8(&mut self, addr: u64) -> u8 {
        if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
            return self.uart.read_mut(addr - UART_BASE) as u8;
        }
        if (VIRTIO0_BASE..VIRTIO0_BASE + VIRTIO0_SIZE).contains(&addr) {
            return self.virtio_blk.read(addr - VIRTIO0_BASE) as u8;
        }
        if addr >= DRAM_BASE && addr < DRAM_BASE + self.ram.size() {
            return self.ram.read8(addr - DRAM_BASE);
        }
        if (CLINT_BASE..CLINT_BASE + CLINT_SIZE).contains(&addr) {
            return self.clint.read(addr - CLINT_BASE) as u8;
        }
        if (PLIC_BASE..PLIC_BASE + PLIC_SIZE).contains(&addr) {
            return self.plic.read(addr - PLIC_BASE) as u8;
        }
        0
    }

    pub fn read16(&mut self, addr: u64) -> u16 {
        let lo = self.read8(addr) as u16;
        let hi = self.read8(addr + 1) as u16;
        lo | (hi << 8)
    }

    pub fn read32(&mut self, addr: u64) -> u32 {
        if (VIRTIO0_BASE..VIRTIO0_BASE + VIRTIO0_SIZE).contains(&addr) {
            return self.virtio_blk.read(addr - VIRTIO0_BASE) as u32;
        }
        if addr >= DRAM_BASE && addr < DRAM_BASE + self.ram.size() {
            return self.ram.read32(addr - DRAM_BASE);
        }
        if (CLINT_BASE..CLINT_BASE + CLINT_SIZE).contains(&addr) {
            return self.clint.read(addr - CLINT_BASE) as u32;
        }
        if (PLIC_BASE..PLIC_BASE + PLIC_SIZE).contains(&addr) {
            return self.plic.read(addr - PLIC_BASE) as u32;
        }
        let lo = self.read16(addr) as u32;
        let hi = self.read16(addr + 2) as u32;
        lo | (hi << 16)
    }

    pub fn read64(&mut self, addr: u64) -> u64 {
        if addr >= DRAM_BASE && addr < DRAM_BASE + self.ram.size() {
            return self.ram.read64(addr - DRAM_BASE);
        }
        if (CLINT_BASE..CLINT_BASE + CLINT_SIZE).contains(&addr) {
            return self.clint.read(addr - CLINT_BASE);
        }
        let lo = self.read32(addr) as u64;
        let hi = self.read32(addr + 4) as u64;
        lo | (hi << 32)
    }

    pub fn write8(&mut self, addr: u64, val: u8) {
        if (UART_BASE..UART_BASE + UART_SIZE).contains(&addr) {
            self.uart.write(addr - UART_BASE, val as u64);
            return;
        }
        if (VIRTIO0_BASE..VIRTIO0_BASE + VIRTIO0_SIZE).contains(&addr) {
            self.virtio_blk.write(addr - VIRTIO0_BASE, val as u64);
            return;
        }
        if addr >= DRAM_BASE && addr < DRAM_BASE + self.ram.size() {
            self.ram.write8(addr - DRAM_BASE, val);
            return;
        }
        if (CLINT_BASE..CLINT_BASE + CLINT_SIZE).contains(&addr) {
            self.clint.write(addr - CLINT_BASE, val as u64);
            return;
        }
        if (PLIC_BASE..PLIC_BASE + PLIC_SIZE).contains(&addr) {
            self.plic.write(addr - PLIC_BASE, val as u64);
        }
    }

    pub fn write16(&mut self, addr: u64, val: u16) {
        self.write8(addr, val as u8);
        self.write8(addr + 1, (val >> 8) as u8);
    }

    pub fn write32(&mut self, addr: u64, val: u32) {
        if (VIRTIO0_BASE..VIRTIO0_BASE + VIRTIO0_SIZE).contains(&addr) {
            self.virtio_blk.write(addr - VIRTIO0_BASE, val as u64);
            return;
        }
        if addr >= DRAM_BASE && addr < DRAM_BASE + self.ram.size() {
            self.ram.write32(addr - DRAM_BASE, val);
            return;
        }
        if (CLINT_BASE..CLINT_BASE + CLINT_SIZE).contains(&addr) {
            self.clint.write(addr - CLINT_BASE, val as u64);
            return;
        }
        if (PLIC_BASE..PLIC_BASE + PLIC_SIZE).contains(&addr) {
            self.plic.write(addr - PLIC_BASE, val as u64);
            return;
        }
        self.write16(addr, val as u16);
        self.write16(addr + 2, (val >> 16) as u16);
    }

    pub fn write64(&mut self, addr: u64, val: u64) {
        if addr >= DRAM_BASE && addr < DRAM_BASE + self.ram.size() {
            self.ram.write64(addr - DRAM_BASE, val);
            return;
        }
        if (CLINT_BASE..CLINT_BASE + CLINT_SIZE).contains(&addr) {
            self.clint.write(addr - CLINT_BASE, val);
            return;
        }
        self.write32(addr, val as u32);
        self.write32(addr + 4, (val >> 32) as u32);
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
