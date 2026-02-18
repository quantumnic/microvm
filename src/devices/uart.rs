use std::collections::VecDeque;
use std::io::{self, Write};

/// 16550 UART emulation
pub struct Uart {
    /// Receive buffer
    rx_buf: VecDeque<u8>,
    /// Line Status Register
    lsr: u8,
    /// Interrupt Enable Register
    ier: u8,
    /// Line Control Register
    lcr: u8,
    /// Modem Control Register
    mcr: u8,
    /// Divisor Latch (low/high)
    dll: u8,
    dlm: u8,
    /// FIFO Control Register
    fcr: u8,
    /// Scratch register
    scr: u8,
}

// LSR bits
const LSR_DR: u8 = 1 << 0; // Data Ready
const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty
const LSR_TEMT: u8 = 1 << 6; // Transmitter Empty

// IER bits
const IER_RDA: u8 = 1 << 0; // Received Data Available
const IER_THRE: u8 = 1 << 1; // Transmitter Holding Register Empty

impl Default for Uart {
    fn default() -> Self {
        Self::new()
    }
}

impl Uart {
    pub fn new() -> Self {
        Self {
            rx_buf: VecDeque::new(),
            lsr: LSR_THRE | LSR_TEMT,
            ier: 0,
            lcr: 0,
            mcr: 0,
            dll: 0,
            dlm: 0,
            fcr: 0,
            scr: 0,
        }
    }


    /// Feed a byte into the receive buffer (from external source)
    pub fn push_byte(&mut self, b: u8) {
        self.rx_buf.push_back(b);
        self.lsr |= LSR_DR;
    }

    /// Check if UART has a pending interrupt
    pub fn has_interrupt(&self) -> bool {
        // RDA interrupt: data available and IER_RDA enabled
        if self.ier & IER_RDA != 0 && self.lsr & LSR_DR != 0 {
            return true;
        }
        // THRE interrupt: transmitter empty and IER_THRE enabled
        if self.ier & IER_THRE != 0 && self.lsr & LSR_THRE != 0 {
            return true;
        }
        false
    }

    pub fn read(&self, offset: u64) -> u64 {
        let dlab = (self.lcr >> 7) & 1;
        match offset {
            0 => {
                if dlab == 1 {
                    self.dll as u64
                } else {
                    // RBR — Receive Buffer Register
                    // We need &mut self for this, so we use interior mutability pattern
                    // For simplicity, return 0; actual read happens in read_mut
                    0
                }
            }
            1 => {
                if dlab == 1 {
                    self.dlm as u64
                } else {
                    self.ier as u64
                }
            }
            2 => {
                // IIR — Interrupt Identification Register
                // Priority: RLS > RDA > THRE > Modem
                if self.lsr & LSR_DR != 0 && self.ier & IER_RDA != 0 {
                    0x04 // RDA interrupt pending (priority 2)
                } else if self.lsr & LSR_THRE != 0 && self.ier & IER_THRE != 0 {
                    0x02 // THRE interrupt pending (priority 3)
                } else {
                    0x01 // No interrupt pending
                }
            }
            3 => self.lcr as u64,
            4 => self.mcr as u64,
            5 => self.lsr as u64,
            6 => 0, // MSR
            7 => self.scr as u64,
            _ => 0,
        }
    }

    pub fn read_mut(&mut self, offset: u64) -> u64 {
        let dlab = (self.lcr >> 7) & 1;
        match offset {
            0 => {
                if dlab == 1 {
                    self.dll as u64
                } else if let Some(b) = self.rx_buf.pop_front() {
                    if self.rx_buf.is_empty() {
                        self.lsr &= !LSR_DR;
                    }
                    b as u64
                } else {
                    0
                }
            }
            _ => self.read(offset),
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        let val = val as u8;
        let dlab = (self.lcr >> 7) & 1;
        match offset {
            0 => {
                if dlab == 1 {
                    self.dll = val;
                } else {
                    // THR — Transmit Holding Register
                    let mut stdout = io::stdout().lock();
                    let _ = stdout.write_all(&[val]);
                    let _ = stdout.flush();
                }
            }
            1 => {
                if dlab == 1 {
                    self.dlm = val;
                } else {
                    self.ier = val;
                }
            }
            2 => self.fcr = val,
            3 => self.lcr = val,
            4 => self.mcr = val,
            7 => self.scr = val,
            _ => {}
        }
    }
}
