use std::collections::VecDeque;
use std::io::{self, Write};

/// 16550A UART emulation with full FIFO support
///
/// Register map (byte-addressed):
///   0: RBR/THR/DLL (read=RBR, write=THR; DLAB=1: DLL)
///   1: IER/DLM (DLAB=1: DLM)
///   2: IIR/FCR (read=IIR, write=FCR)
///   3: LCR
///   4: MCR
///   5: LSR (read-only)
///   6: MSR (read-only)
///   7: SCR
pub struct Uart {
    /// Receive FIFO (up to 16 bytes when FIFO enabled, 1 byte otherwise)
    rx_fifo: VecDeque<u8>,
    /// Transmit FIFO (up to 16 bytes when FIFO enabled)
    tx_fifo: VecDeque<u8>,
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
    /// FIFO Control Register (write-only, but we track state)
    fcr: u8,
    /// Scratch register
    scr: u8,
    /// THRE interrupt pending (cleared on IIR read when THRE is shown)
    thre_pending: bool,
    /// FIFO enabled (FCR bit 0)
    fifo_enabled: bool,
    /// RX FIFO trigger level (1, 4, 8, 14 bytes)
    rx_trigger: usize,
    /// Receiver line status error bits accumulated in FIFO mode
    rx_error: u8,
}

// LSR bits
const LSR_DR: u8 = 1 << 0; // Data Ready
const LSR_OE: u8 = 1 << 1; // Overrun Error
const LSR_THRE: u8 = 1 << 5; // Transmit Holding Register Empty
const LSR_TEMT: u8 = 1 << 6; // Transmitter Empty

// IER bits
const IER_RDA: u8 = 1 << 0; // Received Data Available
const IER_THRE: u8 = 1 << 1; // Transmitter Holding Register Empty
const IER_RLS: u8 = 1 << 2; // Receiver Line Status
const _IER_MSR: u8 = 1 << 3; // Modem Status

// MCR bits
const MCR_OUT2: u8 = 1 << 3; // OUT2 — master interrupt enable (active high)

// IIR identification values
const IIR_NONE: u8 = 0x01; // No interrupt pending
const IIR_RLS: u8 = 0x06; // Receiver Line Status (highest priority)
const IIR_RDA: u8 = 0x04; // Received Data Available
const IIR_CTI: u8 = 0x0C; // Character Timeout Indicator
const IIR_THRE: u8 = 0x02; // Transmitter Holding Register Empty

/// Maximum FIFO depth (16550A standard)
const FIFO_SIZE: usize = 16;

impl Default for Uart {
    fn default() -> Self {
        Self::new()
    }
}

impl Uart {
    pub fn new() -> Self {
        Self {
            rx_fifo: VecDeque::with_capacity(FIFO_SIZE),
            tx_fifo: VecDeque::with_capacity(FIFO_SIZE),
            lsr: LSR_THRE | LSR_TEMT,
            ier: 0,
            lcr: 0,
            mcr: 0,
            dll: 0,
            dlm: 0,
            fcr: 0,
            scr: 0,
            thre_pending: true,
            fifo_enabled: false,
            rx_trigger: 1,
            rx_error: 0,
        }
    }

    /// Feed a byte into the receive FIFO (from external source like stdin)
    pub fn push_byte(&mut self, b: u8) {
        let max = if self.fifo_enabled {
            FIFO_SIZE
        } else {
            FIFO_SIZE
        };
        if self.rx_fifo.len() >= max {
            // Overrun: FIFO full, set OE in LSR
            self.lsr |= LSR_OE;
            self.rx_error |= LSR_OE;
            log::trace!("UART: RX overrun (FIFO full, dropping byte {:#04x})", b);
        } else {
            self.rx_fifo.push_back(b);
        }
        self.lsr |= LSR_DR;
    }

    /// Check if UART has a pending interrupt.
    /// Returns true only if MCR.OUT2 is set (master interrupt enable).
    /// Linux's 8250 driver sets OUT2 to enable interrupts.
    pub fn has_interrupt(&self) -> bool {
        // OUT2 gates all UART interrupts (standard PC behavior, Linux expects this)
        if self.mcr & MCR_OUT2 == 0 {
            return false;
        }
        // Check interrupt conditions in priority order
        // RLS: receiver line status error
        if self.ier & IER_RLS != 0 && self.lsr & (LSR_OE) != 0 {
            return true;
        }
        // RDA: data available (trigger level reached or any data in non-FIFO mode)
        if self.ier & IER_RDA != 0 && self.rx_fifo.len() >= self.rx_trigger {
            return true;
        }
        // CTI: character timeout (data in FIFO but below trigger)
        if self.ier & IER_RDA != 0 && !self.rx_fifo.is_empty() {
            return true;
        }
        // THRE: transmitter empty
        if self.ier & IER_THRE != 0 && self.thre_pending {
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
                    // RBR — needs &mut self, return 0 in immutable path
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
            2 => self.read_iir(),
            3 => self.lcr as u64,
            4 => self.mcr as u64,
            5 => self.lsr as u64,
            6 => {
                // MSR — Modem Status Register
                // Report CTS and DSR asserted (Linux checks these during port setup)
                // DCD (bit 7) also asserted for carrier detect
                0xB0 // DCD=1, CTS=1, DSR=1
            }
            7 => self.scr as u64,
            _ => 0,
        }
    }

    /// Compute IIR value based on current interrupt state
    fn read_iir(&self) -> u64 {
        let fifo_bits: u8 = if self.fifo_enabled { 0xC0 } else { 0 };

        // Priority: RLS > RDA/CTI > THRE > Modem
        if self.ier & IER_RLS != 0 && self.lsr & LSR_OE != 0 {
            (fifo_bits | IIR_RLS) as u64
        } else if self.ier & IER_RDA != 0 && self.rx_fifo.len() >= self.rx_trigger {
            (fifo_bits | IIR_RDA) as u64
        } else if self.ier & IER_RDA != 0 && !self.rx_fifo.is_empty() {
            (fifo_bits | IIR_CTI) as u64 // Character timeout
        } else if self.thre_pending && self.ier & IER_THRE != 0 {
            (fifo_bits | IIR_THRE) as u64
        } else {
            (fifo_bits | IIR_NONE) as u64
        }
    }

    pub fn read_mut(&mut self, offset: u64) -> u64 {
        let dlab = (self.lcr >> 7) & 1;
        match offset {
            0 => {
                if dlab == 1 {
                    self.dll as u64
                } else if let Some(b) = self.rx_fifo.pop_front() {
                    if self.rx_fifo.is_empty() {
                        self.lsr &= !LSR_DR;
                    }
                    b as u64
                } else {
                    0
                }
            }
            2 => {
                // IIR read — reading IIR clears THRE pending (per 16550 spec)
                let val = self.read_iir();
                if val & 0x0F == IIR_THRE as u64 {
                    self.thre_pending = false;
                }
                val
            }
            5 => {
                // LSR read clears OE (overrun error) bit
                let val = self.lsr;
                self.lsr &= !LSR_OE;
                self.rx_error = 0;
                val as u64
            }
            _ => self.read(offset),
        }
    }

    /// Flush the TX FIFO to stdout
    fn flush_tx(&mut self) {
        if self.tx_fifo.is_empty() {
            return;
        }
        let mut stdout = io::stdout().lock();
        while let Some(b) = self.tx_fifo.pop_front() {
            let _ = stdout.write_all(&[b]);
        }
        let _ = stdout.flush();
        // TX is now empty
        self.lsr |= LSR_THRE | LSR_TEMT;
        self.thre_pending = true;
    }

    /// Save UART state for snapshot
    pub fn save_state(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // rx_fifo length + data
        let rx_len = self.rx_fifo.len() as u32;
        out.extend_from_slice(&rx_len.to_le_bytes());
        for &b in &self.rx_fifo {
            out.push(b);
        }
        // Registers
        out.push(self.lsr);
        out.push(self.ier);
        out.push(self.lcr);
        out.push(self.mcr);
        out.push(self.dll);
        out.push(self.dlm);
        out.push(self.fcr);
        out.push(self.scr);
        out.push(if self.thre_pending { 1 } else { 0 });
        out
    }

    /// Restore UART state from snapshot
    pub fn restore_state(&mut self, data: &[u8]) -> std::io::Result<()> {
        if data.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "uart",
            ));
        }
        let rx_len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let mut pos = 4;
        self.rx_fifo.clear();
        for _ in 0..rx_len {
            if pos >= data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "uart rx",
                ));
            }
            self.rx_fifo.push_back(data[pos]);
            pos += 1;
        }
        if pos + 9 > data.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "uart regs",
            ));
        }
        self.lsr = data[pos];
        self.ier = data[pos + 1];
        self.lcr = data[pos + 2];
        self.mcr = data[pos + 3];
        self.dll = data[pos + 4];
        self.dlm = data[pos + 5];
        self.fcr = data[pos + 6];
        self.scr = data[pos + 7];
        self.thre_pending = data[pos + 8] != 0;
        // Restore FIFO state from FCR
        self.fifo_enabled = self.fcr & 1 != 0;
        self.rx_trigger = match (self.fcr >> 6) & 0x3 {
            0 => 1,
            1 => 4,
            2 => 8,
            3 => 14,
            _ => 1,
        };
        Ok(())
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
                    if self.fifo_enabled {
                        self.tx_fifo.push_back(val);
                        if self.tx_fifo.len() >= FIFO_SIZE {
                            self.lsr &= !(LSR_THRE | LSR_TEMT);
                        }
                        // Flush immediately (we're an emulator, no real baud rate)
                        self.flush_tx();
                    } else {
                        // Non-FIFO mode: write directly
                        let mut stdout = io::stdout().lock();
                        let _ = stdout.write_all(&[val]);
                        let _ = stdout.flush();
                        self.thre_pending = true;
                    }
                }
            }
            1 => {
                if dlab == 1 {
                    self.dlm = val;
                } else {
                    let old_ier = self.ier;
                    self.ier = val & 0x0F; // Only bits 3:0 are writable
                                           // Enabling THRE interrupt when THR is empty triggers THRE
                    if val & IER_THRE != 0 && old_ier & IER_THRE == 0 && self.lsr & LSR_THRE != 0 {
                        self.thre_pending = true;
                    }
                }
            }
            2 => {
                // FCR — FIFO Control Register (write-only)
                self.fcr = val;
                self.fifo_enabled = val & 1 != 0;

                // Bit 1: clear RX FIFO
                if val & 0x02 != 0 {
                    self.rx_fifo.clear();
                    self.lsr &= !LSR_DR;
                }
                // Bit 2: clear TX FIFO
                if val & 0x04 != 0 {
                    self.tx_fifo.clear();
                    self.lsr |= LSR_THRE | LSR_TEMT;
                    self.thre_pending = true;
                }
                // Bits 7:6: RX trigger level
                self.rx_trigger = match (val >> 6) & 0x3 {
                    0 => 1,
                    1 => 4,
                    2 => 8,
                    3 => 14,
                    _ => 1,
                };
                log::trace!(
                    "UART: FCR={:#04x} fifo={} rx_trigger={}",
                    val,
                    self.fifo_enabled,
                    self.rx_trigger
                );
            }
            3 => self.lcr = val,
            4 => {
                self.mcr = val;
                log::trace!("UART: MCR={:#04x} OUT2={}", val, (val >> 3) & 1);
            }
            7 => self.scr = val,
            _ => {}
        }
    }
}
