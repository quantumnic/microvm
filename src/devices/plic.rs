use crate::devices::clint::MAX_HARTS;

/// Maximum PLIC contexts: 2 per hart (M-mode + S-mode)
const MAX_CONTEXTS: usize = MAX_HARTS * 2;

/// Platform-Level Interrupt Controller
/// Simplified implementation supporting up to 64 interrupt sources
/// and up to MAX_HARTS harts (2 contexts each: M-mode + S-mode)
pub struct Plic {
    /// Priority for each source (0 = disabled)
    priority: [u32; 64],
    /// Pending bits
    pending: u64,
    /// Enable bits per context (context 2*hart=M, 2*hart+1=S)
    enable: [u64; MAX_CONTEXTS],
    /// Priority threshold per context
    threshold: [u32; MAX_CONTEXTS],
    /// Claimed interrupt per context
    claimed: [u32; MAX_CONTEXTS],
    /// Number of harts
    num_harts: usize,
}

impl Default for Plic {
    fn default() -> Self {
        Self::new()
    }
}

impl Plic {
    pub fn new() -> Self {
        Self {
            priority: [0; 64],
            pending: 0,
            enable: [0; MAX_CONTEXTS],
            threshold: [0; MAX_CONTEXTS],
            claimed: [0; MAX_CONTEXTS],
            num_harts: 1,
        }
    }

    /// Create PLIC for multiple harts
    pub fn with_harts(num_harts: usize) -> Self {
        let mut plic = Self::new();
        plic.num_harts = num_harts.min(MAX_HARTS);
        plic
    }

    /// Signal an external interrupt
    pub fn set_pending(&mut self, irq: u32) {
        if irq > 0 && irq < 64 {
            self.pending |= 1 << irq;
        }
    }

    /// Check if there's a pending interrupt for given context
    pub fn has_interrupt(&self, context: usize) -> bool {
        if context >= self.num_harts * 2 {
            return false;
        }
        let enabled_pending = self.pending & self.enable[context];
        for i in 1..64 {
            if enabled_pending & (1 << i) != 0 && self.priority[i] > self.threshold[context] {
                return true;
            }
        }
        false
    }

    pub fn read(&mut self, offset: u64) -> u64 {
        match offset {
            // Priority registers: 0x000000 - 0x0000FF
            0x000000..=0x0000FF => {
                let src = (offset / 4) as usize;
                if src < 64 {
                    self.priority[src] as u64
                } else {
                    0
                }
            }
            // Pending bits: 0x001000
            0x001000 => self.pending & 0xFFFFFFFF,
            0x001004 => self.pending >> 32,
            // Enable bits: 0x002000 + context * 0x80
            0x002000..=0x002FFF => {
                let ctx_offset = offset - 0x002000;
                let context = (ctx_offset / 0x80) as usize;
                let reg_off = ctx_offset % 0x80;
                if context < self.num_harts * 2 {
                    match reg_off {
                        0 => self.enable[context] & 0xFFFFFFFF,
                        4 => self.enable[context] >> 32,
                        _ => 0,
                    }
                } else {
                    0
                }
            }
            // Threshold & claim: 0x200000 + context * 0x1000
            0x200000..=0x3FFFFF => {
                let ctx_offset = offset - 0x200000;
                let context = (ctx_offset / 0x1000) as usize;
                let reg_off = ctx_offset % 0x1000;
                if context < self.num_harts * 2 {
                    match reg_off {
                        0 => self.threshold[context] as u64,
                        4 => self.claim(context) as u64,
                        _ => 0,
                    }
                } else {
                    0
                }
            }
            _ => 0,
        }
    }

    /// Claim the highest-priority pending interrupt for a context.
    /// Per PLIC spec: claim clears the pending bit, the interrupt is now "in service".
    /// Complete (write to same register) signals that the handler is done.
    fn claim(&mut self, context: usize) -> u32 {
        let enabled_pending = self.pending & self.enable[context];
        let mut best_irq = 0u32;
        let mut best_prio = 0u32;
        for i in 1..64usize {
            if enabled_pending & (1 << i) != 0
                && self.priority[i] > best_prio
                && self.priority[i] > self.threshold[context]
            {
                best_irq = i as u32;
                best_prio = self.priority[i];
            }
        }
        if best_irq > 0 {
            self.pending &= !(1u64 << best_irq);
            self.claimed[context] = best_irq;
        }
        best_irq
    }

    /// Complete an interrupt (write the IRQ id back to claim/complete register)
    fn complete(&mut self, context: usize, irq: u32) {
        if irq > 0 && irq < 64 && self.claimed[context] == irq {
            self.claimed[context] = 0;
        }
    }

    /// Save PLIC state for snapshot (saves first 2 contexts for backward compat)
    pub fn save_state(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 * 4 + 8 + 16 + 8 + 8);
        for &p in &self.priority {
            out.extend_from_slice(&p.to_le_bytes());
        }
        out.extend_from_slice(&self.pending.to_le_bytes());
        out.extend_from_slice(&self.enable[0].to_le_bytes());
        out.extend_from_slice(&self.enable[1].to_le_bytes());
        out.extend_from_slice(&self.threshold[0].to_le_bytes());
        out.extend_from_slice(&self.threshold[1].to_le_bytes());
        out.extend_from_slice(&self.claimed[0].to_le_bytes());
        out.extend_from_slice(&self.claimed[1].to_le_bytes());
        out
    }

    /// Restore PLIC state from snapshot
    pub fn restore_state(&mut self, data: &[u8]) -> std::io::Result<()> {
        let mut pos = 0;
        let read_u32 = |data: &[u8], pos: &mut usize| -> std::io::Result<u32> {
            if *pos + 4 > data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "plic",
                ));
            }
            let v = u32::from_le_bytes(data[*pos..*pos + 4].try_into().unwrap());
            *pos += 4;
            Ok(v)
        };
        let read_u64 = |data: &[u8], pos: &mut usize| -> std::io::Result<u64> {
            if *pos + 8 > data.len() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "plic",
                ));
            }
            let v = u64::from_le_bytes(data[*pos..*pos + 8].try_into().unwrap());
            *pos += 8;
            Ok(v)
        };
        for i in 0..64 {
            self.priority[i] = read_u32(data, &mut pos)?;
        }
        self.pending = read_u64(data, &mut pos)?;
        self.enable[0] = read_u64(data, &mut pos)?;
        self.enable[1] = read_u64(data, &mut pos)?;
        self.threshold[0] = read_u32(data, &mut pos)?;
        self.threshold[1] = read_u32(data, &mut pos)?;
        self.claimed[0] = read_u32(data, &mut pos)?;
        self.claimed[1] = read_u32(data, &mut pos)?;
        Ok(())
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            // Priority registers
            0x000000..=0x0000FF => {
                let src = (offset / 4) as usize;
                if src < 64 {
                    self.priority[src] = val as u32;
                }
            }
            // Enable bits: 0x002000 + context * 0x80
            0x002000..=0x002FFF => {
                let ctx_offset = offset - 0x002000;
                let context = (ctx_offset / 0x80) as usize;
                let reg_off = ctx_offset % 0x80;
                if context < self.num_harts * 2 {
                    match reg_off {
                        0 => {
                            self.enable[context] =
                                (self.enable[context] & !0xFFFFFFFF) | (val & 0xFFFFFFFF)
                        }
                        4 => {
                            self.enable[context] =
                                (self.enable[context] & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32)
                        }
                        _ => {}
                    }
                }
            }
            // Threshold & claim/complete: 0x200000 + context * 0x1000
            0x200000..=0x3FFFFF => {
                let ctx_offset = offset - 0x200000;
                let context = (ctx_offset / 0x1000) as usize;
                let reg_off = ctx_offset % 0x1000;
                if context < self.num_harts * 2 {
                    match reg_off {
                        0 => self.threshold[context] = val as u32,
                        4 => self.complete(context, val as u32),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}
