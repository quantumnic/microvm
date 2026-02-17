/// Platform-Level Interrupt Controller
/// Simplified implementation supporting up to 64 interrupt sources
pub struct Plic {
    /// Priority for each source (0 = disabled)
    priority: [u32; 64],
    /// Pending bits
    pending: u64,
    /// Enable bits (context 0 = M-mode, context 1 = S-mode)
    enable: [u64; 2],
    /// Priority threshold per context
    threshold: [u32; 2],
    /// Claimed interrupt per context
    claimed: [u32; 2],
}

impl Plic {
    pub fn new() -> Self {
        Self {
            priority: [0; 64],
            pending: 0,
            enable: [0; 2],
            threshold: [0; 2],
            claimed: [0; 2],
        }
    }

    /// Signal an external interrupt
    pub fn set_pending(&mut self, irq: u32) {
        if irq > 0 && irq < 64 {
            self.pending |= 1 << irq;
        }
    }

    /// Check if there's a pending interrupt for given context
    pub fn has_interrupt(&self, context: usize) -> bool {
        if context >= 2 { return false; }
        let enabled_pending = self.pending & self.enable[context];
        for i in 1..64 {
            if enabled_pending & (1 << i) != 0 && self.priority[i] > self.threshold[context] {
                return true;
            }
        }
        false
    }

    pub fn read(&self, offset: u64) -> u64 {
        match offset {
            // Priority registers: 0x000000 - 0x000FFF
            0x000000..=0x0000FF => {
                let src = (offset / 4) as usize;
                if src < 64 { self.priority[src] as u64 } else { 0 }
            }
            // Pending bits
            0x001000 => self.pending & 0xFFFFFFFF,
            0x001004 => self.pending >> 32,
            // Enable bits context 0 (M-mode hart 0)
            0x002000 => self.enable[0] & 0xFFFFFFFF,
            0x002004 => self.enable[0] >> 32,
            // Enable bits context 1 (S-mode hart 0)
            0x002080 => self.enable[1] & 0xFFFFFFFF,
            0x002084 => self.enable[1] >> 32,
            // Threshold & claim context 0
            0x200000 => self.threshold[0] as u64,
            0x200004 => self.claim(0) as u64,
            // Threshold & claim context 1
            0x201000 => self.threshold[1] as u64,
            0x201004 => self.claim(1) as u64,
            _ => 0,
        }
    }

    fn claim(&self, context: usize) -> u32 {
        let enabled_pending = self.pending & self.enable[context];
        let mut best_irq = 0u32;
        let mut best_prio = 0u32;
        for i in 1..64usize {
            if enabled_pending & (1 << i) != 0 && self.priority[i] > best_prio && self.priority[i] > self.threshold[context] {
                best_irq = i as u32;
                best_prio = self.priority[i];
            }
        }
        best_irq
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            0x000000..=0x0000FF => {
                let src = (offset / 4) as usize;
                if src < 64 { self.priority[src] = val as u32; }
            }
            0x002000 => self.enable[0] = (self.enable[0] & !0xFFFFFFFF) | (val & 0xFFFFFFFF),
            0x002004 => self.enable[0] = (self.enable[0] & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32),
            0x002080 => self.enable[1] = (self.enable[1] & !0xFFFFFFFF) | (val & 0xFFFFFFFF),
            0x002084 => self.enable[1] = (self.enable[1] & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32),
            0x200000 => self.threshold[0] = val as u32,
            0x200004 => {
                // Claim/complete context 0
                let irq = val as u32;
                if irq > 0 && irq < 64 {
                    self.pending &= !(1 << irq);
                }
            }
            0x201000 => self.threshold[1] = val as u32,
            0x201004 => {
                let irq = val as u32;
                if irq > 0 && irq < 64 {
                    self.pending &= !(1 << irq);
                }
            }
            _ => {}
        }
    }
}
