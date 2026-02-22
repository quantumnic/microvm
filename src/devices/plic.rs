use crate::devices::clint::MAX_HARTS;

/// Maximum PLIC contexts: 2 per hart (M-mode + S-mode)
const MAX_CONTEXTS: usize = MAX_HARTS * 2;

/// Maximum interrupt sources (PLIC spec allows up to 1024, source 0 is reserved)
const MAX_SOURCES: usize = 1024;

/// Number of u32 words needed for MAX_SOURCES bits
const PENDING_WORDS: usize = MAX_SOURCES / 32;

/// Platform-Level Interrupt Controller
/// Full PLIC spec implementation supporting up to 1024 interrupt sources
/// and up to MAX_HARTS harts (2 contexts each: M-mode + S-mode)
pub struct Plic {
    /// Priority for each source (0 = disabled, max 7)
    priority: Vec<u32>,
    /// Pending bits (1 bit per source, stored as u32 words)
    pending: [u32; PENDING_WORDS],
    /// Enable bits per context (1 bit per source per context)
    enable: Vec<[u32; PENDING_WORDS]>,
    /// Priority threshold per context
    threshold: [u32; MAX_CONTEXTS],
    /// Claimed interrupt per context (0 = no claim in progress)
    claimed: [u32; MAX_CONTEXTS],
    /// Number of harts
    num_harts: usize,
    /// Number of interrupt sources actually wired (for ndev reporting)
    #[allow(dead_code)]
    num_sources: usize,
    /// Gateway state: tracks edge-triggered sources that have fired
    /// Once pending, a source stays pending until claimed (level-triggered emulation)
    gateway: [u32; PENDING_WORDS],
}

impl Default for Plic {
    fn default() -> Self {
        Self::new()
    }
}

impl Plic {
    pub fn new() -> Self {
        Self {
            priority: vec![0; MAX_SOURCES],
            pending: [0; PENDING_WORDS],
            enable: vec![[0; PENDING_WORDS]; MAX_CONTEXTS],
            threshold: [0; MAX_CONTEXTS],
            claimed: [0; MAX_CONTEXTS],
            num_harts: 1,
            num_sources: 96,
            gateway: [0; PENDING_WORDS],
        }
    }

    /// Create PLIC for multiple harts
    pub fn with_harts(num_harts: usize) -> Self {
        let mut plic = Self::new();
        plic.num_harts = num_harts.min(MAX_HARTS);
        plic
    }

    /// Get number of supported interrupt sources
    #[allow(dead_code)]
    pub fn num_sources(&self) -> usize {
        self.num_sources
    }

    /// Signal an external interrupt (edge-triggered: sets pending bit)
    pub fn set_pending(&mut self, irq: u32) {
        if irq > 0 && (irq as usize) < MAX_SOURCES {
            let word = irq as usize / 32;
            let bit = irq as usize % 32;
            self.pending[word] |= 1 << bit;
        }
    }

    /// Clear a pending interrupt (used when device de-asserts)
    #[allow(dead_code)]
    pub fn clear_pending(&mut self, irq: u32) {
        if irq > 0 && (irq as usize) < MAX_SOURCES {
            let word = irq as usize / 32;
            let bit = irq as usize % 32;
            self.pending[word] &= !(1 << bit);
        }
    }

    /// Check if there's a pending interrupt for given context
    pub fn has_interrupt(&self, context: usize) -> bool {
        if context >= self.num_harts * 2 {
            return false;
        }
        for word in 0..PENDING_WORDS {
            let enabled_pending = self.pending[word] & self.enable[context][word];
            if enabled_pending == 0 {
                continue;
            }
            for bit in 0..32 {
                let irq = word * 32 + bit;
                if irq == 0 {
                    continue;
                }
                if irq >= MAX_SOURCES {
                    break;
                }
                if enabled_pending & (1 << bit) != 0 && self.priority[irq] > self.threshold[context]
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn read(&mut self, offset: u64) -> u64 {
        match offset {
            // Priority registers: 0x000000 - 0x000FFF (1024 sources × 4 bytes)
            0x000000..=0x000FFF => {
                let src = (offset / 4) as usize;
                if src < MAX_SOURCES {
                    self.priority[src] as u64
                } else {
                    0
                }
            }
            // Pending bits: 0x001000 - 0x00107F (1024 bits = 32 words)
            0x001000..=0x00107F => {
                let word = ((offset - 0x001000) / 4) as usize;
                if word < PENDING_WORDS {
                    self.pending[word] as u64
                } else {
                    0
                }
            }
            // Enable bits: 0x002000 + context * 0x80 (each context: 1024 bits = 128 bytes)
            0x002000..=0x1FFFFF => {
                let ctx_offset = offset - 0x002000;
                let context = (ctx_offset / 0x80) as usize;
                let word = ((ctx_offset % 0x80) / 4) as usize;
                if context < self.num_harts * 2 && word < PENDING_WORDS {
                    self.enable[context][word] as u64
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
        let mut best_irq = 0u32;
        let mut best_prio = 0u32;

        for word in 0..PENDING_WORDS {
            let enabled_pending = self.pending[word] & self.enable[context][word];
            if enabled_pending == 0 {
                continue;
            }
            for bit in 0..32 {
                let irq = word * 32 + bit;
                if irq == 0 || irq >= MAX_SOURCES {
                    continue;
                }
                if enabled_pending & (1 << bit) != 0
                    && self.priority[irq] > best_prio
                    && self.priority[irq] > self.threshold[context]
                {
                    best_irq = irq as u32;
                    best_prio = self.priority[irq];
                }
            }
        }

        if best_irq > 0 {
            let word = best_irq as usize / 32;
            let bit = best_irq as usize % 32;
            self.pending[word] &= !(1u32 << bit);
            self.claimed[context] = best_irq;
            log::trace!("PLIC: context {} claimed IRQ {}", context, best_irq);
        }
        best_irq
    }

    /// Complete an interrupt (write the IRQ id back to claim/complete register)
    fn complete(&mut self, context: usize, irq: u32) {
        if irq > 0 && (irq as usize) < MAX_SOURCES && self.claimed[context] == irq {
            self.claimed[context] = 0;
            // Re-enable the gateway for this source (allows new interrupts)
            let word = irq as usize / 32;
            let bit = irq as usize % 32;
            self.gateway[word] &= !(1u32 << bit);
            log::trace!("PLIC: context {} completed IRQ {}", context, irq);
        }
    }

    /// Save PLIC state for snapshot (saves first 2 contexts for backward compat)
    pub fn save_state(&self) -> Vec<u8> {
        // Backward-compatible format: 64 priorities + pending(u64) + 2 enables(u64) + 2 thresholds + 2 claimed
        let mut out = Vec::with_capacity(64 * 4 + 8 + 16 + 8 + 8);
        for i in 0..64 {
            out.extend_from_slice(&self.priority[i].to_le_bytes());
        }
        // Pack first 64 pending bits into a u64
        let pending_lo = self.pending[0] as u64 | ((self.pending[1] as u64) << 32);
        out.extend_from_slice(&pending_lo.to_le_bytes());
        // Pack first 64 enable bits per context
        let enable0 = self.enable[0][0] as u64 | ((self.enable[0][1] as u64) << 32);
        let enable1 = self.enable[1][0] as u64 | ((self.enable[1][1] as u64) << 32);
        out.extend_from_slice(&enable0.to_le_bytes());
        out.extend_from_slice(&enable1.to_le_bytes());
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
        let pending = read_u64(data, &mut pos)?;
        self.pending[0] = pending as u32;
        self.pending[1] = (pending >> 32) as u32;
        let enable0 = read_u64(data, &mut pos)?;
        self.enable[0][0] = enable0 as u32;
        self.enable[0][1] = (enable0 >> 32) as u32;
        let enable1 = read_u64(data, &mut pos)?;
        self.enable[1][0] = enable1 as u32;
        self.enable[1][1] = (enable1 >> 32) as u32;
        self.threshold[0] = read_u32(data, &mut pos)?;
        self.threshold[1] = read_u32(data, &mut pos)?;
        self.claimed[0] = read_u32(data, &mut pos)?;
        self.claimed[1] = read_u32(data, &mut pos)?;
        Ok(())
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            // Priority registers: 0x000000 - 0x000FFF
            0x000000..=0x000FFF => {
                let src = (offset / 4) as usize;
                if src < MAX_SOURCES {
                    // Priority is typically 0-7 (3 bits) per PLIC spec
                    self.priority[src] = (val as u32) & 0x7;
                }
            }
            // Pending bits are read-only (set by hardware, cleared by claim)
            0x001000..=0x00107F => {
                // Some implementations allow writing pending bits for testing
                // Linux doesn't write here, but allow it for compatibility
                let word = ((offset - 0x001000) / 4) as usize;
                if word < PENDING_WORDS {
                    self.pending[word] = val as u32;
                }
            }
            // Enable bits: 0x002000 + context * 0x80
            0x002000..=0x1FFFFF => {
                let ctx_offset = offset - 0x002000;
                let context = (ctx_offset / 0x80) as usize;
                let word = ((ctx_offset % 0x80) / 4) as usize;
                if context < self.num_harts * 2 && word < PENDING_WORDS {
                    self.enable[context][word] = val as u32;
                }
            }
            // Threshold & claim/complete: 0x200000 + context * 0x1000
            0x200000..=0x3FFFFF => {
                let ctx_offset = offset - 0x200000;
                let context = (ctx_offset / 0x1000) as usize;
                let reg_off = ctx_offset % 0x1000;
                if context < self.num_harts * 2 {
                    match reg_off {
                        0 => self.threshold[context] = (val as u32) & 0x7,
                        4 => self.complete(context, val as u32),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
}
