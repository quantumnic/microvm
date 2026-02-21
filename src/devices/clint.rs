use std::time::Instant;

/// Maximum number of harts supported
pub const MAX_HARTS: usize = 8;

/// Core-Local Interruptor — per-hart timer and software interrupts
pub struct Clint {
    /// Per-hart machine software interrupt pending (MSIP)
    /// CLINT layout: msip[hart] at offset hart * 4
    pub msip: [u32; MAX_HARTS],
    /// Per-hart timer compare values
    /// CLINT layout: mtimecmp[hart] at offset 0x4000 + hart * 8
    pub mtimecmp: [u64; MAX_HARTS],
    /// Number of harts
    pub num_harts: usize,
    /// Base time
    start: Instant,
    /// Frequency (ticks per second) — 10 MHz
    frequency: u64,
}

impl Default for Clint {
    fn default() -> Self {
        Self::new()
    }
}

impl Clint {
    pub fn new() -> Self {
        Self {
            msip: [0; MAX_HARTS],
            mtimecmp: [u64::MAX; MAX_HARTS],
            num_harts: 1,
            start: Instant::now(),
            frequency: 10_000_000,
        }
    }

    /// Create CLINT for multiple harts
    pub fn with_harts(num_harts: usize) -> Self {
        let mut clint = Self::new();
        clint.num_harts = num_harts.min(MAX_HARTS);
        clint
    }

    /// Get mtimecmp value for hart 0 (snapshot compat)
    pub fn mtimecmp(&self) -> u64 {
        self.mtimecmp[0]
    }

    /// Get mtimecmp value for a specific hart
    #[allow(dead_code)]
    pub fn mtimecmp_hart(&self, hart: usize) -> u64 {
        if hart < MAX_HARTS {
            self.mtimecmp[hart]
        } else {
            u64::MAX
        }
    }

    /// Restore CLINT state from snapshot
    pub fn restore_state(&mut self, _mtime: u64, mtimecmp: u64, msip: bool) {
        self.mtimecmp[0] = mtimecmp;
        self.msip[0] = if msip { 1 } else { 0 };
    }

    /// Current mtime value
    pub fn mtime(&self) -> u64 {
        let elapsed = self.start.elapsed();
        (elapsed.as_nanos() as u64) * self.frequency / 1_000_000_000
    }

    /// Check if timer interrupt is pending for a specific hart
    pub fn timer_interrupt_hart(&self, hart: usize) -> bool {
        if hart < MAX_HARTS {
            self.mtime() >= self.mtimecmp[hart]
        } else {
            false
        }
    }

    /// Check if timer interrupt is pending (hart 0, backward compat)
    #[allow(dead_code)]
    pub fn timer_interrupt(&self) -> bool {
        self.timer_interrupt_hart(0)
    }

    /// Check if software interrupt is pending for a specific hart
    pub fn software_interrupt_hart(&self, hart: usize) -> bool {
        if hart < MAX_HARTS {
            self.msip[hart] & 1 != 0
        } else {
            false
        }
    }

    /// Check if software interrupt is pending (hart 0, backward compat)
    pub fn software_interrupt(&self) -> bool {
        self.software_interrupt_hart(0)
    }

    pub fn read(&self, offset: u64) -> u64 {
        // MSIP: offset 0x0000 + hart*4
        if offset < 0x4000 {
            let hart = (offset / 4) as usize;
            return if hart < self.num_harts {
                self.msip[hart] as u64
            } else {
                0
            };
        }
        // MTIMECMP: offset 0x4000 + hart*8
        if (0x4000..0xBFF8).contains(&offset) {
            let byte_off = offset - 0x4000;
            let hart = (byte_off / 8) as usize;
            let lo = (byte_off % 8) < 4;
            return if hart < self.num_harts {
                if lo {
                    self.mtimecmp[hart] & 0xFFFF_FFFF
                } else {
                    self.mtimecmp[hart] >> 32
                }
            } else {
                0
            };
        }
        // MTIME: offset 0xBFF8
        match offset {
            0xBFF8 => self.mtime(),
            0xBFFC => self.mtime() >> 32,
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        // MSIP: offset 0x0000 + hart*4
        if offset < 0x4000 {
            let hart = (offset / 4) as usize;
            if hart < self.num_harts {
                self.msip[hart] = val as u32 & 1;
            }
            return;
        }
        // MTIMECMP: offset 0x4000 + hart*8
        if (0x4000..0xBFF8).contains(&offset) {
            let byte_off = offset - 0x4000;
            let hart = (byte_off / 8) as usize;
            let lo = (byte_off % 8) < 4;
            if hart < self.num_harts {
                if lo {
                    self.mtimecmp[hart] =
                        (self.mtimecmp[hart] & 0xFFFFFFFF_00000000) | (val & 0xFFFFFFFF);
                } else {
                    self.mtimecmp[hart] =
                        (self.mtimecmp[hart] & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32);
                }
            }
        }
        // MTIME is read-only
    }
}
