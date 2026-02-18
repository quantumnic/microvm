use std::time::Instant;

/// Core-Local Interruptor — timer and software interrupts
pub struct Clint {
    /// Machine software interrupt pending
    pub msip: u32,
    /// Timer compare value
    pub mtimecmp: u64,
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
            msip: 0,
            mtimecmp: u64::MAX,
            start: Instant::now(),
            frequency: 10_000_000,
        }
    }

    /// Current mtime value
    pub fn mtime(&self) -> u64 {
        let elapsed = self.start.elapsed();
        (elapsed.as_nanos() as u64) * self.frequency / 1_000_000_000
    }

    /// Check if timer interrupt is pending
    pub fn timer_interrupt(&self) -> bool {
        self.mtime() >= self.mtimecmp
    }

    /// Check if software interrupt is pending
    pub fn software_interrupt(&self) -> bool {
        self.msip & 1 != 0
    }

    pub fn read(&self, offset: u64) -> u64 {
        match offset {
            0x0000 => self.msip as u64,
            0x4000 => self.mtimecmp,
            0x4004 => self.mtimecmp >> 32,
            0xBFF8 => self.mtime(),
            0xBFFC => self.mtime() >> 32,
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            0x0000 => self.msip = val as u32 & 1,
            0x4000 => self.mtimecmp = (self.mtimecmp & 0xFFFFFFFF_00000000) | (val & 0xFFFFFFFF),
            0x4004 => self.mtimecmp = (self.mtimecmp & 0xFFFFFFFF) | ((val & 0xFFFFFFFF) << 32),
            0xBFF8 => {} // mtime is read-only (hardware counter)
            _ => {}
        }
    }
}
