/// Goldfish RTC (Real-Time Clock) device
///
/// Provides wall-clock time to the guest via a simple MMIO interface.
/// Linux has built-in support for "google,goldfish-rtc".
///
/// Register map (all 32-bit reads):
///   0x00  TIME_LOW   — low 32 bits of nanoseconds since epoch
///   0x04  TIME_HIGH  — high 32 bits of nanoseconds since epoch
///   0x08  ALARM_LOW  — alarm low (write-only, not implemented)
///   0x0C  ALARM_HIGH — alarm high (write-only, not implemented)
///   0x10  IRQ_ENABLED — alarm IRQ enable (not implemented)
///   0x14  CLEAR_ALARM — clear alarm (not implemented)
///   0x18  ALARM_STATUS — alarm status (reads 0)
///   0x1C  CLEAR_INTERRUPT — clear interrupt (not implemented)
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Default)]
pub struct GoldfishRtc {
    /// Cached time in nanoseconds (updated on TIME_LOW read, latched for TIME_HIGH)
    latched_ns: u64,
}

impl GoldfishRtc {
    pub fn new() -> Self {
        Self { latched_ns: 0 }
    }

    fn now_ns() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }

    /// Read a 32-bit register at the given offset.
    /// Reading TIME_LOW latches the full 64-bit time so TIME_HIGH is consistent.
    pub fn read(&mut self, offset: u64) -> u32 {
        match offset {
            0x00 => {
                // TIME_LOW — latch current time
                self.latched_ns = Self::now_ns();
                self.latched_ns as u32
            }
            0x04 => {
                // TIME_HIGH — return upper 32 bits of latched time
                (self.latched_ns >> 32) as u32
            }
            0x18 => {
                // ALARM_STATUS — no alarm support
                0
            }
            _ => 0,
        }
    }

    /// Write a 32-bit register (alarm registers — accepted but ignored).
    pub fn write(&mut self, _offset: u64, _val: u64) {
        // Alarm functionality not implemented — writes are silently ignored
    }

    /// RTC does not generate interrupts (alarm not implemented).
    #[allow(dead_code)]
    pub fn has_interrupt(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtc_returns_nonzero_time() {
        let mut rtc = GoldfishRtc::new();
        let low = rtc.read(0x00);
        let high = rtc.read(0x04);
        let ns = ((high as u64) << 32) | (low as u64);
        // Should be after year 2020 (1577836800 seconds = 0x5E0BE100)
        assert!(ns > 1_577_836_800_000_000_000);
    }

    #[test]
    fn test_rtc_latching() {
        let mut rtc = GoldfishRtc::new();
        // Read TIME_LOW to latch
        let low = rtc.read(0x00);
        let high = rtc.read(0x04);
        // Read TIME_HIGH again — should return same latched value
        let high2 = rtc.read(0x04);
        assert_eq!(high, high2);
        // Sanity: low was captured
        assert_eq!(low, rtc.latched_ns as u32);
    }

    #[test]
    fn test_rtc_alarm_status_zero() {
        let mut rtc = GoldfishRtc::new();
        assert_eq!(rtc.read(0x18), 0);
    }

    #[test]
    fn test_rtc_write_ignored() {
        let mut rtc = GoldfishRtc::new();
        rtc.write(0x08, 12345); // ALARM_LOW
        rtc.write(0x0C, 67890); // ALARM_HIGH
                                // Should not panic or change behavior
        assert_eq!(rtc.read(0x18), 0);
    }

    #[test]
    fn test_rtc_no_interrupt() {
        let rtc = GoldfishRtc::new();
        assert!(!rtc.has_interrupt());
    }
}
