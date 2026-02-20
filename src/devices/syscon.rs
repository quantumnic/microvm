/// Syscon — system controller for poweroff/reboot
///
/// Compatible with "syscon-poweroff" and "syscon-reboot" in the device tree.
/// Linux writes a magic value to trigger shutdown or reboot.
///
/// Memory layout (4 bytes):
///   offset 0x00: control register (write-only)
///     Write 0x5555 → poweroff
///     Write 0x7777 → reboot

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SysconAction {
    None,
    Poweroff,
    Reboot,
}

pub struct Syscon {
    pub action: SysconAction,
}

impl Default for Syscon {
    fn default() -> Self {
        Self::new()
    }
}

impl Syscon {
    pub fn new() -> Self {
        Self {
            action: SysconAction::None,
        }
    }

    pub fn read(&self, _offset: u64) -> u32 {
        0
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        if offset == 0 {
            match val as u32 {
                0x5555 => {
                    log::info!("Syscon: poweroff requested");
                    self.action = SysconAction::Poweroff;
                }
                0x7777 => {
                    log::info!("Syscon: reboot requested");
                    self.action = SysconAction::Reboot;
                }
                _ => {
                    log::warn!("Syscon: unknown control value {:#x}", val);
                }
            }
        }
    }

    /// Check if a system action was requested and clear it
    pub fn take_action(&mut self) -> SysconAction {
        let a = self.action;
        self.action = SysconAction::None;
        a
    }
}
