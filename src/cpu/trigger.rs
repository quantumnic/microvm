/// Sdtrig — Debug Trigger Module
///
/// Implements hardware breakpoints and watchpoints via the RISC-V Debug Trigger
/// mechanism (Sdtrig extension). Provides mcontrol6-type triggers for address
/// matching on execute, load, and store accesses.
///
/// CSRs: tselect (0x7A0), tdata1 (0x7A1), tdata2 (0x7A2), tdata3 (0x7A3), tinfo (0x7A4)
use super::PrivilegeMode;

/// Number of hardware triggers supported
pub const NUM_TRIGGERS: usize = 4;

// Trigger CSR addresses
pub const TSELECT: u16 = 0x7A0;
pub const TDATA1: u16 = 0x7A1;
pub const TDATA2: u16 = 0x7A2;
pub const TDATA3: u16 = 0x7A3;
pub const TINFO: u16 = 0x7A4;

// mcontrol6 type field (bits [63:60] on RV64)
const TYPE_MCONTROL6: u64 = 6;
const TYPE_DISABLED: u64 = 15; // Trigger exists but is disabled (type=15 means "disabled")

// mcontrol6 field positions (RV64)
const MC6_DMODE: u64 = 1 << 59; // D-mode: trigger only usable in debug mode
const MC6_VS: u64 = 1 << 24; // Match in VS-mode
const MC6_VU: u64 = 1 << 23; // Match in VU-mode
#[allow(dead_code)]
const MC6_HIT1: u64 = 1 << 25; // Hit1 bit (high)
#[allow(dead_code)]
const MC6_HIT0: u64 = 1 << 22; // Hit0 bit (low)
const MC6_SELECT: u64 = 1 << 21; // 0=address, 1=data
const MC6_SIZE_SHIFT: u32 = 16;
const MC6_SIZE_MASK: u64 = 0xF << MC6_SIZE_SHIFT; // match size
const MC6_ACTION_SHIFT: u32 = 12;
const MC6_ACTION_MASK: u64 = 0xF << MC6_ACTION_SHIFT;
const MC6_CHAIN: u64 = 1 << 11;
const MC6_MATCH_SHIFT: u32 = 7;
const MC6_MATCH_MASK: u64 = 0xF << MC6_MATCH_SHIFT;
const MC6_M: u64 = 1 << 6; // Match in M-mode
const MC6_S: u64 = 1 << 4; // Match in S-mode
const MC6_U: u64 = 1 << 3; // Match in U-mode
const MC6_EXECUTE: u64 = 1 << 2;
const MC6_STORE: u64 = 1 << 1;
const MC6_LOAD: u64 = 1 << 0;

/// Writable bits mask for mcontrol6 (excluding type, dmode, hit bits which have special handling)
const MC6_WRITABLE: u64 = MC6_VS
    | MC6_VU
    | MC6_SELECT
    | MC6_SIZE_MASK
    | MC6_ACTION_MASK
    | MC6_CHAIN
    | MC6_MATCH_MASK
    | MC6_M
    | MC6_S
    | MC6_U
    | MC6_EXECUTE
    | MC6_STORE
    | MC6_LOAD;

/// Access type for trigger matching
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerAccess {
    Execute,
    Load,
    Store,
}

/// Action to take when trigger fires
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerAction {
    /// Raise breakpoint exception (cause 3)
    BreakpointException,
    /// Enter debug mode (not supported without external debugger)
    DebugMode,
}

/// A single hardware trigger
#[derive(Clone)]
pub struct Trigger {
    /// tdata1: type + control fields
    pub tdata1: u64,
    /// tdata2: match value (address or data)
    pub tdata2: u64,
    /// tdata3: additional match info (textra — not used for mcontrol6)
    pub tdata3: u64,
}

impl Default for Trigger {
    fn default() -> Self {
        // Default: type=15 (disabled), all other fields 0
        Self {
            tdata1: TYPE_DISABLED << 60,
            tdata2: 0,
            tdata3: 0,
        }
    }
}

impl Trigger {
    /// Get the trigger type from tdata1
    fn trigger_type(&self) -> u64 {
        self.tdata1 >> 60
    }

    /// Check if this trigger is an active mcontrol6
    fn is_mcontrol6(&self) -> bool {
        self.trigger_type() == TYPE_MCONTROL6
    }

    /// Get the action field
    fn action(&self) -> TriggerAction {
        let action = (self.tdata1 & MC6_ACTION_MASK) >> MC6_ACTION_SHIFT;
        match action {
            0 => TriggerAction::BreakpointException,
            _ => TriggerAction::DebugMode,
        }
    }

    /// Get the match type
    fn match_type(&self) -> u64 {
        (self.tdata1 & MC6_MATCH_MASK) >> MC6_MATCH_SHIFT
    }

    /// Check if trigger matches the given access in the given privilege mode
    pub fn matches(&self, addr: u64, access: TriggerAccess, mode: PrivilegeMode) -> bool {
        if !self.is_mcontrol6() {
            return false;
        }

        let tdata1 = self.tdata1;

        // Check privilege mode
        let mode_ok = match mode {
            PrivilegeMode::Machine => tdata1 & MC6_M != 0,
            PrivilegeMode::Supervisor => tdata1 & MC6_S != 0,
            PrivilegeMode::User => tdata1 & MC6_U != 0,
        };
        if !mode_ok {
            return false;
        }

        // Check access type
        let access_ok = match access {
            TriggerAccess::Execute => tdata1 & MC6_EXECUTE != 0,
            TriggerAccess::Load => tdata1 & MC6_LOAD != 0,
            TriggerAccess::Store => tdata1 & MC6_STORE != 0,
        };
        if !access_ok {
            return false;
        }

        // SELECT bit: 0 = address match, 1 = data match (we only support address)
        if tdata1 & MC6_SELECT != 0 {
            return false;
        }

        // Match based on match type
        match self.match_type() {
            0 => addr == self.tdata2,    // exact match
            1 => self.napot_match(addr), // NAPOT
            2 => addr >= self.tdata2,    // >=
            3 => addr < self.tdata2,     // <
            // Match types 4/5: tdata2 low half = value, high half = mask
            4 => {
                let mask = self.tdata2 >> 32;
                let value = self.tdata2 & 0xFFFF_FFFF;
                (addr & mask) == (value & mask)
            }
            5 => {
                let mask = self.tdata2 >> 32;
                let value = self.tdata2 & 0xFFFF_FFFF;
                (addr & mask) != (value & mask)
            }
            _ => false,
        }
    }

    /// NAPOT (Naturally Aligned Power-of-Two) address matching
    fn napot_match(&self, addr: u64) -> bool {
        // tdata2 encodes: base | (size/2 - 1)
        // Trailing ones + 1 = log2(size)
        let trailing_ones = self.tdata2.trailing_ones();
        let size = 1u64 << (trailing_ones + 1);
        let mask = !(size - 1);
        (addr & mask) == (self.tdata2 & mask)
    }
}

/// Debug trigger module containing all triggers
pub struct TriggerModule {
    /// Currently selected trigger index
    pub tselect: usize,
    /// Hardware triggers
    pub triggers: [Trigger; NUM_TRIGGERS],
}

impl Default for TriggerModule {
    fn default() -> Self {
        Self::new()
    }
}

impl TriggerModule {
    pub fn new() -> Self {
        Self {
            tselect: 0,
            triggers: std::array::from_fn(|_| Trigger::default()),
        }
    }

    /// Read a trigger CSR
    pub fn read_csr(&self, addr: u16) -> u64 {
        match addr {
            TSELECT => self.tselect as u64,
            TDATA1 => {
                if self.tselect < NUM_TRIGGERS {
                    self.triggers[self.tselect].tdata1
                } else {
                    // Out-of-range tselect: return 0 (no trigger)
                    0
                }
            }
            TDATA2 => {
                if self.tselect < NUM_TRIGGERS {
                    self.triggers[self.tselect].tdata2
                } else {
                    0
                }
            }
            TDATA3 => {
                if self.tselect < NUM_TRIGGERS {
                    self.triggers[self.tselect].tdata3
                } else {
                    0
                }
            }
            TINFO => {
                if self.tselect < NUM_TRIGGERS {
                    // Supported types bitmask: bit 6 = mcontrol6, bit 15 = disabled
                    (1 << TYPE_MCONTROL6) | (1 << TYPE_DISABLED)
                } else {
                    // No trigger at this index: tinfo=1 (only type 0 = "no trigger")
                    1
                }
            }
            _ => 0,
        }
    }

    /// Write a trigger CSR
    pub fn write_csr(&mut self, addr: u16, val: u64, mode: PrivilegeMode) {
        match addr {
            TSELECT => {
                // Spec: writing an out-of-range value is fine; reads of tdata1 will show type=0
                self.tselect = val as usize;
            }
            TDATA1 => {
                if self.tselect >= NUM_TRIGGERS {
                    return;
                }
                let old = &self.triggers[self.tselect];
                // If dmode is set and we're not in M-mode, ignore write
                if old.tdata1 & MC6_DMODE != 0 && mode != PrivilegeMode::Machine {
                    return;
                }
                let new_type = val >> 60;
                let tdata1 = match new_type {
                    TYPE_MCONTROL6 => {
                        // Write writable fields, set type
                        (TYPE_MCONTROL6 << 60) | (val & MC6_WRITABLE)
                    }
                    TYPE_DISABLED | 0 => {
                        // Disable trigger
                        TYPE_DISABLED << 60
                    }
                    _ => {
                        // Unsupported type: set to disabled
                        TYPE_DISABLED << 60
                    }
                };
                self.triggers[self.tselect].tdata1 = tdata1;
            }
            TDATA2 => {
                if self.tselect >= NUM_TRIGGERS {
                    return;
                }
                let old = &self.triggers[self.tselect];
                if old.tdata1 & MC6_DMODE != 0 && mode != PrivilegeMode::Machine {
                    return;
                }
                self.triggers[self.tselect].tdata2 = val;
            }
            TDATA3 => {
                if self.tselect >= NUM_TRIGGERS {
                    return;
                }
                let old = &self.triggers[self.tselect];
                if old.tdata1 & MC6_DMODE != 0 && mode != PrivilegeMode::Machine {
                    return;
                }
                self.triggers[self.tselect].tdata3 = val;
            }
            _ => {}
        }
    }

    /// Check if any execute trigger fires for the given PC and privilege mode.
    /// Returns Some(action) if a trigger fires.
    #[inline]
    pub fn check_execute(&self, pc: u64, mode: PrivilegeMode) -> Option<TriggerAction> {
        for trigger in &self.triggers {
            if trigger.matches(pc, TriggerAccess::Execute, mode) {
                return Some(trigger.action());
            }
        }
        None
    }

    /// Check if any load trigger fires for the given address and privilege mode.
    #[inline]
    pub fn check_load(&self, addr: u64, mode: PrivilegeMode) -> Option<TriggerAction> {
        for trigger in &self.triggers {
            if trigger.matches(addr, TriggerAccess::Load, mode) {
                return Some(trigger.action());
            }
        }
        None
    }

    /// Check if any store trigger fires for the given address and privilege mode.
    #[inline]
    pub fn check_store(&self, addr: u64, mode: PrivilegeMode) -> Option<TriggerAction> {
        for trigger in &self.triggers {
            if trigger.matches(addr, TriggerAccess::Store, mode) {
                return Some(trigger.action());
            }
        }
        None
    }

    /// Configure a trigger programmatically (used by GDB stub)
    pub fn set_breakpoint(&mut self, addr: u64, access: TriggerAccess) -> Option<usize> {
        // Find a free trigger slot (type = disabled)
        let slot = self
            .triggers
            .iter()
            .position(|t| t.trigger_type() == TYPE_DISABLED)?;

        let access_bits = match access {
            TriggerAccess::Execute => MC6_EXECUTE,
            TriggerAccess::Load => MC6_LOAD,
            TriggerAccess::Store => MC6_STORE,
        };

        // Configure as mcontrol6 with exact address match, action=breakpoint, all modes
        self.triggers[slot].tdata1 = (TYPE_MCONTROL6 << 60) | MC6_M | MC6_S | MC6_U | access_bits;
        // match type 0 (exact) is default (bits 10:7 = 0)
        self.triggers[slot].tdata2 = addr;
        self.triggers[slot].tdata3 = 0;

        Some(slot)
    }

    /// Remove a trigger by address and access type (used by GDB stub)
    pub fn clear_breakpoint(&mut self, addr: u64, access: TriggerAccess) -> bool {
        let access_bit = match access {
            TriggerAccess::Execute => MC6_EXECUTE,
            TriggerAccess::Load => MC6_LOAD,
            TriggerAccess::Store => MC6_STORE,
        };
        for trigger in &mut self.triggers {
            if trigger.trigger_type() == TYPE_MCONTROL6
                && trigger.tdata2 == addr
                && trigger.tdata1 & access_bit != 0
            {
                trigger.tdata1 = TYPE_DISABLED << 60;
                trigger.tdata2 = 0;
                trigger.tdata3 = 0;
                return true;
            }
        }
        false
    }

    /// Check if any triggers are active (optimization: skip checks if none configured)
    #[inline]
    pub fn has_active_triggers(&self) -> bool {
        self.triggers.iter().any(|t| t.is_mcontrol6())
    }

    // === SBI DBTR (Debug Triggers) interface ===

    /// Return the number of triggers available
    pub fn num_triggers(&self) -> usize {
        NUM_TRIGGERS
    }

    /// Read tdata1/tdata2/tdata3 for a trigger by index.
    /// Returns None if index is out of range.
    pub fn dbtr_read(&self, idx: usize) -> Option<(u64, u64, u64)> {
        if idx >= NUM_TRIGGERS {
            return None;
        }
        let t = &self.triggers[idx];
        Some((t.tdata1, t.tdata2, t.tdata3))
    }

    /// Install (configure) a trigger via SBI DBTR.
    /// Sets tdata1/tdata2/tdata3 on the first available (disabled) slot.
    /// Returns the slot index on success, or None if no slots available.
    pub fn dbtr_install(&mut self, tdata1: u64, tdata2: u64, tdata3: u64) -> Option<usize> {
        let slot = self
            .triggers
            .iter()
            .position(|t| t.trigger_type() == TYPE_DISABLED)?;

        let new_type = tdata1 >> 60;
        let stored_tdata1 = if new_type == TYPE_MCONTROL6 {
            (TYPE_MCONTROL6 << 60) | (tdata1 & MC6_WRITABLE)
        } else if new_type == TYPE_DISABLED || new_type == 0 {
            TYPE_DISABLED << 60
        } else {
            // Unsupported type
            return None;
        };

        self.triggers[slot].tdata1 = stored_tdata1;
        self.triggers[slot].tdata2 = tdata2;
        self.triggers[slot].tdata3 = tdata3;
        Some(slot)
    }

    /// Uninstall (disable) a trigger by index.
    /// Returns true if the trigger existed and was uninstalled.
    pub fn dbtr_uninstall(&mut self, idx: usize) -> bool {
        if idx >= NUM_TRIGGERS {
            return false;
        }
        self.triggers[idx].tdata1 = TYPE_DISABLED << 60;
        self.triggers[idx].tdata2 = 0;
        self.triggers[idx].tdata3 = 0;
        true
    }

    /// Enable a trigger by index (set it to mcontrol6 if it was installed but disabled).
    /// If the trigger is already active, this is a no-op success.
    /// Returns true if the trigger was enabled.
    pub fn dbtr_enable(&mut self, idx: usize) -> bool {
        if idx >= NUM_TRIGGERS {
            return false;
        }
        // If trigger is disabled type but has saved state in tdata2/tdata3,
        // we restore it as mcontrol6. For simplicity, if it's already mcontrol6
        // we leave it alone.
        let t = &self.triggers[idx];
        if t.trigger_type() == TYPE_MCONTROL6 {
            return true; // already enabled
        }
        // Can't enable a trigger that was never installed (all zeros)
        if t.tdata2 == 0 && t.tdata3 == 0 {
            return false;
        }
        // Restore as mcontrol6 with previously stored writable bits
        // (the tdata1 low bits may still hold the configuration)
        let bits = self.triggers[idx].tdata1 & MC6_WRITABLE;
        if bits == 0 {
            return false; // no configuration to restore
        }
        self.triggers[idx].tdata1 = (TYPE_MCONTROL6 << 60) | bits;
        true
    }

    /// Disable a trigger by index (set type to disabled but preserve config in lower bits).
    /// Returns true if the trigger was disabled.
    pub fn dbtr_disable(&mut self, idx: usize) -> bool {
        if idx >= NUM_TRIGGERS {
            return false;
        }
        let t = &self.triggers[idx];
        if t.trigger_type() != TYPE_MCONTROL6 {
            return true; // already disabled
        }
        // Preserve writable bits but change type to disabled
        let bits = self.triggers[idx].tdata1 & MC6_WRITABLE;
        self.triggers[idx].tdata1 = (TYPE_DISABLED << 60) | bits;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trigger_default_disabled() {
        let tm = TriggerModule::new();
        assert!(!tm.has_active_triggers());
        assert_eq!(tm.read_csr(TSELECT), 0);
        // tdata1 should be type=15 (disabled)
        assert_eq!(tm.read_csr(TDATA1) >> 60, TYPE_DISABLED);
    }

    #[test]
    fn test_tselect_range() {
        let mut tm = TriggerModule::new();
        // Valid indices
        for i in 0..NUM_TRIGGERS {
            tm.write_csr(TSELECT, i as u64, PrivilegeMode::Machine);
            assert_eq!(tm.read_csr(TSELECT), i as u64);
            assert_eq!(tm.read_csr(TDATA1) >> 60, TYPE_DISABLED);
        }
        // Out of range: tdata1 reads as 0
        tm.write_csr(TSELECT, 100, PrivilegeMode::Machine);
        assert_eq!(tm.read_csr(TDATA1), 0);
    }

    #[test]
    fn test_tinfo() {
        let tm = TriggerModule::new();
        let tinfo = tm.read_csr(TINFO);
        assert!(tinfo & (1 << 6) != 0, "mcontrol6 supported");
        assert!(tinfo & (1 << 15) != 0, "disabled type supported");
    }

    #[test]
    fn test_configure_execute_trigger() {
        let mut tm = TriggerModule::new();
        tm.write_csr(TSELECT, 0, PrivilegeMode::Machine);
        // Set type=mcontrol6, execute, all modes, action=breakpoint
        let tdata1 = (TYPE_MCONTROL6 << 60) | MC6_M | MC6_S | MC6_U | MC6_EXECUTE;
        tm.write_csr(TDATA1, tdata1, PrivilegeMode::Machine);
        tm.write_csr(TDATA2, 0x8000_0000, PrivilegeMode::Machine);

        assert!(tm.has_active_triggers());
        assert!(tm
            .check_execute(0x8000_0000, PrivilegeMode::Supervisor)
            .is_some());
        assert!(tm
            .check_execute(0x8000_0004, PrivilegeMode::Supervisor)
            .is_none());
        // Should not match loads
        assert!(tm
            .check_load(0x8000_0000, PrivilegeMode::Supervisor)
            .is_none());
    }

    #[test]
    fn test_configure_load_watchpoint() {
        let mut tm = TriggerModule::new();
        let slot = tm.set_breakpoint(0x1000, TriggerAccess::Load);
        assert!(slot.is_some());
        assert!(tm.check_load(0x1000, PrivilegeMode::Machine).is_some());
        assert!(tm.check_load(0x1001, PrivilegeMode::Machine).is_none());
        assert!(tm.check_store(0x1000, PrivilegeMode::Machine).is_none());
    }

    #[test]
    fn test_configure_store_watchpoint() {
        let mut tm = TriggerModule::new();
        let slot = tm.set_breakpoint(0x2000, TriggerAccess::Store);
        assert!(slot.is_some());
        assert!(tm.check_store(0x2000, PrivilegeMode::User).is_some());
        assert!(tm.check_load(0x2000, PrivilegeMode::User).is_none());
    }

    #[test]
    fn test_privilege_mode_filtering() {
        let mut tm = TriggerModule::new();
        tm.write_csr(TSELECT, 0, PrivilegeMode::Machine);
        // Only match S-mode
        let tdata1 = (TYPE_MCONTROL6 << 60) | MC6_S | MC6_EXECUTE;
        tm.write_csr(TDATA1, tdata1, PrivilegeMode::Machine);
        tm.write_csr(TDATA2, 0x1000, PrivilegeMode::Machine);

        assert!(tm
            .check_execute(0x1000, PrivilegeMode::Supervisor)
            .is_some());
        assert!(tm.check_execute(0x1000, PrivilegeMode::Machine).is_none());
        assert!(tm.check_execute(0x1000, PrivilegeMode::User).is_none());
    }

    #[test]
    fn test_clear_breakpoint() {
        let mut tm = TriggerModule::new();
        tm.set_breakpoint(0x1000, TriggerAccess::Execute);
        assert!(tm.has_active_triggers());

        let cleared = tm.clear_breakpoint(0x1000, TriggerAccess::Execute);
        assert!(cleared);
        assert!(!tm.has_active_triggers());
        assert!(tm.check_execute(0x1000, PrivilegeMode::Machine).is_none());
    }

    #[test]
    fn test_multiple_triggers() {
        let mut tm = TriggerModule::new();
        tm.set_breakpoint(0x1000, TriggerAccess::Execute);
        tm.set_breakpoint(0x2000, TriggerAccess::Execute);
        tm.set_breakpoint(0x3000, TriggerAccess::Load);
        tm.set_breakpoint(0x4000, TriggerAccess::Store);

        assert!(tm.check_execute(0x1000, PrivilegeMode::Machine).is_some());
        assert!(tm.check_execute(0x2000, PrivilegeMode::Machine).is_some());
        assert!(tm.check_load(0x3000, PrivilegeMode::Machine).is_some());
        assert!(tm.check_store(0x4000, PrivilegeMode::Machine).is_some());

        // All slots used
        assert!(tm.set_breakpoint(0x5000, TriggerAccess::Execute).is_none());
    }

    #[test]
    fn test_napot_match() {
        let mut tm = TriggerModule::new();
        tm.write_csr(TSELECT, 0, PrivilegeMode::Machine);
        // mcontrol6, NAPOT match (match=1), execute, all modes
        let tdata1 = (TYPE_MCONTROL6 << 60)
            | MC6_M
            | MC6_S
            | MC6_U
            | MC6_EXECUTE
            | (1u64 << MC6_MATCH_SHIFT); // match type 1 = NAPOT
        tm.write_csr(TDATA1, tdata1, PrivilegeMode::Machine);
        // NAPOT for 8-byte range at 0x1000: tdata2 = 0x1000 | 0x3 (trailing 2 ones → size=8)
        tm.write_csr(TDATA2, 0x1003, PrivilegeMode::Machine);

        // Addresses 0x1000-0x1007 should match
        for addr in 0x1000..0x1008 {
            assert!(
                tm.check_execute(addr, PrivilegeMode::Machine).is_some(),
                "addr 0x{:x} should match",
                addr
            );
        }
        // Outside range
        assert!(tm.check_execute(0x1008, PrivilegeMode::Machine).is_none());
        assert!(tm.check_execute(0x0FFF, PrivilegeMode::Machine).is_none());
    }

    #[test]
    fn test_ge_lt_match() {
        let mut tm = TriggerModule::new();
        // Trigger 0: >= 0x1000
        tm.write_csr(TSELECT, 0, PrivilegeMode::Machine);
        let tdata1_ge = (TYPE_MCONTROL6 << 60)
            | MC6_M
            | MC6_S
            | MC6_U
            | MC6_EXECUTE
            | (2u64 << MC6_MATCH_SHIFT); // match type 2 = >=
        tm.write_csr(TDATA1, tdata1_ge, PrivilegeMode::Machine);
        tm.write_csr(TDATA2, 0x1000, PrivilegeMode::Machine);

        assert!(tm.check_execute(0x1000, PrivilegeMode::Machine).is_some());
        assert!(tm.check_execute(0x2000, PrivilegeMode::Machine).is_some());
        assert!(tm.check_execute(0x0FFF, PrivilegeMode::Machine).is_none());
    }

    #[test]
    fn test_disable_trigger() {
        let mut tm = TriggerModule::new();
        tm.set_breakpoint(0x1000, TriggerAccess::Execute);
        assert!(tm.has_active_triggers());

        // Disable by writing type=disabled
        tm.write_csr(TSELECT, 0, PrivilegeMode::Machine);
        tm.write_csr(TDATA1, TYPE_DISABLED << 60, PrivilegeMode::Machine);
        assert!(!tm.has_active_triggers());
    }

    #[test]
    fn test_unsupported_type_becomes_disabled() {
        let mut tm = TriggerModule::new();
        tm.write_csr(TSELECT, 0, PrivilegeMode::Machine);
        // Try to set type=2 (mcontrol, not mcontrol6) — unsupported
        tm.write_csr(TDATA1, 2u64 << 60, PrivilegeMode::Machine);
        // Should become disabled
        assert_eq!(tm.read_csr(TDATA1) >> 60, TYPE_DISABLED);
    }
}
