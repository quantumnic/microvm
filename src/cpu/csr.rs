use super::PrivilegeMode;
use std::collections::HashMap;

// Machine-level CSRs
pub const MSTATUS: u16 = 0x300;
pub const MISA: u16 = 0x301;
pub const MEDELEG: u16 = 0x302;
pub const MIDELEG: u16 = 0x303;
pub const MIE: u16 = 0x304;
pub const MTVEC: u16 = 0x305;
pub const MCOUNTEREN: u16 = 0x306;
#[allow(dead_code)]
pub const MSCRATCH: u16 = 0x340;
pub const MEPC: u16 = 0x341;
pub const MCAUSE: u16 = 0x342;
pub const MTVAL: u16 = 0x343;
pub const MIP: u16 = 0x344;
#[allow(dead_code)]
pub const PMPCFG0: u16 = 0x3A0;
#[allow(dead_code)]
pub const PMPCFG2: u16 = 0x3A2;
#[allow(dead_code)]
pub const PMPADDR0: u16 = 0x3B0;
pub const MHARTID: u16 = 0xF14;
pub const MCYCLE: u16 = 0xB00;
pub const MINSTRET: u16 = 0xB02;
pub const MVENDORID: u16 = 0xF11;
pub const MARCHID: u16 = 0xF12;
pub const MIMPID: u16 = 0xF13;

// Supervisor-level CSRs
pub const SSTATUS: u16 = 0x100;
pub const SIE: u16 = 0x104;
pub const STVEC: u16 = 0x105;
pub const SCOUNTEREN: u16 = 0x106;
#[allow(dead_code)]
pub const SSCRATCH: u16 = 0x140;
pub const SEPC: u16 = 0x141;
pub const SCAUSE: u16 = 0x142;
pub const STVAL: u16 = 0x143;
pub const SIP: u16 = 0x144;
pub const SATP: u16 = 0x180;

// User-level CSRs
pub const CYCLE: u16 = 0xC00;
pub const TIME: u16 = 0xC01;
pub const INSTRET: u16 = 0xC02;

// Floating-point CSRs (stubs — needed for Linux even without FPU)
pub const FFLAGS: u16 = 0x001;
pub const FRM: u16 = 0x002;
pub const FCSR: u16 = 0x003;

// Supervisor environment config (Linux probes this)
pub const SENVCFG: u16 = 0x10A;
pub const MENVCFG: u16 = 0x30A;

// Machine counter-inhibit (Linux reads this)
pub const MCOUNTINHIBIT: u16 = 0x320;

// Machine configuration pointer (Linux 6.x probes this)
#[allow(dead_code)]
pub const MCONFIGPTR: u16 = 0xF15;

// Sstc extension — supervisor timer compare
pub const STIMECMP: u16 = 0x14D;

// MSTATUS bit masks
pub const MSTATUS_SIE: u64 = 1 << 1;
#[allow(dead_code)]
pub const MSTATUS_MIE: u64 = 1 << 3;
pub const MSTATUS_SPIE: u64 = 1 << 5;
#[allow(dead_code)]
pub const MSTATUS_MPIE: u64 = 1 << 7;
pub const MSTATUS_SPP: u64 = 1 << 8;
#[allow(dead_code)]
pub const MSTATUS_MPP: u64 = 3 << 11;
pub const MSTATUS_SUM: u64 = 1 << 18;
pub const MSTATUS_MXR: u64 = 1 << 19;
#[allow(dead_code)]
pub const MSTATUS_FS: u64 = 3 << 13; // Floating-point status field

// SSTATUS mask — bits visible to S-mode
// Note: FS (bits 14:13) is excluded because MISA has no F/D extensions.
// When no FPU is present, FS must be hardwired to 0 (Off) per RISC-V spec.
// Including FS here would make Linux think FPU exists and crash on FP instructions.
const SSTATUS_MASK: u64 = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP | MSTATUS_SUM | MSTATUS_MXR
    | (3 << 32) // UXL
    | (1 << 63); // SD

pub struct CsrFile {
    regs: HashMap<u16, u64>,
    /// PMP configuration registers (pmpcfg0-pmpcfg3 for RV64 = 2 regs × 8 entries each)
    pub pmpcfg: [u64; 4],
    /// PMP address registers (pmpaddr0-pmpaddr15)
    pub pmpaddr: [u64; 16],
    /// Cached mtime from CLINT (updated each step for TIME CSR reads)
    pub mtime: u64,
}

impl CsrFile {
    /// Check if a CSR is accessible from the given privilege mode.
    /// RISC-V spec: CSR address bits [9:8] encode the minimum privilege level.
    /// Returns true if accessible.
    pub fn check_privilege(&self, csr_addr: u16, mode: PrivilegeMode) -> bool {
        let required_priv = (csr_addr >> 8) & 3;
        let current_priv = mode as u16;
        current_priv >= required_priv
    }

    /// Check if a CSR is read-only (bits [11:10] == 0b11).
    pub fn is_read_only(&self, csr_addr: u16) -> bool {
        (csr_addr >> 10) & 3 == 3
    }
}

impl Default for CsrFile {
    fn default() -> Self {
        Self::new()
    }
}

impl CsrFile {
    pub fn new() -> Self {
        let mut csrs = Self {
            regs: HashMap::new(),
            pmpcfg: [0; 4],
            pmpaddr: [0; 16],
            mtime: 0,
        };
        // MISA: RV64IMACSU
        let misa = (2u64 << 62)  // MXL = 64-bit
            | (1 << 0)   // A - Atomic
            | (1 << 2)   // C - Compressed
            | (1 << 8)   // I - Integer
            | (1 << 12)  // M - Multiply/Divide
            | (1 << 18)  // S - Supervisor mode
            | (1 << 20); // U - User mode
        csrs.regs.insert(MISA, misa);
        csrs.regs.insert(MHARTID, 0);
        // MSTATUS: set UXL=2 (64-bit) and SXL=2 (64-bit)
        let mstatus = (2u64 << 32) | (2u64 << 34); // UXL | SXL
        csrs.regs.insert(MSTATUS, mstatus);
        // Read-only zero registers
        csrs.regs.insert(MVENDORID, 0);
        csrs.regs.insert(MARCHID, 0);
        csrs.regs.insert(MIMPID, 0);
        // Enable Sstc extension: MENVCFG.STCE (bit 63)
        csrs.regs.insert(MENVCFG, 1u64 << 63);
        // stimecmp defaults to max (no interrupt)
        csrs.regs.insert(STIMECMP, u64::MAX);
        csrs
    }

    /// Set cycle/instret counters (called from CPU step)
    pub fn update_counters(&mut self, cycle: u64) {
        self.regs.insert(MCYCLE, cycle);
        self.regs.insert(MINSTRET, cycle); // 1:1 for now
    }

    /// Check if a counter CSR is accessible from the given privilege mode.
    /// Returns true if accessible.
    pub fn counter_accessible(&self, csr_addr: u16, mode: PrivilegeMode) -> bool {
        let bit = match csr_addr {
            CYCLE | MCYCLE => 0,
            TIME => 1,
            INSTRET | MINSTRET => 2,
            _ => return true,
        };
        match mode {
            PrivilegeMode::Machine => true,
            PrivilegeMode::Supervisor => {
                let mcounteren = self.regs.get(&MCOUNTEREN).copied().unwrap_or(0);
                (mcounteren >> bit) & 1 != 0
            }
            PrivilegeMode::User => {
                let mcounteren = self.regs.get(&MCOUNTEREN).copied().unwrap_or(0);
                let scounteren = self.regs.get(&SCOUNTEREN).copied().unwrap_or(0);
                ((mcounteren >> bit) & 1 != 0) && ((scounteren >> bit) & 1 != 0)
            }
        }
    }

    /// Check if stimecmp timer has fired (Sstc extension)
    pub fn stimecmp_pending(&self) -> bool {
        let stimecmp = self.regs.get(&STIMECMP).copied().unwrap_or(u64::MAX);
        self.mtime >= stimecmp
    }

    pub fn read(&self, addr: u16) -> u64 {
        match addr {
            // User-level counter CSRs (read-only shadows)
            CYCLE => self.regs.get(&MCYCLE).copied().unwrap_or(0),
            INSTRET => self.regs.get(&MINSTRET).copied().unwrap_or(0),
            TIME => self.mtime,
            STIMECMP => self.regs.get(&STIMECMP).copied().unwrap_or(u64::MAX),
            SSTATUS => self.regs.get(&MSTATUS).copied().unwrap_or(0) & SSTATUS_MASK,
            SIE => {
                let mie = self.regs.get(&MIE).copied().unwrap_or(0);
                let mideleg = self.regs.get(&MIDELEG).copied().unwrap_or(0);
                mie & mideleg
            }
            SIP => {
                let mip = self.regs.get(&MIP).copied().unwrap_or(0);
                let mideleg = self.regs.get(&MIDELEG).copied().unwrap_or(0);
                mip & mideleg
            }
            // PMP config registers (RV64: pmpcfg0 at 0x3A0, pmpcfg2 at 0x3A2)
            0x3A0 => self.pmpcfg[0],
            0x3A1 => 0, // pmpcfg1 is not accessible on RV64
            0x3A2 => self.pmpcfg[1],
            0x3A3 => 0, // pmpcfg3 is not accessible on RV64
            // PMP address registers (0x3B0 - 0x3BF)
            0x3B0..=0x3BF => self.pmpaddr[(addr - 0x3B0) as usize],
            // FP CSRs (stub — always 0, FPU not implemented)
            FFLAGS | FRM | FCSR => 0,
            // Environment config CSRs
            SENVCFG => self.regs.get(&SENVCFG).copied().unwrap_or(0),
            MENVCFG => self.regs.get(&MENVCFG).copied().unwrap_or(0),
            MCOUNTINHIBIT => self.regs.get(&MCOUNTINHIBIT).copied().unwrap_or(0),
            _ => self.regs.get(&addr).copied().unwrap_or(0),
        }
    }

    pub fn write(&mut self, addr: u16, val: u64) {
        match addr {
            MISA | MHARTID | MVENDORID | MARCHID | MIMPID => {} // Read-only
            SSTATUS => {
                let mstatus = self.regs.get(&MSTATUS).copied().unwrap_or(0);
                let new_mstatus = (mstatus & !SSTATUS_MASK) | (val & SSTATUS_MASK);
                self.regs.insert(MSTATUS, new_mstatus);
            }
            SIE => {
                let mideleg = self.regs.get(&MIDELEG).copied().unwrap_or(0);
                let mie = self.regs.get(&MIE).copied().unwrap_or(0);
                self.regs.insert(MIE, (mie & !mideleg) | (val & mideleg));
            }
            SIP => {
                let mideleg = self.regs.get(&MIDELEG).copied().unwrap_or(0);
                let mip = self.regs.get(&MIP).copied().unwrap_or(0);
                // Only SSIP is writable from S-mode
                let writable = mideleg & (1 << 1);
                self.regs.insert(MIP, (mip & !writable) | (val & writable));
            }
            MSTATUS => {
                // Preserve read-only fields: SXL, UXL, and FS (hardwired 0, no FPU)
                let old = self.regs.get(&MSTATUS).copied().unwrap_or(0);
                let readonly_mask = (3u64 << 32) | (3u64 << 34) | MSTATUS_FS;
                let new_val = (val & !readonly_mask) | (old & readonly_mask);
                self.regs.insert(MSTATUS, new_val);
            }
            // PMP config registers
            0x3A0 => self.pmpcfg[0] = val,
            0x3A1 => {} // not accessible on RV64
            0x3A2 => self.pmpcfg[1] = val,
            0x3A3 => {}
            // PMP address registers
            0x3B0..=0x3BF => self.pmpaddr[(addr - 0x3B0) as usize] = val,
            SATP => {
                // Accept mode 0 (Bare), 8 (Sv39), 9 (Sv48); ignore unsupported modes
                let mode = val >> 60;
                if mode == 0 || mode == 8 || mode == 9 {
                    self.regs.insert(SATP, val);
                }
                // Writes with unsupported modes are silently ignored (spec allows this)
            }
            _ => {
                self.regs.insert(addr, val);
            }
        }
    }
}
