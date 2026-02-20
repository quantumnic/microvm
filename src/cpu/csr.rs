use super::PrivilegeMode;

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

// Machine hardware performance counters (0xB03-0xB1F) — all zero (no HPM events)
// User-level HPM counters (0xC03-0xC1F) — shadows of above
// Machine HPM event selectors (0x323-0x33F)

// Machine environment config high (RV64: reads as 0)
pub const MENVCFGH: u16 = 0x31A;

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
const SSTATUS_MASK: u64 = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP | MSTATUS_SUM | MSTATUS_MXR
    | MSTATUS_FS  // FP status (F/D extensions present)
    | (3 << 32)   // UXL
    | (1 << 63); // SD

/// CSR address space size (12-bit addresses = 4096 entries)
const CSR_COUNT: usize = 4096;

pub struct CsrFile {
    /// Fixed array for all CSR registers (indexed by 12-bit address)
    regs: Box<[u64; CSR_COUNT]>,
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
            regs: Box::new([0u64; CSR_COUNT]),
            pmpcfg: [0; 4],
            pmpaddr: [0; 16],
            mtime: 0,
        };
        // MISA: RV64IMAFDCSU (G = IMAFD + Zicsr + Zifencei)
        let misa = (2u64 << 62)  // MXL = 64-bit
            | (1 << 0)   // A - Atomic
            | (1 << 2)   // C - Compressed
            | (1 << 3)   // D - Double-precision float
            | (1 << 5)   // F - Single-precision float
            | (1 << 8)   // I - Integer
            | (1 << 12)  // M - Multiply/Divide
            | (1 << 18)  // S - Supervisor mode
            | (1 << 20); // U - User mode
        csrs.regs[MISA as usize] = misa;
        csrs.regs[MHARTID as usize] = 0;
        // MSTATUS: set UXL=2 (64-bit), SXL=2 (64-bit), FS=1 (Initial)
        let mstatus = (2u64 << 32) | (2u64 << 34) | (1u64 << 13); // UXL | SXL | FS=Initial
        csrs.regs[MSTATUS as usize] = mstatus;
        // Enable Sstc extension: MENVCFG.STCE (bit 63)
        // Enable Svadu: MENVCFG.ADUE (bit 61) — hardware A/D bit updates
        csrs.regs[MENVCFG as usize] = (1u64 << 63) | (1u64 << 61);
        // stimecmp defaults to max (no interrupt)
        csrs.regs[STIMECMP as usize] = u64::MAX;
        csrs
    }

    /// Set cycle/instret counters (called from CPU step)
    pub fn update_counters(&mut self, cycle: u64) {
        self.regs[MCYCLE as usize] = cycle;
        self.regs[MINSTRET as usize] = cycle; // 1:1 for now
    }

    /// Check if a counter CSR is accessible from the given privilege mode.
    /// Returns true if accessible.
    pub fn counter_accessible(&self, csr_addr: u16, mode: PrivilegeMode) -> bool {
        let bit = match csr_addr {
            CYCLE | MCYCLE => 0,
            TIME => 1,
            INSTRET | MINSTRET => 2,
            // HPM counters: user 0xC03-0xC1F, machine 0xB03-0xB1F
            0xC03..=0xC1F => (csr_addr - 0xC00) as u32,
            0xB03..=0xB1F => (csr_addr - 0xB00) as u32,
            _ => return true,
        };
        match mode {
            PrivilegeMode::Machine => true,
            PrivilegeMode::Supervisor => (self.regs[MCOUNTEREN as usize] >> bit) & 1 != 0,
            PrivilegeMode::User => {
                let mcounteren = self.regs[MCOUNTEREN as usize];
                let scounteren = self.regs[SCOUNTEREN as usize];
                ((mcounteren >> bit) & 1 != 0) && ((scounteren >> bit) & 1 != 0)
            }
        }
    }

    /// Check if stimecmp timer has fired (Sstc extension)
    pub fn stimecmp_pending(&self) -> bool {
        self.mtime >= self.regs[STIMECMP as usize]
    }

    /// Mark floating-point state as Dirty (FS=3) in mstatus, and set SD bit
    pub fn set_fs_dirty(&mut self) {
        let mstatus = self.regs[MSTATUS as usize];
        let fs = (mstatus >> 13) & 3;
        if fs != 3 {
            let mut new = (mstatus & !MSTATUS_FS) | (3u64 << 13); // FS = Dirty
            new |= 1u64 << 63; // SD
            self.regs[MSTATUS as usize] = new;
        }
    }

    /// Check if FP instructions are allowed (FS != 0/Off)
    pub fn fp_enabled(&self) -> bool {
        ((self.regs[MSTATUS as usize] >> 13) & 3) != 0
    }

    pub fn read(&self, addr: u16) -> u64 {
        match addr {
            // User-level counter CSRs (read-only shadows)
            CYCLE => self.regs[MCYCLE as usize],
            INSTRET => self.regs[MINSTRET as usize],
            TIME => self.mtime,
            STIMECMP => self.regs[STIMECMP as usize],
            SSTATUS => self.regs[MSTATUS as usize] & SSTATUS_MASK,
            SIE => self.regs[MIE as usize] & self.regs[MIDELEG as usize],
            SIP => self.regs[MIP as usize] & self.regs[MIDELEG as usize],
            // PMP config registers (RV64: pmpcfg0 at 0x3A0, pmpcfg2 at 0x3A2)
            0x3A0 => self.pmpcfg[0],
            0x3A1 => 0, // pmpcfg1 is not accessible on RV64
            0x3A2 => self.pmpcfg[1],
            0x3A3 => 0, // pmpcfg3 is not accessible on RV64
            // PMP address registers (0x3B0 - 0x3BF)
            0x3B0..=0x3BF => self.pmpaddr[(addr - 0x3B0) as usize],
            // FP CSRs
            FFLAGS => self.regs[FCSR as usize] & 0x1F,
            FRM => (self.regs[FCSR as usize] >> 5) & 0x7,
            FCSR => self.regs[FCSR as usize] & 0xFF,
            // Environment config CSRs
            SENVCFG => self.regs[SENVCFG as usize],
            MENVCFG => self.regs[MENVCFG as usize],
            MENVCFGH => 0, // RV64: high half is 0
            MCOUNTINHIBIT => self.regs[MCOUNTINHIBIT as usize],
            // Machine HPM counters (mhpmcounter3-31) — all zero
            0xB03..=0xB1F => 0,
            // Machine HPM event selectors (mhpmevent3-31) — all zero
            0x323..=0x33F => 0,
            // User HPM counters (hpmcounter3-31) — shadows, all zero
            0xC03..=0xC1F => 0,
            _ => self.regs[addr as usize],
        }
    }

    pub fn write(&mut self, addr: u16, val: u64) {
        match addr {
            MISA | MHARTID | MVENDORID | MARCHID | MIMPID => {} // Read-only
            SSTATUS => {
                let mstatus = self.regs[MSTATUS as usize];
                self.regs[MSTATUS as usize] = (mstatus & !SSTATUS_MASK) | (val & SSTATUS_MASK);
            }
            SIE => {
                let mideleg = self.regs[MIDELEG as usize];
                let mie = self.regs[MIE as usize];
                self.regs[MIE as usize] = (mie & !mideleg) | (val & mideleg);
            }
            SIP => {
                let mideleg = self.regs[MIDELEG as usize];
                let mip = self.regs[MIP as usize];
                // Only SSIP is writable from S-mode
                let writable = mideleg & (1 << 1);
                self.regs[MIP as usize] = (mip & !writable) | (val & writable);
            }
            MSTATUS => {
                // Preserve read-only fields: SXL, UXL
                let old = self.regs[MSTATUS as usize];
                let readonly_mask = (3u64 << 32) | (3u64 << 34); // SXL | UXL
                let mut new_val = (val & !readonly_mask) | (old & readonly_mask);
                // SD (bit 63) is read-only: set when FS=3 (Dirty)
                let fs = (new_val >> 13) & 3;
                if fs == 3 {
                    new_val |= 1u64 << 63;
                } else {
                    new_val &= !(1u64 << 63);
                }
                self.regs[MSTATUS as usize] = new_val;
            }
            // PMP config registers
            0x3A0 => self.pmpcfg[0] = val,
            0x3A1 => {} // not accessible on RV64
            0x3A2 => self.pmpcfg[1] = val,
            0x3A3 => {}
            // PMP address registers
            0x3B0..=0x3BF => self.pmpaddr[(addr - 0x3B0) as usize] = val,
            // FP CSR writes
            FFLAGS => {
                let old = self.regs[FCSR as usize];
                self.regs[FCSR as usize] = (old & !0x1F) | (val & 0x1F);
            }
            FRM => {
                let old = self.regs[FCSR as usize];
                self.regs[FCSR as usize] = (old & !0xE0) | ((val & 0x7) << 5);
            }
            FCSR => {
                self.regs[FCSR as usize] = val & 0xFF;
            }
            // HPM counters and event selectors — writable but no effect
            0xB03..=0xB1F | 0x323..=0x33F => {}
            MENVCFGH => {} // RV64: writes ignored
            SATP => {
                // Accept mode 0 (Bare), 8 (Sv39), 9 (Sv48), 10 (Sv57); ignore unsupported modes
                let mode = val >> 60;
                if mode == 0 || mode == 8 || mode == 9 || mode == 10 {
                    self.regs[SATP as usize] = val;
                }
                // Writes with unsupported modes are silently ignored (spec allows this)
            }
            _ => {
                self.regs[addr as usize] = val;
            }
        }
    }
}
