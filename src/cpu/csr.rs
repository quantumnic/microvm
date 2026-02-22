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

// Sscofpmf extension — Supervisor-level Count Overflow and Privilege Mode Filtering
// scountovf: read-only bitmap of counters that have overflowed (bits 31:3 for hpmcounter3-31)
pub const SCOUNTOVF: u16 = 0xDA0;
// LCOFIP (Local Counter Overflow Interrupt Pending) — bit 13 in mip/mie
#[allow(dead_code)]
pub const LCOFIP_BIT: u64 = 1 << 13;

// Zkr extension — Entropy Source (seed CSR)
// M-mode only; each read returns 16 bits of entropy with ES16 status
pub const SEED: u16 = 0x015;
// seed optype values (bits [31:30])
pub const SEED_OPTYPE_ES16: u64 = 2 << 30; // 16 bits of entropy available in [15:0]

// Machine environment config high (RV64: reads as 0)
pub const MENVCFGH: u16 = 0x31A;

// Machine configuration pointer (Linux 6.x probes this)
#[allow(dead_code)]
pub const MCONFIGPTR: u16 = 0xF15;

// Sstc extension — supervisor timer compare
pub const STIMECMP: u16 = 0x14D;

// Smstateen extension — state enable CSRs
pub const MSTATEEN0: u16 = 0x30C;
pub const MSTATEEN1: u16 = 0x30D;
pub const MSTATEEN2: u16 = 0x30E;
pub const MSTATEEN3: u16 = 0x30F;
pub const SSTATEEN0: u16 = 0x10C;
pub const SSTATEEN1: u16 = 0x10D;
pub const SSTATEEN2: u16 = 0x10E;
pub const SSTATEEN3: u16 = 0x10F;

// Smstateen bit masks
/// Bit 63: controls whether sstateen0 is accessible from S-mode
pub const STATEEN_SE0: u64 = 1u64 << 63;
/// Bit 62: controls whether henvcfg/senvcfg PBMTE/ADUE are accessible
#[allow(dead_code)]
pub const STATEEN_ENVCFG: u64 = 1u64 << 62;
/// Bit 57: controls whether context register (scontext) is accessible
#[allow(dead_code)]
pub const STATEEN_CONTEXT: u64 = 1u64 << 57;
/// Bit 56: controls whether IMSIC (AIA) state is accessible
#[allow(dead_code)]
pub const STATEEN_AIA: u64 = 1u64 << 56;

// Vector extension CSRs
pub const VSTART: u16 = 0x008;
pub const VXSAT: u16 = 0x009;
pub const VXRM: u16 = 0x00A;
pub const VCSR: u16 = 0x00F;
pub const VL: u16 = 0xC20;
pub const VTYPE: u16 = 0xC21;
pub const VLENB: u16 = 0xC22;

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

// VS (Vector Status) field in mstatus
#[allow(dead_code)]
pub const MSTATUS_VS: u64 = 3 << 9;

// SSTATUS mask — bits visible to S-mode
const SSTATUS_MASK: u64 = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP | MSTATUS_SUM | MSTATUS_MXR
    | MSTATUS_FS  // FP status (F/D extensions present)
    | MSTATUS_VS  // Vector status (V extension present)
    | (3 << 32)   // UXL
    | (1 << 63); // SD

/// CSR address space size (12-bit addresses = 4096 entries)
const CSR_COUNT: usize = 4096;

/// Hardware Performance Monitor event types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)]
pub enum HpmEvent {
    /// Event 1: Load instructions retired
    Load = 1,
    /// Event 2: Store instructions retired
    Store = 2,
    /// Event 3: Conditional branches retired
    Branch = 3,
    /// Event 4: Conditional branches taken
    BranchTaken = 4,
    /// Event 5: Exceptions taken
    Exception = 5,
    /// Event 6: Interrupts taken
    Interrupt = 6,
    /// Event 7: TLB misses
    TlbMiss = 7,
    /// Event 8: Atomic instructions (AMO/LR/SC)
    Atomic = 8,
    /// Event 9: System instructions (CSR, ECALL, EBREAK, FENCE, etc.)
    System = 9,
    /// Event 10: Floating-point instructions
    FloatingPoint = 10,
    /// Event 11: Vector instructions
    Vector = 11,
    /// Event 12: Compressed instructions (16-bit)
    Compressed = 12,
}

pub struct CsrFile {
    /// Fixed array for all CSR registers (indexed by 12-bit address)
    regs: Box<[u64; CSR_COUNT]>,
    /// PMP configuration registers (pmpcfg0-pmpcfg3 for RV64 = 2 regs × 8 entries each)
    pub pmpcfg: [u64; 4],
    /// PMP address registers (pmpaddr0-pmpaddr15)
    pub pmpaddr: [u64; 16],
    /// Cached mtime from CLINT (updated each step for TIME CSR reads)
    pub mtime: u64,
    /// Hardware performance counters 3-31 (29 counters)
    pub hpm_counters: [u64; 29],
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
            hpm_counters: [0; 29],
        };
        // MISA: RV64IMAFDCVSU (G = IMAFD + Zicsr + Zifencei, V = Vector)
        let misa = (2u64 << 62)  // MXL = 64-bit
            | (1 << 0)   // A - Atomic
            | (1 << 2)   // C - Compressed
            | (1 << 3)   // D - Double-precision float
            | (1 << 5)   // F - Single-precision float
            | (1 << 8)   // I - Integer
            | (1 << 12)  // M - Multiply/Divide
            | (1 << 18)  // S - Supervisor mode
            | (1 << 20)  // U - User mode
            | (1 << 21); // V - Vector
        csrs.regs[MISA as usize] = misa;
        csrs.regs[MHARTID as usize] = 0;
        // MSTATUS: set UXL=2 (64-bit), SXL=2 (64-bit), FS=1 (Initial), VS=1 (Initial)
        let mstatus = (2u64 << 32) | (2u64 << 34) | (1u64 << 13) | (1u64 << 9); // UXL | SXL | FS=Initial | VS=Initial
        csrs.regs[MSTATUS as usize] = mstatus;
        // Enable Sstc extension: MENVCFG.STCE (bit 63)
        // Enable Svadu: MENVCFG.ADUE (bit 61) — hardware A/D bit updates
        csrs.regs[MENVCFG as usize] = (1u64 << 63) | (1u64 << 61);
        // stimecmp defaults to max (no interrupt)
        csrs.regs[STIMECMP as usize] = u64::MAX;
        // Smstateen: default all bits set (all state accessible)
        csrs.regs[MSTATEEN0 as usize] = u64::MAX;
        csrs.regs[MSTATEEN1 as usize] = u64::MAX;
        csrs.regs[MSTATEEN2 as usize] = u64::MAX;
        csrs.regs[MSTATEEN3 as usize] = u64::MAX;
        // sstateen defaults to 0 — S-mode sets what U-mode can access
        // Vector extension: VLENB = VLEN/8
        csrs.regs[VLENB as usize] = super::vector::VLENB as u64;
        // vtype starts as vill (no configuration set yet)
        csrs.regs[VTYPE as usize] = 1u64 << 63;
        csrs
    }

    /// Set cycle/instret counters (called from CPU step)
    pub fn update_counters(&mut self, cycle: u64) {
        self.regs[MCYCLE as usize] = cycle;
        self.regs[MINSTRET as usize] = cycle; // 1:1 for now
    }

    /// Increment HPM counters matching the given event.
    /// Checks mhpmevent selectors and mcountinhibit bits.
    #[inline]
    pub fn hpm_increment(&mut self, event: HpmEvent) {
        let inhibit = self.regs[MCOUNTINHIBIT as usize];
        let event_id = event as u64;
        // Check counters 3-31 (indices 0-28 in hpm_counters)
        for i in 0..29u16 {
            let counter_idx = i + 3;
            // Check mcountinhibit bit
            if (inhibit >> counter_idx) & 1 != 0 {
                continue;
            }
            // Check mhpmevent selector (low 12 bits = event ID)
            let event_sel_addr = 0x323 + i;
            let selector = self.regs[event_sel_addr as usize];
            // Low 8 bits = event type; match if equal to our event
            if (selector & 0xFF) == event_id {
                self.hpm_counters[i as usize] = self.hpm_counters[i as usize].wrapping_add(1);
            }
        }
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

    /// Check if a stateen CSR is accessible from the given privilege mode.
    /// M-mode can always access mstateen*. S-mode can access sstateen* only
    /// if the corresponding mstateen* bit 63 (SE0) is set.
    pub fn stateen_accessible(&self, csr_addr: u16, mode: PrivilegeMode) -> bool {
        match mode {
            PrivilegeMode::Machine => true,
            PrivilegeMode::Supervisor | PrivilegeMode::User => match csr_addr {
                SSTATEEN0 => self.regs[MSTATEEN0 as usize] & STATEEN_SE0 != 0,
                SSTATEEN1 => self.regs[MSTATEEN1 as usize] & STATEEN_SE0 != 0,
                SSTATEEN2 => self.regs[MSTATEEN2 as usize] & STATEEN_SE0 != 0,
                SSTATEEN3 => self.regs[MSTATEEN3 as usize] & STATEEN_SE0 != 0,
                _ => true,
            },
        }
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
            // Machine HPM counters (mhpmcounter3-31)
            0xB03..=0xB1F => self.hpm_counters[(addr - 0xB03) as usize],
            // Machine HPM event selectors (mhpmevent3-31)
            0x323..=0x33F => self.regs[addr as usize],
            // Sscofpmf: scountovf — read-only overflow bitmap
            SCOUNTOVF => {
                // Bit N is set if hpmcounterN has overflowed (wrapped past u64::MAX)
                // We approximate: bit set if counter's MSB is set (large value)
                // In practice, real overflow requires OF bit in mhpmevent which we don't track yet
                0
            }
            // Zkr: seed CSR — returns 16 bits of entropy with ES16 status
            SEED => {
                use std::io::Read;
                let mut buf = [0u8; 2];
                if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
                    let _ = f.read_exact(&mut buf);
                }
                SEED_OPTYPE_ES16 | u64::from(u16::from_le_bytes(buf))
            }
            // User HPM counters (hpmcounter3-31) — shadows of machine counters
            0xC03..=0xC1F => self.hpm_counters[(addr - 0xC03) as usize],
            // Smstateen CSRs
            MSTATEEN0 => self.regs[MSTATEEN0 as usize],
            MSTATEEN1 => self.regs[MSTATEEN1 as usize],
            MSTATEEN2 => self.regs[MSTATEEN2 as usize],
            MSTATEEN3 => self.regs[MSTATEEN3 as usize],
            SSTATEEN0 => self.regs[SSTATEEN0 as usize] & self.regs[MSTATEEN0 as usize],
            SSTATEEN1 => self.regs[SSTATEEN1 as usize] & self.regs[MSTATEEN1 as usize],
            SSTATEEN2 => self.regs[SSTATEEN2 as usize] & self.regs[MSTATEEN2 as usize],
            SSTATEEN3 => self.regs[SSTATEEN3 as usize] & self.regs[MSTATEEN3 as usize],
            // Vector CSRs
            VSTART => self.regs[VSTART as usize],
            VXSAT => self.regs[VXSAT as usize] & 1,
            VXRM => self.regs[VXRM as usize] & 3,
            VCSR => (self.regs[VXRM as usize] & 3) << 1 | (self.regs[VXSAT as usize] & 1),
            VL => self.regs[VL as usize],
            VTYPE => self.regs[VTYPE as usize],
            VLENB => self.regs[VLENB as usize],
            _ => self.regs[addr as usize],
        }
    }

    /// Check PMP (Physical Memory Protection) for a physical address.
    /// Returns true if access is allowed, false if denied.
    /// Per RISC-V spec: S/U-mode accesses are denied by default (no matching entry = deny).
    /// M-mode accesses are allowed by default unless a PMP entry with L bit locks it.
    pub fn pmp_check(
        &self,
        paddr: u64,
        size: u64,
        access: super::mmu::AccessType,
        mode: PrivilegeMode,
    ) -> bool {
        // Check each byte of the access range against PMP
        // For simplicity and correctness, check start and end addresses
        // (PMP is checked per-byte conceptually, but contiguous ranges within
        // one PMP region are fine)
        self.pmp_check_addr(paddr, access, mode)
            && (size <= 1 || self.pmp_check_addr(paddr + size - 1, access, mode))
    }

    fn pmp_check_addr(
        &self,
        paddr: u64,
        access: super::mmu::AccessType,
        mode: PrivilegeMode,
    ) -> bool {
        let mut prev_addr: u64 = 0;

        for i in 0..16usize {
            let cfg_reg = i / 8; // pmpcfg0 or pmpcfg1
            let cfg_byte = (self.pmpcfg[cfg_reg] >> ((i % 8) * 8)) as u8;

            // Skip disabled entries (A=0)
            let a_field = (cfg_byte >> 3) & 3;
            if a_field == 0 {
                prev_addr = self.pmpaddr[i];
                continue;
            }

            let locked = cfg_byte & 0x80 != 0;
            let r = cfg_byte & 0x01 != 0;
            let w = cfg_byte & 0x02 != 0;
            let x = cfg_byte & 0x04 != 0;

            // Determine address range [range_start, range_end) in byte addresses
            // pmpaddr stores address >> 2 (granularity of 4 bytes)
            let (range_start, range_end) = match a_field {
                1 => {
                    // TOR (Top of Range): [pmpaddr[i-1]<<2, pmpaddr[i]<<2)
                    let top = self.pmpaddr[i] << 2;
                    let bot = prev_addr << 2;
                    (bot, top)
                }
                2 => {
                    // NA4 (Naturally Aligned 4-byte)
                    let base = self.pmpaddr[i] << 2;
                    (base, base + 4)
                }
                3 => {
                    // NAPOT (Naturally Aligned Power-of-Two)
                    // Find lowest clear bit in pmpaddr to determine size
                    let addr = self.pmpaddr[i];
                    // Count trailing ones to find the size encoding
                    let trailing_ones = addr.trailing_ones() as u64;
                    if trailing_ones >= 62 {
                        // Full address space
                        (0, u64::MAX)
                    } else {
                        let size = 1u64 << (trailing_ones + 3); // +3 because pmpaddr is addr>>2, and min NAPOT is 8 bytes
                        let base = (addr & !((1u64 << (trailing_ones + 1)) - 1)) << 2;
                        (base, base.saturating_add(size))
                    }
                }
                _ => unreachable!(),
            };

            prev_addr = self.pmpaddr[i];

            // Check if address falls in this range
            if paddr >= range_start && paddr < range_end {
                // Found matching entry
                if mode == PrivilegeMode::Machine && !locked {
                    // M-mode with non-locked entry: always allowed
                    return true;
                }
                // Check permission bits
                return match access {
                    super::mmu::AccessType::Read => r,
                    super::mmu::AccessType::Write => w,
                    super::mmu::AccessType::Execute => x,
                };
            }
        }

        // No matching entry
        // M-mode: default allow
        // S/U-mode: default deny
        mode == PrivilegeMode::Machine
    }

    /// Raw read — direct array access, bypassing SSTATUS/SIE/SIP masking.
    /// Used for snapshot serialization.
    pub fn read_raw(&self, addr: u16) -> u64 {
        self.regs[addr as usize]
    }

    /// Raw write — direct array access, bypassing MISA/MSTATUS protection.
    /// Used for snapshot deserialization.
    pub fn write_raw(&mut self, addr: u16, val: u64) {
        self.regs[addr as usize] = val;
    }

    pub fn write(&mut self, addr: u16, val: u64) {
        match addr {
            MISA | MHARTID | MVENDORID | MARCHID | MIMPID | SEED => {} // Read-only
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
                // SD (bit 63) is read-only: set when FS=3 or VS=3 (Dirty)
                let fs = (new_val >> 13) & 3;
                let vs = (new_val >> 9) & 3;
                if fs == 3 || vs == 3 {
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
            // HPM counters — writable (set counter value)
            0xB03..=0xB1F => {
                self.hpm_counters[(addr - 0xB03) as usize] = val;
            }
            // HPM event selectors — store for Sscofpmf privilege filtering bits
            0x323..=0x33F => {
                self.regs[addr as usize] = val;
            }
            // Smstateen CSRs
            MSTATEEN0 | MSTATEEN1 | MSTATEEN2 | MSTATEEN3 => {
                self.regs[addr as usize] = val;
            }
            SSTATEEN0 => {
                // S-mode can only set bits that M-mode allows
                self.regs[SSTATEEN0 as usize] = val & self.regs[MSTATEEN0 as usize];
            }
            SSTATEEN1 => {
                self.regs[SSTATEEN1 as usize] = val & self.regs[MSTATEEN1 as usize];
            }
            SSTATEEN2 => {
                self.regs[SSTATEEN2 as usize] = val & self.regs[MSTATEEN2 as usize];
            }
            SSTATEEN3 => {
                self.regs[SSTATEEN3 as usize] = val & self.regs[MSTATEEN3 as usize];
            }
            // Vector CSRs
            VSTART => self.regs[VSTART as usize] = val,
            VXSAT => self.regs[VXSAT as usize] = val & 1,
            VXRM => self.regs[VXRM as usize] = val & 3,
            VCSR => {
                self.regs[VXSAT as usize] = val & 1;
                self.regs[VXRM as usize] = (val >> 1) & 3;
            }
            VL | VTYPE | VLENB => {} // read-only from CSR instructions
            MENVCFGH => {}           // RV64: writes ignored
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
