use std::collections::HashMap;

// Machine-level CSRs
pub const MSTATUS: u16 = 0x300;
pub const MISA: u16 = 0x301;
pub const MEDELEG: u16 = 0x302;
pub const MIDELEG: u16 = 0x303;
pub const MIE: u16 = 0x304;
pub const MTVEC: u16 = 0x305;
pub const MCOUNTEREN: u16 = 0x306;
pub const MSCRATCH: u16 = 0x340;
pub const MEPC: u16 = 0x341;
pub const MCAUSE: u16 = 0x342;
pub const MTVAL: u16 = 0x343;
pub const MIP: u16 = 0x344;
pub const PMPCFG0: u16 = 0x3A0;
pub const PMPADDR0: u16 = 0x3B0;
pub const MHARTID: u16 = 0xF14;
pub const MCYCLE: u16 = 0xB00;
pub const MINSTRET: u16 = 0xB02;

// Supervisor-level CSRs
pub const SSTATUS: u16 = 0x100;
pub const SIE: u16 = 0x104;
pub const STVEC: u16 = 0x105;
pub const SCOUNTEREN: u16 = 0x106;
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

// MSTATUS bit masks
pub const MSTATUS_SIE: u64 = 1 << 1;
pub const MSTATUS_MIE: u64 = 1 << 3;
pub const MSTATUS_SPIE: u64 = 1 << 5;
pub const MSTATUS_MPIE: u64 = 1 << 7;
pub const MSTATUS_SPP: u64 = 1 << 8;
pub const MSTATUS_MPP: u64 = 3 << 11;
pub const MSTATUS_SUM: u64 = 1 << 18;
pub const MSTATUS_MXR: u64 = 1 << 19;

// SSTATUS mask — bits visible to S-mode
const SSTATUS_MASK: u64 = MSTATUS_SIE | MSTATUS_SPIE | MSTATUS_SPP | MSTATUS_SUM | MSTATUS_MXR
    | (3 << 13) // FS
    | (3 << 32) // UXL
    | (1 << 63); // SD

pub struct CsrFile {
    regs: HashMap<u16, u64>,
}

impl CsrFile {
    pub fn new() -> Self {
        let mut csrs = Self {
            regs: HashMap::new(),
        };
        // MISA: RV64IMACSU
        // Bit layout: MXL=2 (64-bit) in bits [63:62], then extension bits
        let misa = (2u64 << 62)  // MXL = 64-bit
            | (1 << 0)   // A - Atomic
            | (1 << 2)   // C - Compressed
            | (1 << 8)   // I - Integer
            | (1 << 12)  // M - Multiply/Divide
            | (1 << 18)  // S - Supervisor mode
            | (1 << 20); // U - User mode
        csrs.regs.insert(MISA, misa);
        csrs.regs.insert(MHARTID, 0);
        csrs
    }

    pub fn read(&self, addr: u16) -> u64 {
        match addr {
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
            _ => self.regs.get(&addr).copied().unwrap_or(0),
        }
    }

    pub fn write(&mut self, addr: u16, val: u64) {
        match addr {
            MISA | MHARTID => {} // Read-only
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
            _ => {
                self.regs.insert(addr, val);
            }
        }
    }
}
