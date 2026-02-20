pub mod csr;
pub mod decode;
pub mod disasm;
pub mod execute;
pub mod fpu;
pub mod mmu;

use crate::memory::Bus;
use csr::CsrFile;
use mmu::Mmu;

/// RISC-V privilege modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeMode {
    User = 0,
    Supervisor = 1,
    Machine = 3,
}

impl PrivilegeMode {
    pub fn from_u64(v: u64) -> Self {
        match v & 3 {
            0 => Self::User,
            1 => Self::Supervisor,
            3 => Self::Machine,
            _ => Self::Machine,
        }
    }
}

/// RV64GC CPU core
pub struct Cpu {
    /// General-purpose registers x0-x31
    pub regs: [u64; 32],
    /// Floating-point registers f0-f31 (IEEE 754 double stored as u64 bits)
    pub fregs: [u64; 32],
    /// Program counter
    pub pc: u64,
    /// CSR file
    pub csrs: CsrFile,
    /// Current privilege mode
    pub mode: PrivilegeMode,
    /// MMU
    pub mmu: Mmu,
    /// Wait-for-interrupt flag
    pub wfi: bool,
    /// LR/SC reservation address
    pub reservation: Option<u64>,
    /// Cycle counter
    pub cycle: u64,
    /// Last trap cause (for profiling; set in handle_exception/handle_interrupt)
    pub last_trap: Option<(u64, bool)>,
    /// Last SBI call (eid, fid) for profiling
    pub last_sbi: Option<(u64, u64)>,
}

impl Default for Cpu {
    fn default() -> Self {
        Self::new()
    }
}

impl Cpu {
    pub fn new() -> Self {
        Self {
            regs: [0; 32],
            fregs: [0; 32],
            pc: 0,
            csrs: CsrFile::new(),
            mode: PrivilegeMode::Machine,
            mmu: Mmu::new(),
            wfi: false,
            reservation: None,
            cycle: 0,
            last_trap: None,
            last_sbi: None,
        }
    }

    /// Reset CPU, set PC to reset vector
    pub fn reset(&mut self, pc: u64) {
        self.regs = [0; 32];
        self.fregs = [0; 32];
        self.pc = pc;
        self.mode = PrivilegeMode::Machine;
        self.wfi = false;
        self.cycle = 0;
    }

    /// Execute one instruction, returns whether to continue
    pub fn step(&mut self, bus: &mut Bus) -> bool {
        if self.wfi {
            // Check for pending interrupts
            if self.check_pending_interrupts(bus) {
                self.wfi = false;
            } else {
                self.cycle += 1;
                return true;
            }
        }

        // Check for pending interrupts
        self.check_and_handle_interrupt(bus);

        // Fetch instruction
        let pc = self.pc;
        let fetch_result =
            self.mmu
                .translate(pc, mmu::AccessType::Execute, self.mode, &self.csrs, bus);
        let phys_pc = match fetch_result {
            Ok(addr) => addr,
            Err(exception) => {
                self.handle_exception(exception, pc, bus);
                self.cycle += 1;
                return true;
            }
        };

        // Read instruction (could be 16-bit compressed or 32-bit)
        let raw16 = bus.read16(phys_pc);
        let (inst, inst_len) = if raw16 & 0x03 != 0x03 {
            // Compressed instruction (16-bit)
            let expanded = decode::expand_compressed(raw16 as u32);
            (expanded, 2u64)
        } else {
            // Normal 32-bit instruction
            let raw32 = bus.read32(phys_pc);
            (raw32, 4u64)
        };

        // Decode and execute
        let cont = execute::execute(self, bus, inst, inst_len);

        // x0 is always zero
        self.regs[0] = 0;
        self.cycle += 1;
        self.csrs.update_counters(self.cycle);
        cont
    }

    fn check_pending_interrupts(&self, _bus: &Bus) -> bool {
        let mip = self.csrs.read(csr::MIP);
        let mie = self.csrs.read(csr::MIE);
        (mip & mie) != 0
    }

    fn check_and_handle_interrupt(&mut self, _bus: &mut Bus) {
        let mip = self.csrs.read(csr::MIP);
        let mie = self.csrs.read(csr::MIE);
        let pending = mip & mie;
        if pending == 0 {
            return;
        }

        let mstatus = self.csrs.read(csr::MSTATUS);
        let mideleg = self.csrs.read(csr::MIDELEG);

        // Priority: MEI > MSI > MTI > SEI > SSI > STI
        let priorities = [11, 3, 7, 9, 1, 5];
        for &code in &priorities {
            if pending & (1 << code) == 0 {
                continue;
            }

            let delegated = (mideleg >> code) & 1 == 1;

            if delegated && self.mode != PrivilegeMode::Machine {
                // Delegated to S-mode — check if S-mode can take it
                let can_take = match self.mode {
                    PrivilegeMode::Supervisor => (mstatus >> 1) & 1 == 1, // SIE
                    PrivilegeMode::User => true, // S-mode interrupts always preempt U-mode
                    _ => false,
                };
                if can_take {
                    self.last_trap = Some((code, true));
                    self.trap_to_smode(code, true);
                    return;
                }
            } else if !delegated {
                // M-mode interrupt
                let can_take = match self.mode {
                    PrivilegeMode::Machine => (mstatus >> 3) & 1 == 1, // MIE
                    _ => true, // M-mode interrupts always preempt lower modes
                };
                if can_take {
                    self.last_trap = Some((code, true));
                    self.trap_to_mmode(code, true);
                    return;
                }
            }
        }
    }

    pub fn handle_exception(&mut self, cause: u64, tval: u64, _bus: &mut Bus) {
        self.last_trap = Some((cause, false));
        let medeleg = self.csrs.read(csr::MEDELEG);
        if (medeleg >> cause) & 1 == 1 && self.mode != PrivilegeMode::Machine {
            self.csrs.write(csr::STVAL, tval);
            self.trap_to_smode(cause, false);
        } else {
            self.csrs.write(csr::MTVAL, tval);
            self.trap_to_mmode(cause, false);
        }
    }

    fn trap_to_mmode(&mut self, cause: u64, is_interrupt: bool) {
        let cause_val = if is_interrupt {
            (1u64 << 63) | cause
        } else {
            cause
        };
        self.csrs.write(csr::MCAUSE, cause_val);
        self.csrs.write(csr::MEPC, self.pc);

        // Update mstatus: save MIE to MPIE, clear MIE, save mode to MPP
        let mut mstatus = self.csrs.read(csr::MSTATUS);
        let mie = (mstatus >> 3) & 1;
        mstatus = (mstatus & !(1 << 7)) | (mie << 7); // MPIE = MIE
        mstatus &= !(1 << 3); // Clear MIE
        mstatus = (mstatus & !(3 << 11)) | ((self.mode as u64) << 11); // MPP
        self.csrs.write(csr::MSTATUS, mstatus);

        let mtvec = self.csrs.read(csr::MTVEC);
        let mode = mtvec & 3;
        let base = mtvec & !3;
        self.pc = if mode == 1 && is_interrupt {
            base + cause * 4
        } else {
            base
        };
        self.mode = PrivilegeMode::Machine;
    }

    fn trap_to_smode(&mut self, cause: u64, is_interrupt: bool) {
        let cause_val = if is_interrupt {
            (1u64 << 63) | cause
        } else {
            cause
        };
        self.csrs.write(csr::SCAUSE, cause_val);
        self.csrs.write(csr::SEPC, self.pc);

        let mut sstatus = self.csrs.read(csr::SSTATUS);
        let sie = (sstatus >> 1) & 1;
        sstatus = (sstatus & !(1 << 5)) | (sie << 5); // SPIE = SIE
        sstatus &= !(1 << 1); // Clear SIE
        sstatus = (sstatus & !(1 << 8)) | (((self.mode as u64) & 1) << 8); // SPP
        self.csrs.write(csr::SSTATUS, sstatus);

        let stvec = self.csrs.read(csr::STVEC);
        let mode = stvec & 3;
        let base = stvec & !3;
        self.pc = if mode == 1 && is_interrupt {
            base + cause * 4
        } else {
            base
        };
        self.mode = PrivilegeMode::Supervisor;
    }
}
