use super::csr;
use super::decode::Instruction;
use super::mmu::AccessType;
use super::{Cpu, PrivilegeMode};
use crate::memory::Bus;

/// Execute a decoded instruction. Returns true to continue, false to halt.
pub fn execute(cpu: &mut Cpu, bus: &mut Bus, raw: u32, inst_len: u64) -> bool {
    let inst = Instruction::decode(raw);

    match inst.opcode {
        0x37 => op_lui(cpu, &inst, inst_len),
        0x17 => op_auipc(cpu, &inst, inst_len),
        0x6F => op_jal(cpu, &inst),
        0x67 => op_jalr(cpu, &inst),
        0x63 => op_branch(cpu, &inst, inst_len),
        0x03 => op_load(cpu, bus, &inst, inst_len),
        0x23 => op_store(cpu, bus, &inst, inst_len),
        0x13 => op_imm(cpu, &inst, inst_len),
        0x1B => op_imm32(cpu, &inst, inst_len),
        0x33 => op_reg(cpu, &inst, inst_len),
        0x3B => op_reg32(cpu, &inst, inst_len),
        0x0F => {
            // FENCE (funct3=0) and FENCE.I (funct3=1) — both NOPs in single-hart emulator
            cpu.pc += inst_len;
        }
        0x73 => return op_system(cpu, bus, &inst, inst_len),
        0x2F => op_atomic(cpu, bus, &inst, inst_len),
        _ => {
            log::warn!("Illegal instruction: {:#010x} at PC={:#x}", raw, cpu.pc);
            cpu.handle_exception(2, raw as u64, bus); // Illegal instruction
        }
    }
    true
}

fn op_lui(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    cpu.regs[inst.rd] = inst.imm_u as u64;
    cpu.pc += len;
}

fn op_auipc(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    cpu.regs[inst.rd] = cpu.pc.wrapping_add(inst.imm_u as u64);
    cpu.pc += len;
}

fn op_jal(cpu: &mut Cpu, inst: &Instruction) {
    cpu.regs[inst.rd] = cpu.pc + 4; // Always saves PC+4 for JAL
    cpu.pc = cpu.pc.wrapping_add(inst.imm_j as u64);
}

fn op_jalr(cpu: &mut Cpu, inst: &Instruction) {
    let target = (cpu.regs[inst.rs1].wrapping_add(inst.imm_i as u64)) & !1;
    cpu.regs[inst.rd] = cpu.pc + 4;
    cpu.pc = target;
}

fn op_branch(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    let rs1 = cpu.regs[inst.rs1];
    let rs2 = cpu.regs[inst.rs2];
    let taken = match inst.funct3 {
        0 => rs1 == rs2,                   // BEQ
        1 => rs1 != rs2,                   // BNE
        4 => (rs1 as i64) < (rs2 as i64),  // BLT
        5 => (rs1 as i64) >= (rs2 as i64), // BGE
        6 => rs1 < rs2,                    // BLTU
        7 => rs1 >= rs2,                   // BGEU
        _ => false,
    };
    if taken {
        cpu.pc = cpu.pc.wrapping_add(inst.imm_b as u64);
    } else {
        cpu.pc += len;
    }
}

fn op_load(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) {
    let addr = cpu.regs[inst.rs1].wrapping_add(inst.imm_i as u64);
    let phys = match cpu
        .mmu
        .translate(addr, AccessType::Read, cpu.mode, &cpu.csrs, bus)
    {
        Ok(a) => a,
        Err(e) => {
            cpu.handle_exception(e, addr, bus);
            return;
        }
    };
    let val = match inst.funct3 {
        0 => bus.read8(phys) as i8 as i64 as u64,   // LB
        1 => bus.read16(phys) as i16 as i64 as u64, // LH
        2 => bus.read32(phys) as i32 as i64 as u64, // LW
        3 => bus.read64(phys),                      // LD
        4 => bus.read8(phys) as u64,                // LBU
        5 => bus.read16(phys) as u64,               // LHU
        6 => bus.read32(phys) as u64,               // LWU
        _ => 0,
    };
    cpu.regs[inst.rd] = val;
    cpu.pc += len;
}

fn op_store(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) {
    let addr = cpu.regs[inst.rs1].wrapping_add(inst.imm_s as u64);
    let phys = match cpu
        .mmu
        .translate(addr, AccessType::Write, cpu.mode, &cpu.csrs, bus)
    {
        Ok(a) => a,
        Err(e) => {
            cpu.handle_exception(e, addr, bus);
            return;
        }
    };
    let val = cpu.regs[inst.rs2];
    match inst.funct3 {
        0 => bus.write8(phys, val as u8),
        1 => bus.write16(phys, val as u16),
        2 => bus.write32(phys, val as u32),
        3 => bus.write64(phys, val),
        _ => {}
    }
    cpu.pc += len;
}

fn op_imm(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    let rs1 = cpu.regs[inst.rs1];
    let imm = inst.imm_i as u64;
    let shamt = (imm & 0x3F) as u32;
    let val = match inst.funct3 {
        0 => rs1.wrapping_add(imm),                // ADDI
        1 => rs1 << shamt,                         // SLLI
        2 => ((rs1 as i64) < (imm as i64)) as u64, // SLTI
        3 => (rs1 < imm) as u64,                   // SLTIU
        4 => rs1 ^ imm,                            // XORI
        5 => {
            if (inst.raw >> 30) & 1 == 1 {
                ((rs1 as i64) >> shamt) as u64 // SRAI
            } else {
                rs1 >> shamt // SRLI
            }
        }
        6 => rs1 | imm, // ORI
        7 => rs1 & imm, // ANDI
        _ => 0,
    };
    cpu.regs[inst.rd] = val;
    cpu.pc += len;
}

fn op_imm32(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    let rs1 = cpu.regs[inst.rs1] as u32;
    let imm = inst.imm_i as u32;
    let shamt = imm & 0x1F;
    let val = match inst.funct3 {
        0 => rs1.wrapping_add(imm) as i32 as i64 as u64, // ADDIW
        1 => (rs1 << shamt) as i32 as i64 as u64,        // SLLIW
        5 => {
            if (inst.raw >> 30) & 1 == 1 {
                ((rs1 as i32) >> shamt) as i64 as u64 // SRAIW
            } else {
                (rs1 >> shamt) as i32 as i64 as u64 // SRLIW
            }
        }
        _ => 0,
    };
    cpu.regs[inst.rd] = val;
    cpu.pc += len;
}

fn op_reg(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    let rs1 = cpu.regs[inst.rs1];
    let rs2 = cpu.regs[inst.rs2];

    let val = if inst.funct7 == 0x01 {
        // RV64M
        match inst.funct3 {
            0 => rs1.wrapping_mul(rs2), // MUL
            1 => ((rs1 as i64 as i128).wrapping_mul(rs2 as i64 as i128) >> 64) as u64, // MULH
            2 => ((rs1 as i64 as i128).wrapping_mul(rs2 as u128 as i128) >> 64) as u64, // MULHSU
            3 => ((rs1 as u128).wrapping_mul(rs2 as u128) >> 64) as u64, // MULHU
            4 => {
                if rs2 == 0 {
                    u64::MAX
                } else if rs1 as i64 == i64::MIN && rs2 as i64 == -1 {
                    rs1
                } else {
                    ((rs1 as i64).wrapping_div(rs2 as i64)) as u64
                } // DIV
            }
            5 => {
                if rs2 == 0 {
                    u64::MAX
                } else {
                    rs1.wrapping_div(rs2)
                } // DIVU
            }
            6 => {
                if rs2 == 0 {
                    rs1
                } else if rs1 as i64 == i64::MIN && rs2 as i64 == -1 {
                    0
                } else {
                    ((rs1 as i64).wrapping_rem(rs2 as i64)) as u64
                } // REM
            }
            7 => {
                if rs2 == 0 {
                    rs1
                } else {
                    rs1.wrapping_rem(rs2)
                } // REMU
            }
            _ => 0,
        }
    } else {
        match (inst.funct3, inst.funct7) {
            (0, 0x00) => rs1.wrapping_add(rs2),                 // ADD
            (0, 0x20) => rs1.wrapping_sub(rs2),                 // SUB
            (1, 0x00) => rs1 << (rs2 & 0x3F),                   // SLL
            (2, 0x00) => ((rs1 as i64) < (rs2 as i64)) as u64,  // SLT
            (3, 0x00) => (rs1 < rs2) as u64,                    // SLTU
            (4, 0x00) => rs1 ^ rs2,                             // XOR
            (5, 0x00) => rs1 >> (rs2 & 0x3F),                   // SRL
            (5, 0x20) => ((rs1 as i64) >> (rs2 & 0x3F)) as u64, // SRA
            (6, 0x00) => rs1 | rs2,                             // OR
            (7, 0x00) => rs1 & rs2,                             // AND
            _ => 0,
        }
    };
    cpu.regs[inst.rd] = val;
    cpu.pc += len;
}

fn op_reg32(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    let rs1 = cpu.regs[inst.rs1] as u32;
    let rs2 = cpu.regs[inst.rs2] as u32;

    let val = if inst.funct7 == 0x01 {
        // RV64M — 32-bit variants
        match inst.funct3 {
            0 => rs1.wrapping_mul(rs2) as i32 as i64 as u64, // MULW
            4 => {
                if rs2 == 0 {
                    u32::MAX as i32 as i64 as u64
                } else if rs1 as i32 == i32::MIN && rs2 as i32 == -1 {
                    rs1 as i32 as i64 as u64
                } else {
                    ((rs1 as i32).wrapping_div(rs2 as i32)) as i64 as u64
                }
            }
            5 => {
                if rs2 == 0 {
                    u32::MAX as i32 as i64 as u64
                } else {
                    rs1.wrapping_div(rs2) as i32 as i64 as u64
                }
            }
            6 => {
                if rs2 == 0 {
                    rs1 as i32 as i64 as u64
                } else if rs1 as i32 == i32::MIN && rs2 as i32 == -1 {
                    0
                } else {
                    ((rs1 as i32).wrapping_rem(rs2 as i32)) as i64 as u64
                }
            }
            7 => {
                if rs2 == 0 {
                    rs1 as i32 as i64 as u64
                } else {
                    rs1.wrapping_rem(rs2) as i32 as i64 as u64
                }
            }
            _ => 0,
        }
    } else {
        match (inst.funct3, inst.funct7) {
            (0, 0x00) => rs1.wrapping_add(rs2) as i32 as i64 as u64, // ADDW
            (0, 0x20) => rs1.wrapping_sub(rs2) as i32 as i64 as u64, // SUBW
            (1, 0x00) => (rs1 << (rs2 & 0x1F)) as i32 as i64 as u64, // SLLW
            (5, 0x00) => (rs1 >> (rs2 & 0x1F)) as i32 as i64 as u64, // SRLW
            (5, 0x20) => ((rs1 as i32) >> (rs2 & 0x1F)) as i64 as u64, // SRAW
            _ => 0,
        }
    };
    cpu.regs[inst.rd] = val;
    cpu.pc += len;
}

fn op_atomic(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) {
    let funct5 = inst.funct7 >> 2;
    let addr = cpu.regs[inst.rs1];
    let is_word = inst.funct3 == 2; // funct3=2 → 32-bit, funct3=3 → 64-bit

    let phys = match cpu
        .mmu
        .translate(addr, AccessType::Write, cpu.mode, &cpu.csrs, bus)
    {
        Ok(a) => a,
        Err(e) => {
            cpu.handle_exception(e, addr, bus);
            return;
        }
    };

    match funct5 {
        0x02 => {
            // LR
            let val = if is_word {
                bus.read32(phys) as i32 as i64 as u64
            } else {
                bus.read64(phys)
            };
            cpu.regs[inst.rd] = val;
            cpu.reservation = Some(addr);
        }
        0x03 => {
            // SC
            if cpu.reservation == Some(addr) {
                let val = cpu.regs[inst.rs2];
                if is_word {
                    bus.write32(phys, val as u32);
                } else {
                    bus.write64(phys, val);
                }
                cpu.regs[inst.rd] = 0; // success
            } else {
                cpu.regs[inst.rd] = 1; // failure
            }
            cpu.reservation = None;
        }
        _ => {
            // AMO instructions
            let old = if is_word {
                bus.read32(phys) as i32 as i64 as u64
            } else {
                bus.read64(phys)
            };
            let src = cpu.regs[inst.rs2];
            let result = match funct5 {
                0x01 => src,                                          // AMOSWAP
                0x00 => old.wrapping_add(src),                        // AMOADD
                0x04 => old ^ src,                                    // AMOXOR
                0x0C => old & src,                                    // AMOAND
                0x08 => old | src,                                    // AMOOR
                0x10 => std::cmp::min(old as i64, src as i64) as u64, // AMOMIN
                0x14 => std::cmp::max(old as i64, src as i64) as u64, // AMOMAX
                0x18 => std::cmp::min(old, src),                      // AMOMINU
                0x1C => std::cmp::max(old, src),                      // AMOMAXU
                _ => old,
            };
            if is_word {
                bus.write32(phys, result as u32);
            } else {
                bus.write64(phys, result);
            }
            cpu.regs[inst.rd] = old;
        }
    }
    cpu.pc += len;
}

fn op_system(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) -> bool {
    if inst.funct3 == 0 {
        match inst.raw {
            0x00000073 => {
                // ECALL
                if cpu.mode == PrivilegeMode::Supervisor {
                    // SBI call — handle in M-mode firmware
                    if handle_sbi_call(cpu, bus) {
                        cpu.pc += len;
                        return true;
                    }
                }
                let cause = match cpu.mode {
                    PrivilegeMode::User => 8,
                    PrivilegeMode::Supervisor => 9,
                    PrivilegeMode::Machine => 11,
                };
                cpu.handle_exception(cause, 0, bus);
                return true;
            }
            0x00100073 => {
                // EBREAK
                cpu.handle_exception(3, cpu.pc, bus);
                return true;
            }
            0x10200073 => {
                // SRET
                let sstatus = cpu.csrs.read(csr::SSTATUS);
                let spp = (sstatus >> 8) & 1;
                let spie = (sstatus >> 5) & 1;
                let mut new_sstatus = sstatus;
                new_sstatus = (new_sstatus & !(1 << 1)) | (spie << 1); // SIE = SPIE
                new_sstatus |= 1 << 5; // SPIE = 1
                new_sstatus &= !(1 << 8); // SPP = 0
                cpu.csrs.write(csr::SSTATUS, new_sstatus);
                cpu.pc = cpu.csrs.read(csr::SEPC);
                cpu.mode = if spp == 1 {
                    PrivilegeMode::Supervisor
                } else {
                    PrivilegeMode::User
                };
                return true;
            }
            0x30200073 => {
                // MRET
                let mstatus = cpu.csrs.read(csr::MSTATUS);
                let mpp = (mstatus >> 11) & 3;
                let mpie = (mstatus >> 7) & 1;
                let mut new_mstatus = mstatus;
                new_mstatus = (new_mstatus & !(1 << 3)) | (mpie << 3); // MIE = MPIE
                new_mstatus |= 1 << 7; // MPIE = 1
                new_mstatus &= !(3 << 11); // MPP = 0
                cpu.csrs.write(csr::MSTATUS, new_mstatus);
                cpu.pc = cpu.csrs.read(csr::MEPC);
                cpu.mode = PrivilegeMode::from_u64(mpp);
                return true;
            }
            0x10500073 => {
                // WFI
                cpu.wfi = true;
                cpu.pc += len;
                return true;
            }
            _ => {
                match inst.funct7 {
                    0x09 => {
                        // SFENCE.VMA — flush TLB
                        if inst.rs1 == 0 {
                            cpu.mmu.flush_tlb();
                        } else {
                            cpu.mmu.flush_tlb_vaddr(cpu.regs[inst.rs1]);
                        }
                        cpu.pc += len;
                        return true;
                    }
                    0x0B => {
                        // SINVAL.VMA — same as SFENCE.VMA (Svinval extension)
                        if inst.rs1 == 0 {
                            cpu.mmu.flush_tlb();
                        } else {
                            cpu.mmu.flush_tlb_vaddr(cpu.regs[inst.rs1]);
                        }
                        cpu.pc += len;
                        return true;
                    }
                    0x0C => {
                        // SFENCE.W.INVAL — nop (Svinval extension)
                        cpu.pc += len;
                        return true;
                    }
                    0x0D => {
                        // SFENCE.INVAL.IR — nop (Svinval extension)
                        cpu.pc += len;
                        return true;
                    }
                    _ => {
                        log::warn!(
                            "Unknown SYSTEM instruction: {:#010x} at PC={:#x}",
                            inst.raw,
                            cpu.pc
                        );
                        cpu.handle_exception(2, inst.raw as u64, bus);
                        return true;
                    }
                }
            }
        }
    }

    // CSR instructions
    let csr_addr = (inst.raw >> 20) & 0xFFF;
    let csr_addr = csr_addr as u16;

    // Check CSR privilege level access
    if !cpu.csrs.check_privilege(csr_addr, cpu.mode) {
        cpu.handle_exception(2, inst.raw as u64, bus); // Illegal instruction
        return true;
    }

    // Check counter CSR access permissions
    if matches!(csr_addr, csr::CYCLE | csr::TIME | csr::INSTRET)
        && !cpu.csrs.counter_accessible(csr_addr, cpu.mode)
    {
        cpu.handle_exception(2, inst.raw as u64, bus); // Illegal instruction
        return true;
    }

    let old_val = cpu.csrs.read(csr_addr);

    let write_val = match inst.funct3 {
        1 => cpu.regs[inst.rs1],            // CSRRW
        2 => old_val | cpu.regs[inst.rs1],  // CSRRS
        3 => old_val & !cpu.regs[inst.rs1], // CSRRC
        5 => inst.rs1 as u64,               // CSRRWI
        6 => old_val | (inst.rs1 as u64),   // CSRRSI
        7 => old_val & !(inst.rs1 as u64),  // CSRRCI
        _ => {
            cpu.pc += len;
            return true;
        }
    };

    // For CSRRS/CSRRC with rs1=0, don't write
    let should_write = match inst.funct3 {
        2 | 3 => inst.rs1 != 0,
        6 | 7 => inst.rs1 != 0,
        _ => true,
    };

    if should_write {
        // Check if CSR is read-only
        if cpu.csrs.is_read_only(csr_addr) {
            cpu.handle_exception(2, inst.raw as u64, bus); // Illegal instruction
            return true;
        }
        cpu.csrs.write(csr_addr, write_val);
        // Flush TLB when SATP changes (address space switch)
        if csr_addr == csr::SATP {
            cpu.mmu.flush_tlb();
        }
    }
    cpu.regs[inst.rd] = old_val;
    cpu.pc += len;
    true
}

/// Handle SBI (Supervisor Binary Interface) calls from S-mode.
/// Uses the RISC-V SBI specification:
///   a7 = extension ID (EID), a6 = function ID (FID)
///   a0-a5 = arguments
///   Returns: a0 = error code, a1 = value
/// Returns true if handled, false to fall through to normal ecall.
fn handle_sbi_call(cpu: &mut Cpu, bus: &mut Bus) -> bool {
    let eid = cpu.regs[17]; // a7
    let fid = cpu.regs[16]; // a6
    let a0 = cpu.regs[10];
    // SBI return: a0 = error, a1 = value
    // SBI_SUCCESS = 0, SBI_ERR_NOT_SUPPORTED = -2

    match eid {
        // Legacy SBI extensions (deprecated but Linux still uses them early)
        0x00 => {
            // sbi_set_timer (legacy)
            bus.clint.mtimecmp = a0;
            // Clear STIP when timer is set
            let mip = cpu.csrs.read(csr::MIP);
            cpu.csrs.write(csr::MIP, mip & !(1 << 5));
            cpu.regs[10] = 0; // success
            true
        }
        0x01 => {
            // sbi_console_putchar (legacy)
            let ch = a0 as u8;
            use std::io::Write;
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&[ch]);
            let _ = stdout.flush();
            cpu.regs[10] = 0;
            true
        }
        0x02 => {
            // sbi_console_getchar (legacy)
            // Return -1 if no char available
            cpu.regs[10] = (-1i64) as u64;
            true
        }
        0x08 => {
            // sbi_shutdown (legacy)
            log::info!("SBI shutdown requested");
            false // Let it trap, will cause halt
        }

        // SBI v0.2+ extensions
        0x10 => {
            // Base extension
            match fid {
                0 => {
                    // sbi_get_spec_version
                    cpu.regs[10] = 0; // success
                                      // SBI spec v2.0: encoding is (major << 24) | minor
                    cpu.regs[11] = 2u64 << 24;
                    true
                }
                1 => {
                    // sbi_get_impl_id
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0xFF; // custom implementation
                    true
                }
                2 => {
                    // sbi_get_impl_version
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 1;
                    true
                }
                3 => {
                    // sbi_probe_extension
                    let ext_id = a0;
                    let available = matches!(
                        ext_id,
                        0x00 | 0x01
                            | 0x02
                            | 0x10
                            | 0x54494D45
                            | 0x735049
                            | 0x48534D
                            | 0x52464E43
                            | 0x53525354
                            | 0x4442434E
                    );
                    cpu.regs[10] = 0;
                    cpu.regs[11] = if available { 1 } else { 0 };
                    true
                }
                4 => {
                    // sbi_get_mvendorid
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                5 => {
                    // sbi_get_marchid
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                6 => {
                    // sbi_get_mimpid
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                _ => {
                    cpu.regs[10] = (-2i64) as u64; // SBI_ERR_NOT_SUPPORTED
                    cpu.regs[11] = 0;
                    true
                }
            }
        }
        0x54494D45 => {
            // Timer extension (TIME)
            match fid {
                0 => {
                    // sbi_set_timer
                    bus.clint.mtimecmp = a0;
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip & !(1 << 5)); // Clear STIP
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                _ => {
                    cpu.regs[10] = (-2i64) as u64;
                    cpu.regs[11] = 0;
                    true
                }
            }
        }
        0x735049 => {
            // sPI (IPI) extension
            match fid {
                0 => {
                    // sbi_send_ipi
                    // Single-hart system, send IPI to self
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip | (1 << 1)); // Set SSIP
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                _ => {
                    cpu.regs[10] = (-2i64) as u64;
                    cpu.regs[11] = 0;
                    true
                }
            }
        }
        0x48534D => {
            // HSM (Hart State Management) extension
            match fid {
                0 => {
                    // hart_start — single hart, already started
                    cpu.regs[10] = (-1i64) as u64; // SBI_ERR_ALREADY_AVAILABLE
                    cpu.regs[11] = 0;
                    true
                }
                1 => {
                    // hart_stop — single hart, cannot stop
                    cpu.regs[10] = 0; // SBI_SUCCESS (pretend we stopped)
                    cpu.regs[11] = 0;
                    true
                }
                2 => {
                    // hart_get_status
                    cpu.regs[10] = 0; // success
                    cpu.regs[11] = 0; // STARTED
                    true
                }
                3 => {
                    // hart_suspend
                    cpu.wfi = true; // Act like WFI
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                _ => {
                    cpu.regs[10] = (-2i64) as u64;
                    cpu.regs[11] = 0;
                    true
                }
            }
        }
        0x52464E43 => {
            // RFENCE extension — remote fence operations
            // On a single-hart system these are all no-ops that succeed
            match fid {
                0 => {
                    // remote_fence_i
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                1 => {
                    // remote_sfence_vma
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                2 => {
                    // remote_sfence_vma_asid
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                _ => {
                    cpu.regs[10] = (-2i64) as u64;
                    cpu.regs[11] = 0;
                    true
                }
            }
        }
        0x53525354 => {
            // SRST (System Reset) extension
            match fid {
                0 => {
                    // system_reset
                    log::info!(
                        "SBI system reset requested (type={}, reason={})",
                        a0,
                        cpu.regs[11]
                    );
                    std::process::exit(0);
                }
                _ => {
                    cpu.regs[10] = (-2i64) as u64;
                    cpu.regs[11] = 0;
                    true
                }
            }
        }
        0x4442434E => {
            // DBCN (Debug Console) extension
            match fid {
                0 => {
                    // sbi_debug_console_write
                    // a0 = num_bytes, a1 = base_addr_lo, a2 = base_addr_hi
                    let num_bytes = a0 as usize;
                    let base_addr = cpu.regs[11]; // a1
                    use std::io::Write;
                    let mut stdout = std::io::stdout().lock();
                    for i in 0..num_bytes {
                        let phys = match cpu.mmu.translate(
                            base_addr + i as u64,
                            super::mmu::AccessType::Read,
                            cpu.mode,
                            &cpu.csrs,
                            bus,
                        ) {
                            Ok(a) => a,
                            Err(_) => {
                                cpu.regs[10] = (-1i64) as u64; // SBI_ERR_INVALID_ADDRESS
                                cpu.regs[11] = i as u64;
                                return true;
                            }
                        };
                        let byte = bus.read8(phys);
                        let _ = stdout.write_all(&[byte]);
                    }
                    let _ = stdout.flush();
                    cpu.regs[10] = 0; // SBI_SUCCESS
                    cpu.regs[11] = num_bytes as u64;
                    true
                }
                1 => {
                    // sbi_debug_console_read
                    // Not supported (no non-blocking read)
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0; // 0 bytes read
                    true
                }
                2 => {
                    // sbi_debug_console_write_byte
                    let byte = a0 as u8;
                    use std::io::Write;
                    let mut stdout = std::io::stdout().lock();
                    let _ = stdout.write_all(&[byte]);
                    let _ = stdout.flush();
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                _ => {
                    cpu.regs[10] = (-2i64) as u64;
                    cpu.regs[11] = 0;
                    true
                }
            }
        }
        0x504D55 => {
            // PMU (Performance Monitoring Unit) extension
            // Linux probes this early; return SBI_ERR_NOT_SUPPORTED for all functions
            cpu.regs[10] = (-2i64) as u64;
            cpu.regs[11] = 0;
            true
        }
        0x535553 => {
            // SUSP (System Suspend) extension
            cpu.regs[10] = (-2i64) as u64;
            cpu.regs[11] = 0;
            true
        }
        0x4E41434C => {
            // NACL (Nested Acceleration) extension
            cpu.regs[10] = (-2i64) as u64;
            cpu.regs[11] = 0;
            true
        }
        0x535441 => {
            // STA (Steal-time Accounting) extension
            cpu.regs[10] = (-2i64) as u64;
            cpu.regs[11] = 0;
            true
        }
        _ => {
            // Unknown extension — return not supported
            cpu.regs[10] = (-2i64) as u64;
            cpu.regs[11] = 0;
            true
        }
    }
}
