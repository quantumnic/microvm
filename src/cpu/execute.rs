use super::csr;
use super::decode::Instruction;
use super::mmu::AccessType;
use super::{Cpu, PrivilegeMode};
use crate::memory::Bus;

// ============================================================================
// Scalar Crypto Extensions (Zkn = Zbkb + Zbkc + Zbkx + Zknd + Zkne + Zknh)
// ============================================================================

/// AES forward S-box
pub(crate) const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES inverse S-box
pub(crate) const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// AES round constants
pub(crate) const AES_RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// GF(2^8) multiply by 2 (xtime)
fn gf_mul2(x: u8) -> u8 {
    let r = (x as u16) << 1;
    if r & 0x100 != 0 {
        (r ^ 0x11b) as u8
    } else {
        r as u8
    }
}

/// GF(2^8) multiply
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            result ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    result
}

/// AES MixColumns on a single 32-bit column
fn aes_mixcolumn(col: u32) -> u32 {
    let b0 = col as u8;
    let b1 = (col >> 8) as u8;
    let b2 = (col >> 16) as u8;
    let b3 = (col >> 24) as u8;
    let r0 = gf_mul2(b0) ^ gf_mul(b1, 3) ^ b2 ^ b3;
    let r1 = b0 ^ gf_mul2(b1) ^ gf_mul(b2, 3) ^ b3;
    let r2 = b0 ^ b1 ^ gf_mul2(b2) ^ gf_mul(b3, 3);
    let r3 = gf_mul(b0, 3) ^ b1 ^ b2 ^ gf_mul2(b3);
    r0 as u32 | (r1 as u32) << 8 | (r2 as u32) << 16 | (r3 as u32) << 24
}

/// AES InvMixColumns on a single 32-bit column
fn aes_inv_mixcolumn(col: u32) -> u32 {
    let b0 = col as u8;
    let b1 = (col >> 8) as u8;
    let b2 = (col >> 16) as u8;
    let b3 = (col >> 24) as u8;
    let r0 = gf_mul(b0, 14) ^ gf_mul(b1, 11) ^ gf_mul(b2, 13) ^ gf_mul(b3, 9);
    let r1 = gf_mul(b0, 9) ^ gf_mul(b1, 14) ^ gf_mul(b2, 11) ^ gf_mul(b3, 13);
    let r2 = gf_mul(b0, 13) ^ gf_mul(b1, 9) ^ gf_mul(b2, 14) ^ gf_mul(b3, 11);
    let r3 = gf_mul(b0, 11) ^ gf_mul(b1, 13) ^ gf_mul(b2, 9) ^ gf_mul(b3, 14);
    r0 as u32 | (r1 as u32) << 8 | (r2 as u32) << 16 | (r3 as u32) << 24
}

/// Extract byte i from a u64
fn byte_of(val: u64, i: usize) -> u8 {
    (val >> (i * 8)) as u8
}

/// AES64 forward ShiftRows selection (for computing low 64 bits)
/// rs1 = state[63:0], rs2 = state[127:64]
fn aes64_shiftrows_fwd(rs1: u64, rs2: u64) -> u64 {
    // After ShiftRows, columns 0-1 contain:
    // col0: state[0], state[5], state[10], state[15]
    // col1: state[4], state[9], state[14], state[3]
    let b0 = byte_of(rs1, 0); // state byte 0
    let b1 = byte_of(rs1, 5); // state byte 5
    let b2 = byte_of(rs2, 2); // state byte 10
    let b3 = byte_of(rs2, 7); // state byte 15
    let b4 = byte_of(rs1, 4); // state byte 4
    let b5 = byte_of(rs2, 1); // state byte 9
    let b6 = byte_of(rs2, 6); // state byte 14
    let b7 = byte_of(rs1, 3); // state byte 3
    (b0 as u64)
        | (b1 as u64) << 8
        | (b2 as u64) << 16
        | (b3 as u64) << 24
        | (b4 as u64) << 32
        | (b5 as u64) << 40
        | (b6 as u64) << 48
        | (b7 as u64) << 56
}

/// AES64 inverse ShiftRows selection (for computing low 64 bits)
fn aes64_shiftrows_inv(rs1: u64, rs2: u64) -> u64 {
    // After InvShiftRows, columns 0-1 contain:
    // col0: state[0], state[13], state[10], state[7]
    // col1: state[4], state[1], state[14], state[11]
    let b0 = byte_of(rs1, 0); // state byte 0
    let b1 = byte_of(rs2, 5); // state byte 13
    let b2 = byte_of(rs2, 2); // state byte 10
    let b3 = byte_of(rs1, 7); // state byte 7
    let b4 = byte_of(rs1, 4); // state byte 4
    let b5 = byte_of(rs1, 1); // state byte 1
    let b6 = byte_of(rs2, 6); // state byte 14
    let b7 = byte_of(rs2, 3); // state byte 11
    (b0 as u64)
        | (b1 as u64) << 8
        | (b2 as u64) << 16
        | (b3 as u64) << 24
        | (b4 as u64) << 32
        | (b5 as u64) << 40
        | (b6 as u64) << 48
        | (b7 as u64) << 56
}

/// Apply AES forward S-box to each byte of a u64
fn aes_sbox_fwd_u64(val: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..8 {
        let b = (val >> (i * 8)) as u8;
        result |= (AES_SBOX[b as usize] as u64) << (i * 8);
    }
    result
}

/// Apply AES inverse S-box to each byte of a u64
fn aes_sbox_inv_u64(val: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..8 {
        let b = (val >> (i * 8)) as u8;
        result |= (AES_INV_SBOX[b as usize] as u64) << (i * 8);
    }
    result
}

/// Apply AES forward S-box to each byte of a u32
fn aes_sbox_fwd_u32(val: u32) -> u32 {
    let b0 = AES_SBOX[val as u8 as usize] as u32;
    let b1 = AES_SBOX[(val >> 8) as u8 as usize] as u32;
    let b2 = AES_SBOX[(val >> 16) as u8 as usize] as u32;
    let b3 = AES_SBOX[(val >> 24) as u8 as usize] as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

/// Reverse bits within each byte of a u64 (brev8)
fn brev8(val: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..8 {
        let mut byte = (val >> (i * 8)) as u8;
        byte = (byte & 0xF0) >> 4 | (byte & 0x0F) << 4;
        byte = (byte & 0xCC) >> 2 | (byte & 0x33) << 2;
        byte = (byte & 0xAA) >> 1 | (byte & 0x55) << 1;
        result |= (byte as u64) << (i * 8);
    }
    result
}

/// xperm8: byte-wise lookup permutation
fn xperm8(rs1: u64, rs2: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..8 {
        let idx = (rs2 >> (i * 8)) as u8;
        if idx < 8 {
            result |= ((rs1 >> (idx as u32 * 8)) & 0xFF) << (i * 8);
        }
    }
    result
}

/// xperm4: nibble-wise lookup permutation
fn xperm4(rs1: u64, rs2: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..16 {
        let idx = (rs2 >> (i * 4)) & 0xF;
        if idx < 16 {
            result |= ((rs1 >> (idx * 4)) & 0xF) << (i * 4);
        }
    }
    result
}

/// Carry-less multiply (lower 64 bits) — Zbc extension
fn clmul(a: u64, b: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..64 {
        if (b >> i) & 1 != 0 {
            result ^= a << i;
        }
    }
    result
}

/// Carry-less multiply high (upper 64 bits) — Zbc extension
fn clmulh(a: u64, b: u64) -> u64 {
    let mut result = 0u64;
    for i in 1..64 {
        if (b >> i) & 1 != 0 {
            result ^= a >> (64 - i);
        }
    }
    result
}

/// Carry-less multiply reversed — Zbc extension
fn clmulr(a: u64, b: u64) -> u64 {
    let mut result = 0u64;
    for i in 0..64 {
        if (b >> i) & 1 != 0 {
            result ^= a >> (63 - i);
        }
    }
    result
}

/// Check if a load/store instruction (opcode 0x07/0x27) is a vector load/store.
/// Vector loads use width encodings: 0 (8-bit), 5 (16-bit), 6 (32-bit), 7 (64-bit)
/// with mew=0. FP loads use width 2 (FLW) and 3 (FLD).
fn is_vector_loadstore(raw: u32) -> bool {
    let width = (raw >> 12) & 0x7;
    let mew = (raw >> 28) & 1;
    // Vector: width 0,5,6,7 with mew=0
    mew == 0 && matches!(width, 0 | 5 | 6 | 7)
}

/// Execute a decoded instruction. Returns true to continue, false to halt.
pub fn execute(cpu: &mut Cpu, bus: &mut Bus, raw: u32, inst_len: u64) -> bool {
    let inst = Instruction::decode(raw);

    let opcode = inst.opcode;

    // Check for vector opcodes (V extension)
    if opcode == 0x57
        || opcode == 0x77
        || ((opcode == 0x07 || opcode == 0x27) && is_vector_loadstore(raw))
    {
        if !super::vector::vector_enabled(cpu) {
            cpu.handle_exception(2, raw as u64, bus);
            return true;
        }
        if super::vector::execute_vector(cpu, bus, raw, inst_len) {
            return true;
        }
    }

    // Check for floating-point opcodes first
    if matches!(opcode, 0x07 | 0x27 | 0x43 | 0x47 | 0x4B | 0x4F | 0x53) {
        // FP load/store/compute — check FS != Off
        if !cpu.csrs.fp_enabled() {
            cpu.handle_exception(2, raw as u64, bus); // Illegal when FS=Off
            return true;
        }
        if super::fpu::execute_fp(cpu, bus, raw, inst_len) {
            return true;
        }
    }

    // HPM event counting based on opcode class
    match opcode {
        0x03 | 0x07 => cpu.csrs.hpm_increment(csr::HpmEvent::Load),
        0x23 | 0x27 => cpu.csrs.hpm_increment(csr::HpmEvent::Store),
        0x63 => cpu.csrs.hpm_increment(csr::HpmEvent::Branch),
        0x2F => cpu.csrs.hpm_increment(csr::HpmEvent::Atomic),
        0x73 | 0x0F => cpu.csrs.hpm_increment(csr::HpmEvent::System),
        0x43 | 0x47 | 0x4B | 0x4F | 0x53 => cpu.csrs.hpm_increment(csr::HpmEvent::FloatingPoint),
        0x57 | 0x77 => cpu.csrs.hpm_increment(csr::HpmEvent::Vector),
        _ => {}
    }
    if inst_len == 2 {
        cpu.csrs.hpm_increment(csr::HpmEvent::Compressed);
    }

    match opcode {
        0x37 => op_lui(cpu, &inst, inst_len),
        0x17 => op_auipc(cpu, &inst, inst_len),
        0x6F => op_jal(cpu, &inst, inst_len),
        0x67 => op_jalr(cpu, &inst, inst_len),
        0x63 => op_branch(cpu, &inst, inst_len),
        0x03 => op_load(cpu, bus, &inst, inst_len),
        0x23 => op_store(cpu, bus, &inst, inst_len),
        0x13 => op_imm(cpu, &inst, inst_len),
        0x1B => op_imm32(cpu, &inst, inst_len),
        0x33 => op_reg(cpu, &inst, inst_len),
        0x3B => op_reg32(cpu, &inst, inst_len),
        0x0F => op_misc_mem(cpu, bus, &inst, inst_len),
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

fn op_jal(cpu: &mut Cpu, inst: &Instruction, inst_len: u64) {
    cpu.regs[inst.rd] = cpu.pc + inst_len; // PC+4 for 32-bit, PC+2 for compressed
    cpu.pc = cpu.pc.wrapping_add(inst.imm_j as u64);
}

fn op_jalr(cpu: &mut Cpu, inst: &Instruction, inst_len: u64) {
    let target = (cpu.regs[inst.rs1].wrapping_add(inst.imm_i as u64)) & !1;
    cpu.regs[inst.rd] = cpu.pc + inst_len; // PC+4 for 32-bit, PC+2 for compressed
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
        cpu.csrs.hpm_increment(csr::HpmEvent::BranchTaken);
        cpu.pc = cpu.pc.wrapping_add(inst.imm_b as u64);
    } else {
        cpu.pc += len;
    }
}

fn op_misc_mem(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) {
    match inst.funct3 {
        0 | 1 => {
            // FENCE (funct3=0) and FENCE.I (funct3=1) — memory ordering
        }
        2 => {
            // Zicbom / Zicboz: CBO instructions
            // The operation is encoded in bits [24:20] (rs2 field of the raw instruction)
            let cbo_op = (inst.raw >> 20) & 0x1F;

            // Permission checks based on privilege mode and menvcfg/senvcfg
            let menvcfg = cpu.csrs.read(crate::cpu::csr::MENVCFG);
            let senvcfg = cpu.csrs.read(crate::cpu::csr::SENVCFG);

            match cbo_op {
                0 => {
                    // CBO.INVAL (Zicbom) — cache block invalidate
                    // Check CBIE field (bits 5:4): 00=illegal, 01=inval, 11=flush
                    let cbie = match cpu.mode {
                        PrivilegeMode::Machine => 0b01, // Always allowed in M-mode
                        PrivilegeMode::Supervisor => (menvcfg >> 4) & 0x3,
                        PrivilegeMode::User => {
                            let m = (menvcfg >> 4) & 0x3;
                            let s = (senvcfg >> 4) & 0x3;
                            // Both must allow; effective = min(m, s) conceptually
                            if m == 0 || s == 0 {
                                0
                            } else {
                                s
                            }
                        }
                    };
                    if cbie == 0 {
                        cpu.handle_exception(2, inst.raw as u64, bus); // Illegal instruction
                        return;
                    }
                    // cbie=01: invalidate (NOP since no cache), cbie=11: flush (NOP)
                }
                1 | 2 => {
                    // CBO.CLEAN (1) / CBO.FLUSH (2) — Zicbom
                    // Check CBCFE (bit 7): 0=illegal, 1=allowed
                    let allowed = match cpu.mode {
                        PrivilegeMode::Machine => true,
                        PrivilegeMode::Supervisor => (menvcfg >> 7) & 1 == 1,
                        PrivilegeMode::User => (menvcfg >> 7) & 1 == 1 && (senvcfg >> 7) & 1 == 1,
                    };
                    if !allowed {
                        cpu.handle_exception(2, inst.raw as u64, bus);
                        return;
                    }
                    // NOP — no cache to clean/flush
                }
                4 => {
                    // CBO.ZERO (Zicboz) — zero a 64-byte cache block
                    // Check CBZE (bit 6): 0=illegal, 1=allowed
                    let allowed = match cpu.mode {
                        PrivilegeMode::Machine => true,
                        PrivilegeMode::Supervisor => (menvcfg >> 6) & 1 == 1,
                        PrivilegeMode::User => (menvcfg >> 6) & 1 == 1 && (senvcfg >> 6) & 1 == 1,
                    };
                    if !allowed {
                        cpu.handle_exception(2, inst.raw as u64, bus);
                        return;
                    }
                    let base = cpu.regs[inst.rs1];
                    let block_addr = base & !63; // Align to 64-byte block
                    if let Ok(phys) = cpu.mmu.translate(
                        block_addr,
                        crate::cpu::mmu::AccessType::Write,
                        cpu.mode,
                        &cpu.csrs,
                        bus,
                    ) {
                        for i in 0..8 {
                            bus.write64(phys + i * 8, 0);
                        }
                    } else {
                        cpu.handle_exception(15, block_addr, bus); // Store/AMO page fault
                        return;
                    }
                }
                _ => {
                    log::warn!("Unknown CBO operation {} at PC={:#x}", cbo_op, cpu.pc);
                    cpu.handle_exception(2, inst.raw as u64, bus);
                    return;
                }
            }
        }
        _ => {
            log::warn!(
                "Unknown MISC-MEM funct3={} at PC={:#x}",
                inst.funct3,
                cpu.pc
            );
            cpu.handle_exception(2, inst.raw as u64, bus);
            return;
        }
    }
    cpu.pc += len;
}

fn op_load(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) {
    let addr = cpu.regs[inst.rs1].wrapping_add(inst.imm_i as u64);
    // Sdtrig: check load watchpoints
    if cpu.triggers.has_active_triggers() {
        if let Some(super::trigger::TriggerAction::BreakpointException) =
            cpu.triggers.check_load(addr, cpu.mode)
        {
            cpu.handle_exception(3, addr, bus);
            return;
        }
    }
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
        0 => bus.read8(phys) as i8 as i64 as u64, // LB
        1 => {
            // LH — support misaligned access
            if phys & 1 != 0 {
                let lo = bus.read8(phys) as u16;
                let hi = bus.read8(phys.wrapping_add(1)) as u16;
                (lo | (hi << 8)) as i16 as i64 as u64
            } else {
                bus.read16(phys) as i16 as i64 as u64
            }
        }
        2 => {
            // LW — support misaligned access
            if phys & 3 != 0 {
                read_misaligned_u32(bus, phys) as i32 as i64 as u64
            } else {
                bus.read32(phys) as i32 as i64 as u64
            }
        }
        3 => {
            // LD — support misaligned access
            if phys & 7 != 0 {
                read_misaligned_u64(bus, phys)
            } else {
                bus.read64(phys)
            }
        }
        4 => bus.read8(phys) as u64, // LBU
        5 => {
            // LHU — support misaligned access
            if phys & 1 != 0 {
                let lo = bus.read8(phys) as u16;
                let hi = bus.read8(phys.wrapping_add(1)) as u16;
                (lo | (hi << 8)) as u64
            } else {
                bus.read16(phys) as u64
            }
        }
        6 => {
            // LWU — support misaligned access
            if phys & 3 != 0 {
                read_misaligned_u32(bus, phys) as u64
            } else {
                bus.read32(phys) as u64
            }
        }
        _ => 0,
    };
    cpu.regs[inst.rd] = val;
    cpu.pc += len;
}

/// Read a 32-bit value from a potentially misaligned address byte-by-byte
fn read_misaligned_u32(bus: &mut Bus, addr: u64) -> u32 {
    let b0 = bus.read8(addr) as u32;
    let b1 = bus.read8(addr.wrapping_add(1)) as u32;
    let b2 = bus.read8(addr.wrapping_add(2)) as u32;
    let b3 = bus.read8(addr.wrapping_add(3)) as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

/// Read a 64-bit value from a potentially misaligned address byte-by-byte
fn read_misaligned_u64(bus: &mut Bus, addr: u64) -> u64 {
    let lo = read_misaligned_u32(bus, addr) as u64;
    let hi = read_misaligned_u32(bus, addr.wrapping_add(4)) as u64;
    lo | (hi << 32)
}

fn op_store(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) {
    let addr = cpu.regs[inst.rs1].wrapping_add(inst.imm_s as u64);
    // Sdtrig: check store watchpoints
    if cpu.triggers.has_active_triggers() {
        if let Some(super::trigger::TriggerAction::BreakpointException) =
            cpu.triggers.check_store(addr, cpu.mode)
        {
            cpu.handle_exception(3, addr, bus);
            return;
        }
    }
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
        1 => {
            // SH — support misaligned access
            if phys & 1 != 0 {
                bus.write8(phys, val as u8);
                bus.write8(phys.wrapping_add(1), (val >> 8) as u8);
            } else {
                bus.write16(phys, val as u16);
            }
        }
        2 => {
            // SW — support misaligned access
            if phys & 3 != 0 {
                write_misaligned_u32(bus, phys, val as u32);
            } else {
                bus.write32(phys, val as u32);
            }
        }
        3 => {
            // SD — support misaligned access
            if phys & 7 != 0 {
                write_misaligned_u64(bus, phys, val);
            } else {
                bus.write64(phys, val);
            }
        }
        _ => {}
    }
    cpu.pc += len;
}

/// Write a 32-bit value to a potentially misaligned address byte-by-byte
fn write_misaligned_u32(bus: &mut Bus, addr: u64, val: u32) {
    bus.write8(addr, val as u8);
    bus.write8(addr.wrapping_add(1), (val >> 8) as u8);
    bus.write8(addr.wrapping_add(2), (val >> 16) as u8);
    bus.write8(addr.wrapping_add(3), (val >> 24) as u8);
}

/// Write a 64-bit value to a potentially misaligned address byte-by-byte
fn write_misaligned_u64(bus: &mut Bus, addr: u64, val: u64) {
    write_misaligned_u32(bus, addr, val as u32);
    write_misaligned_u32(bus, addr.wrapping_add(4), (val >> 32) as u32);
}

fn op_imm(cpu: &mut Cpu, inst: &Instruction, len: u64) {
    let rs1 = cpu.regs[inst.rs1];
    let imm = inst.imm_i as u64;
    let shamt = (imm & 0x3F) as u32;
    let funct7 = inst.funct7;
    let val = match inst.funct3 {
        0 => rs1.wrapping_add(imm), // ADDI
        1 => {
            // SLLI, Zbb count instructions, Zbs immediate instructions, Zkn crypto
            let top6 = (inst.raw >> 26) & 0x3F;
            match (funct7, inst.rs2) {
                (0x30, 0x00) => rs1.leading_zeros() as u64,        // CLZ
                (0x30, 0x01) => rs1.trailing_zeros() as u64,       // CTZ
                (0x30, 0x02) => rs1.count_ones() as u64,           // CPOP
                (0x30, 0x04) => (rs1 as u8 as i8) as i64 as u64,   // SEXT.B
                (0x30, 0x05) => (rs1 as u16 as i16) as i64 as u64, // SEXT.H
                // Zknh: SHA-256 instructions (funct7=0x08)
                (0x08, 0x00) => {
                    // SHA256SUM0
                    let x = rs1 as u32;
                    (x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)) as i32 as i64
                        as u64
                }
                (0x08, 0x01) => {
                    // SHA256SUM1
                    let x = rs1 as u32;
                    (x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)) as i32 as i64
                        as u64
                }
                (0x08, 0x02) => {
                    // SHA256SIG0
                    let x = rs1 as u32;
                    (x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)) as i32 as i64 as u64
                }
                (0x08, 0x03) => {
                    // SHA256SIG1
                    let x = rs1 as u32;
                    (x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)) as i32 as i64 as u64
                }
                // Zknh: SHA-512 instructions (funct7=0x08)
                (0x08, 0x04) => {
                    // SHA512SUM0
                    rs1.rotate_right(28) ^ rs1.rotate_right(34) ^ rs1.rotate_right(39)
                }
                (0x08, 0x05) => {
                    // SHA512SUM1
                    rs1.rotate_right(14) ^ rs1.rotate_right(18) ^ rs1.rotate_right(41)
                }
                (0x08, 0x06) => {
                    // SHA512SIG0
                    rs1.rotate_right(1) ^ rs1.rotate_right(8) ^ (rs1 >> 7)
                }
                (0x08, 0x07) => {
                    // SHA512SIG1
                    rs1.rotate_right(19) ^ rs1.rotate_right(61) ^ (rs1 >> 6)
                }
                // Zknd: AES64IM (InvMixColumns for key schedule)
                (0x18, 0x00) => {
                    // AES64IM rd, rs1
                    let lo = aes_inv_mixcolumn(rs1 as u32);
                    let hi = aes_inv_mixcolumn((rs1 >> 32) as u32);
                    lo as u64 | (hi as u64) << 32
                }
                (0x18, rs2_val) if rs2_val & 0x10 != 0 => {
                    // AES64KS1I rd, rs1, rnum — key schedule constant
                    let rnum = rs2_val & 0xF;
                    let w = (rs1 >> 32) as u32; // high 32 bits of rs1
                    let sub = if rnum < 10 {
                        // RotWord + SubWord + rcon
                        let rotated = w.rotate_right(8);
                        aes_sbox_fwd_u32(rotated) ^ (AES_RCON[rnum + 1] as u32)
                    } else {
                        // rnum == 10: SubWord only (no rotate, no rcon)
                        aes_sbox_fwd_u32(w)
                    };
                    sub as u64 | (sub as u64) << 32
                }
                _ => match top6 {
                    0x09 => rs1 & !(1u64 << shamt), // BCLRI (Zbs)
                    0x05 => rs1 | (1u64 << shamt),  // BSETI (Zbs)
                    0x0D => rs1 ^ (1u64 << shamt),  // BINVI (Zbs)
                    _ => rs1 << shamt,              // SLLI
                },
            }
        }
        2 => ((rs1 as i64) < (imm as i64)) as u64, // SLTI
        3 => (rs1 < imm) as u64,                   // SLTIU
        4 => rs1 ^ imm,                            // XORI
        5 => {
            // Use top 6 bits (funct6) for shift disambiguation:
            // bits[31:26] distinguish SRLI/SRAI/RORI etc.
            // bit 25 is part of the 6-bit shamt, not the function code.
            let top6 = (inst.raw >> 26) & 0x3F;
            match top6 {
                0x10 => ((rs1 as i64) >> shamt) as u64, // SRAI (funct6=010000)
                0x12 => (rs1 >> shamt) & 1,             // BEXTI (Zbs, funct6=010010)
                0x18 => rs1.rotate_right(shamt),        // RORI (Zbb, funct6=011000)
                _ => {
                    // Check for REV8 and ORC.B by full funct12
                    let funct12 = (inst.raw >> 20) & 0xFFF;
                    match funct12 {
                        0x6B8 => rs1.swap_bytes(), // REV8 (Zbb, RV64)
                        0x687 => brev8(rs1),       // BREV8 (Zbkb)
                        0x287 => {
                            // ORC.B (Zbb)
                            let mut result = 0u64;
                            for i in 0..8 {
                                let byte = (rs1 >> (i * 8)) & 0xFF;
                                if byte != 0 {
                                    result |= 0xFF << (i * 8);
                                }
                            }
                            result
                        }
                        _ => rs1 >> shamt, // SRLI
                    }
                }
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
    let funct7 = inst.funct7;
    let val = match inst.funct3 {
        0 => rs1.wrapping_add(imm) as i32 as i64 as u64, // ADDIW
        1 => {
            match funct7 {
                0x30 => {
                    match inst.rs2 {
                        0x00 => rs1.leading_zeros() as i32 as i64 as u64, // CLZW (Zbb)
                        0x01 => rs1.trailing_zeros() as i32 as i64 as u64, // CTZW (Zbb)
                        0x02 => rs1.count_ones() as i32 as i64 as u64,    // CPOPW (Zbb)
                        _ => (rs1 << shamt) as i32 as i64 as u64,
                    }
                }
                0x04 => {
                    // SLLI.UW (Zba): shift rs1[31:0] left by shamt, zero-extend
                    let rs1_full = cpu.regs[inst.rs1] as u32 as u64;
                    rs1_full << shamt
                }
                _ => (rs1 << shamt) as i32 as i64 as u64, // SLLIW
            }
        }
        5 => {
            let top7 = (inst.raw >> 25) & 0x7F;
            match top7 {
                0x20 => ((rs1 as i32) >> shamt) as i64 as u64, // SRAIW
                0x30 => rs1.rotate_right(shamt) as i32 as i64 as u64, // RORIW (Zbb)
                _ => (rs1 >> shamt) as i32 as i64 as u64,      // SRLIW
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
            // Zba: address generation
            (2, 0x10) => rs1.wrapping_add(rs2 << 1), // SH1ADD
            (4, 0x10) => rs1.wrapping_add(rs2 << 2), // SH2ADD
            (6, 0x10) => rs1.wrapping_add(rs2 << 3), // SH3ADD
            // Zbb: basic bit manipulation
            (7, 0x20) => rs1 & !rs2,   // ANDN
            (6, 0x20) => rs1 | !rs2,   // ORN
            (4, 0x20) => !(rs1 ^ rs2), // XNOR
            (4, 0x05) => std::cmp::min(rs1 as i64, rs2 as i64) as u64, // MIN
            (5, 0x05) => std::cmp::min(rs1, rs2), // MINU
            (6, 0x05) => std::cmp::max(rs1 as i64, rs2 as i64) as u64, // MAX
            (7, 0x05) => std::cmp::max(rs1, rs2), // MAXU
            (1, 0x30) => rs1.rotate_left((rs2 & 0x3F) as u32), // ROL
            (5, 0x30) => rs1.rotate_right((rs2 & 0x3F) as u32), // ROR
            // Zbs: single-bit manipulation
            (1, 0x24) => rs1 & !(1u64 << (rs2 & 0x3F)), // BCLR
            (1, 0x14) => rs1 | (1u64 << (rs2 & 0x3F)),  // BSET
            (1, 0x34) => rs1 ^ (1u64 << (rs2 & 0x3F)),  // BINV
            (5, 0x24) => (rs1 >> (rs2 & 0x3F)) & 1,     // BEXT
            // Zbc: carry-less multiplication
            (1, 0x05) => clmul(rs1, rs2),  // CLMUL
            (3, 0x05) => clmulh(rs1, rs2), // CLMULH
            (2, 0x05) => clmulr(rs1, rs2), // CLMULR
            // Zbkb: pack instructions
            (4, 0x04) => (rs1 & 0xFFFF_FFFF) | (rs2 << 32), // PACK
            (7, 0x04) => (rs1 & 0xFF) | ((rs2 & 0xFF) << 8), // PACKH
            // Zbkx: crossbar permutations
            (2, 0x14) => xperm4(rs1, rs2), // XPERM4
            (4, 0x14) => xperm8(rs1, rs2), // XPERM8
            // Zkne: AES encrypt
            (0, 0x19) => {
                // AES64ES — SubBytes after ShiftRows
                let sr = aes64_shiftrows_fwd(rs1, rs2);
                aes_sbox_fwd_u64(sr)
            }
            (0, 0x1B) => {
                // AES64ESM — SubBytes + MixColumns after ShiftRows
                let sr = aes64_shiftrows_fwd(rs1, rs2);
                let sb = aes_sbox_fwd_u64(sr);
                let lo = aes_mixcolumn(sb as u32);
                let hi = aes_mixcolumn((sb >> 32) as u32);
                lo as u64 | (hi as u64) << 32
            }
            // Zknd: AES decrypt
            (0, 0x1D) => {
                // AES64DS — InvSubBytes after InvShiftRows
                let sr = aes64_shiftrows_inv(rs1, rs2);
                aes_sbox_inv_u64(sr)
            }
            (0, 0x1F) => {
                // AES64DSM — InvSubBytes + InvMixColumns after InvShiftRows
                let sr = aes64_shiftrows_inv(rs1, rs2);
                let sb = aes_sbox_inv_u64(sr);
                let lo = aes_inv_mixcolumn(sb as u32);
                let hi = aes_inv_mixcolumn((sb >> 32) as u32);
                lo as u64 | (hi as u64) << 32
            }
            // Zkne/Zknd: AES key schedule
            (0, 0x3F) => {
                // AES64KS2 rd, rs1, rs2
                let lo = (rs1 as u32) ^ (rs2 >> 32) as u32;
                let hi = lo ^ (rs1 >> 32) as u32;
                lo as u64 | (hi as u64) << 32
            }
            // Zicond: conditional operations
            (5, 0x07) => {
                if rs2 == 0 {
                    0
                } else {
                    rs1
                } // CZERO.EQZ
            }
            (7, 0x07) => {
                if rs2 != 0 {
                    0
                } else {
                    rs1
                } // CZERO.NEZ
            }
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
            // Zba: address generation (W variants — zero-extend rs1 to 32 bits, add rs2)
            (2, 0x10) => {
                let r1_zext = cpu.regs[inst.rs1] as u32 as u64;
                (r1_zext << 1).wrapping_add(cpu.regs[inst.rs2]) // SH1ADD.UW
            }
            (4, 0x10) => {
                let r1_zext = cpu.regs[inst.rs1] as u32 as u64;
                (r1_zext << 2).wrapping_add(cpu.regs[inst.rs2]) // SH2ADD.UW
            }
            (6, 0x10) => {
                let r1_zext = cpu.regs[inst.rs1] as u32 as u64;
                (r1_zext << 3).wrapping_add(cpu.regs[inst.rs2]) // SH3ADD.UW
            }
            (0, 0x04) => (cpu.regs[inst.rs1] as u32 as u64).wrapping_add(cpu.regs[inst.rs2]), // ADD.UW (Zba)
            // Zbb: 32-bit rotate
            (1, 0x30) => rs1.rotate_left(rs2 & 0x1F) as i32 as i64 as u64, // ROLW
            (5, 0x30) => rs1.rotate_right(rs2 & 0x1F) as i32 as i64 as u64, // RORW
            // Zbkb: PACKW — pack low 16 bits of each source into 32-bit result
            (4, 0x04) => ((rs1 & 0xFFFF) | ((rs2 & 0xFFFF) << 16)) as i32 as i64 as u64,
            // Note: Zbb ZEXT.H is the same encoding (funct7=0x04, funct3=4, rs2=0)
            // When rs2=0, PACKW produces rs1[15:0] sign-extended — equivalent to ZEXT.H
            _ => 0,
        }
    };
    cpu.regs[inst.rd] = val;
    cpu.pc += len;
}

fn op_atomic(cpu: &mut Cpu, bus: &mut Bus, inst: &Instruction, len: u64) {
    let funct5 = inst.funct7 >> 2;
    let addr = cpu.regs[inst.rs1];

    // Zabha: byte (funct3=0) and halfword (funct3=1) atomics
    if inst.funct3 == 0 || inst.funct3 == 1 {
        op_atomic_bh(cpu, bus, inst, len, funct5, addr);
        return;
    }

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
            if val != 0 {
                log::debug!(
                    "LR at vaddr={:#x} phys={:#x} val={:#x} (word={})",
                    addr,
                    phys,
                    val,
                    is_word
                );
            }
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
        0x05 => {
            // AMOCAS (Zacas) — atomic compare-and-swap
            let old = if is_word {
                bus.read32(phys) as i32 as i64 as u64
            } else {
                bus.read64(phys)
            };
            let compare = if is_word {
                cpu.regs[inst.rd] as u32 as u64
            } else {
                cpu.regs[inst.rd]
            };
            if old == compare {
                let swap = cpu.regs[inst.rs2];
                if is_word {
                    bus.write32(phys, swap as u32);
                } else {
                    bus.write64(phys, swap);
                }
            }
            cpu.regs[inst.rd] = if is_word {
                old as i32 as i64 as u64
            } else {
                old
            };
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

/// Zabha: byte and halfword atomic operations
fn op_atomic_bh(
    cpu: &mut Cpu,
    bus: &mut Bus,
    inst: &Instruction,
    len: u64,
    funct5: u32,
    addr: u64,
) {
    let is_byte = inst.funct3 == 0;

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

    let old: u64 = if is_byte {
        bus.read8(phys) as u64
    } else {
        bus.read16(phys) as u64
    };

    // Sign-extend for rd
    let old_sext: u64 = if is_byte {
        old as u8 as i8 as i64 as u64
    } else {
        old as u16 as i16 as i64 as u64
    };

    match funct5 {
        0x05 => {
            // AMOCAS.B / AMOCAS.H (Zacas + Zabha)
            let compare = if is_byte {
                cpu.regs[inst.rd] as u8 as u64
            } else {
                cpu.regs[inst.rd] as u16 as u64
            };
            if old == compare {
                let swap = cpu.regs[inst.rs2];
                if is_byte {
                    bus.write8(phys, swap as u8);
                } else {
                    bus.write16(phys, swap as u16);
                }
            }
        }
        _ => {
            let src = cpu.regs[inst.rs2];
            let result = match funct5 {
                0x01 => src,                   // AMOSWAP
                0x00 => old.wrapping_add(src), // AMOADD
                0x04 => old ^ src,             // AMOXOR
                0x0C => old & src,             // AMOAND
                0x08 => old | src,             // AMOOR
                0x10 => {
                    // AMOMIN (signed)
                    if is_byte {
                        std::cmp::min(old as u8 as i8, src as i8) as u8 as u64
                    } else {
                        std::cmp::min(old as u16 as i16, src as i16) as u16 as u64
                    }
                }
                0x14 => {
                    // AMOMAX (signed)
                    if is_byte {
                        std::cmp::max(old as u8 as i8, src as i8) as u8 as u64
                    } else {
                        std::cmp::max(old as u16 as i16, src as i16) as u16 as u64
                    }
                }
                0x18 => {
                    // AMOMINU (unsigned)
                    if is_byte {
                        std::cmp::min(old as u8, src as u8) as u64
                    } else {
                        std::cmp::min(old as u16, src as u16) as u64
                    }
                }
                0x1C => {
                    // AMOMAXU (unsigned)
                    if is_byte {
                        std::cmp::max(old as u8, src as u8) as u64
                    } else {
                        std::cmp::max(old as u16, src as u16) as u64
                    }
                }
                _ => old,
            };
            if is_byte {
                bus.write8(phys, result as u8);
            } else {
                bus.write16(phys, result as u16);
            }
        }
    }
    cpu.regs[inst.rd] = old_sext;
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
            0x00D00073 => {
                // WRS.NTO (Zawrs) — wait on reservation set, non-timeout
                // Hint: wait until reservation set is invalidated. NOP in emulator.
                cpu.pc += len;
                return true;
            }
            0x01D00073 => {
                // WRS.STO (Zawrs) — wait on reservation set, short timeout
                // Hint: wait with bounded time. NOP in emulator.
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

    // Zimop: May-Be-Operations (funct3 = 4)
    if inst.funct3 == 4 {
        let f7 = inst.funct7;
        let rs2_field = (inst.raw >> 20) & 0x1F;
        // MOP.R.n:  funct7 pattern 1_n4_00_n3n2_0, rs2[4:2]=111
        // MOP.RR.n: funct7 pattern 1_n2_00_n1n0_1
        let is_mop_r = (f7 & 0x59) == 0x40 && (rs2_field & 0x1C) == 0x1C;
        let is_mop_rr = (f7 & 0x59) == 0x41;
        if is_mop_r || is_mop_rr {
            // MOP: write zero to rd
            cpu.regs[inst.rd] = 0;
            cpu.regs[0] = 0;
            cpu.pc += len;
            return true;
        }
        // Unknown funct3=4 SYSTEM instruction
        log::warn!(
            "Unknown SYSTEM funct3=4 instruction: {:#010x} at PC={:#x}",
            inst.raw,
            cpu.pc
        );
        cpu.handle_exception(2, inst.raw as u64, bus);
        return true;
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

    // Smstateen: check sstateen* accessibility from S-mode
    if matches!(
        csr_addr,
        csr::SSTATEEN0 | csr::SSTATEEN1 | csr::SSTATEEN2 | csr::SSTATEEN3
    ) && !cpu.csrs.stateen_accessible(csr_addr, cpu.mode)
    {
        cpu.handle_exception(2, inst.raw as u64, bus); // Illegal instruction
        return true;
    }

    // Sdtrig: route trigger CSRs through trigger module
    let old_val = match csr_addr {
        0x7A0..=0x7A4 => cpu.triggers.read_csr(csr_addr),
        _ => cpu.csrs.read(csr_addr),
    };

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
        // Sdtrig: route trigger CSR writes through trigger module
        match csr_addr {
            0x7A0..=0x7A4 => cpu.triggers.write_csr(csr_addr, write_val, cpu.mode),
            _ => cpu.csrs.write(csr_addr, write_val),
        }
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
/// Get human-readable name for SBI extension ID
fn sbi_ext_name(eid: u64) -> &'static str {
    match eid {
        0x00 => "legacy:set_timer",
        0x01 => "legacy:putchar",
        0x02 => "legacy:getchar",
        0x08 => "legacy:shutdown",
        0x10 => "base",
        0x54494D45 => "TIME",
        0x735049 => "sPI",
        0x48534D => "HSM",
        0x52464E43 => "RFNC",
        0x53525354 => "SRST",
        0x4442434E => "DBCN",
        0x504D55 => "PMU",
        0x535553 => "SUSP",
        0x4E41434C => "NACL",
        0x535441 => "STA",
        0x43505043 => "CPPC",
        0x46574654 => "FWFT",
        _ => "unknown",
    }
}

fn handle_sbi_call(cpu: &mut Cpu, bus: &mut Bus) -> bool {
    let eid = cpu.regs[17]; // a7
    let fid = cpu.regs[16]; // a6
    cpu.last_sbi = Some((eid, fid));
    let a0 = cpu.regs[10];
    // SBI return: a0 = error, a1 = value
    // SBI_SUCCESS = 0, SBI_ERR_NOT_SUPPORTED = -2

    log::debug!(
        "SBI call: {}(eid={:#x}, fid={}, a0={:#x}) at PC={:#x}",
        sbi_ext_name(eid),
        eid,
        fid,
        a0,
        cpu.pc
    );

    match eid {
        // Legacy SBI extensions (deprecated but Linux still uses them early)
        0x00 => {
            // sbi_set_timer (legacy)
            bus.clint.mtimecmp[cpu.hart_id as usize] = a0;
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
                    bus.clint.mtimecmp[cpu.hart_id as usize] = a0;
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
                    // sbi_send_ipi(hart_mask, hart_mask_base)
                    let hart_mask = cpu.regs[10];
                    let hart_mask_base = cpu.regs[11];
                    let base = if hart_mask_base == u64::MAX {
                        0usize
                    } else {
                        hart_mask_base as usize
                    };
                    // Set SSIP for each targeted hart via CLINT MSIP
                    // (CLINT MSIP triggers MSIP, but for SBI IPI we set SSIP directly
                    //  via the software interrupt pending bit in each hart's MIP)
                    // In our architecture, we write to CLINT msip[hart] which the
                    // VM loop translates to MSIP. For S-mode IPIs, we also set SSIP.
                    for bit in 0..64u64 {
                        if hart_mask & (1 << bit) != 0 {
                            let target = base + bit as usize;
                            if target < bus.num_harts {
                                // Set SSIP for target hart via CLINT msip
                                bus.clint.msip[target] = 1;
                            }
                        }
                    }
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
                    // hart_start(hart_id, start_addr, opaque)
                    let target_hart = cpu.regs[10] as usize;
                    let start_addr = cpu.regs[11];
                    let opaque = cpu.regs[12];
                    if target_hart >= bus.num_harts {
                        cpu.regs[10] = (-3i64) as u64; // SBI_ERR_INVALID_PARAM
                    } else {
                        // Queue the start request — VM loop will handle it
                        bus.hart_start_queue.push(crate::memory::HartStartRequest {
                            hart_id: target_hart,
                            start_addr,
                            opaque,
                        });
                        cpu.regs[10] = 0; // SBI_SUCCESS
                    }
                    cpu.regs[11] = 0;
                    true
                }
                1 => {
                    // hart_stop — stop the calling hart
                    cpu.hart_state = crate::cpu::HartState::Stopped;
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                2 => {
                    // hart_get_status(hart_id)
                    let target_hart = cpu.regs[10] as usize;
                    if target_hart >= bus.num_harts {
                        cpu.regs[10] = (-3i64) as u64; // SBI_ERR_INVALID_PARAM
                    } else if target_hart == cpu.hart_id as usize {
                        cpu.regs[10] = 0; // SBI_SUCCESS
                        cpu.regs[11] = 0; // STARTED
                    } else {
                        // Read actual hart state from bus (synced by VM loop)
                        cpu.regs[10] = 0; // SBI_SUCCESS
                        cpu.regs[11] = bus.hart_states[target_hart];
                    }
                    true
                }
                3 => {
                    // hart_suspend
                    cpu.hart_state = crate::cpu::HartState::Suspended;
                    cpu.wfi = true;
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
            // Queue TLB flush requests for target harts (processed by VM loop)
            match fid {
                0 => {
                    // remote_fence_i — icache flush (nop, we don't cache decoded insns)
                    cpu.regs[10] = 0;
                    cpu.regs[11] = 0;
                    true
                }
                1 | 2 => {
                    // remote_sfence_vma / remote_sfence_vma_asid
                    // a0 = hart_mask, a1 = hart_mask_base, a2 = start_addr, a3 = size
                    let hart_mask = cpu.regs[10];
                    let hart_mask_base = cpu.regs[11];
                    let start_addr = cpu.regs[12];
                    let size = cpu.regs[13];
                    let base = if hart_mask_base == u64::MAX {
                        0usize
                    } else {
                        hart_mask_base as usize
                    };
                    // Queue flush for each targeted hart
                    for bit in 0..64usize {
                        if hart_mask & (1u64 << bit) != 0 {
                            let target = base + bit;
                            if target < bus.num_harts {
                                let req = crate::memory::TlbFlushRequest {
                                    hart_id: target,
                                    start_addr: if size == 0 || size == u64::MAX {
                                        None
                                    } else {
                                        Some(start_addr)
                                    },
                                    size,
                                };
                                bus.tlb_flush_queue.push(req);
                            }
                        }
                    }
                    // Also flush calling hart's TLB (caller may be in the mask)
                    cpu.mmu.flush_tlb();
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
                    // Per SBI spec: base_addr is a PHYSICAL address (not virtual)
                    let num_bytes = a0 as usize;
                    let base_addr = cpu.regs[11] | (cpu.regs[12] << 32); // a1 | (a2 << 32)
                    use std::io::Write;
                    let mut stdout = std::io::stdout().lock();
                    for i in 0..num_bytes {
                        let phys = base_addr + i as u64;
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
        0x43505043 => {
            // CPPC (Collaborative Processor Performance Control) extension
            cpu.regs[10] = (-2i64) as u64;
            cpu.regs[11] = 0;
            true
        }
        0x46574654 => {
            // FWFT (Firmware Features) extension
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
