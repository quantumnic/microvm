/// Instruction fields
#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub raw: u32,
    pub opcode: u32,
    pub rd: usize,
    pub rs1: usize,
    pub rs2: usize,
    pub funct3: u32,
    pub funct7: u32,
    pub imm_i: i64,
    pub imm_s: i64,
    pub imm_b: i64,
    pub imm_u: i64,
    pub imm_j: i64,
}

impl Instruction {
    pub fn decode(raw: u32) -> Self {
        let opcode = raw & 0x7F;
        let rd = ((raw >> 7) & 0x1F) as usize;
        let funct3 = (raw >> 12) & 0x7;
        let rs1 = ((raw >> 15) & 0x1F) as usize;
        let rs2 = ((raw >> 20) & 0x1F) as usize;
        let funct7 = (raw >> 25) & 0x7F;

        // I-type immediate
        let imm_i = ((raw as i32) >> 20) as i64;

        // S-type immediate
        let imm_s = ((((raw >> 25) & 0x7F) as i32) << 5 | ((raw >> 7) & 0x1F) as i32) as i64;
        let imm_s = ((imm_s << 20) as i32 >> 20) as i64; // sign-extend from 12 bits

        // B-type immediate
        let imm_b = {
            let b12 = (raw >> 31) & 1;
            let b11 = (raw >> 7) & 1;
            let b10_5 = (raw >> 25) & 0x3F;
            let b4_1 = (raw >> 8) & 0xF;
            let imm = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
            (((imm as i32) << 19) >> 19) as i64
        };

        // U-type immediate
        let imm_u = (raw & 0xFFFFF000) as i32 as i64;

        // J-type immediate
        let imm_j = {
            let b20 = (raw >> 31) & 1;
            let b19_12 = (raw >> 12) & 0xFF;
            let b11 = (raw >> 20) & 1;
            let b10_1 = (raw >> 21) & 0x3FF;
            let imm = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
            (((imm as i32) << 11) >> 11) as i64
        };

        Self {
            raw,
            opcode,
            rd,
            rs1,
            rs2,
            funct3,
            funct7,
            imm_i,
            imm_s,
            imm_b,
            imm_u,
            imm_j,
        }
    }
}

/// Expand a 16-bit compressed instruction to 32-bit equivalent
/// Returns the expanded 32-bit instruction, or 0 (illegal) if unknown
pub fn expand_compressed(inst: u32) -> u32 {
    let op = inst & 0x3;
    let funct3 = (inst >> 13) & 0x7;

    match op {
        0 => match funct3 {
            0 => expand_c_addi4spn(inst),
            2 => expand_c_lw(inst),
            3 => expand_c_ld(inst),
            6 => expand_c_sw(inst),
            7 => expand_c_sd(inst),
            _ => 0,
        },
        1 => match funct3 {
            0 => expand_c_addi(inst),
            1 => expand_c_addiw(inst),
            2 => expand_c_li(inst),
            3 => {
                let rd = (inst >> 7) & 0x1F;
                if rd == 2 {
                    expand_c_addi16sp(inst)
                } else {
                    expand_c_lui(inst)
                }
            }
            4 => expand_c_alu(inst),
            5 => expand_c_j(inst),
            6 => expand_c_beqz(inst),
            7 => expand_c_bnez(inst),
            _ => 0,
        },
        2 => match funct3 {
            0 => expand_c_slli(inst),
            2 => expand_c_lwsp(inst),
            3 => expand_c_ldsp(inst),
            4 => expand_c_jr_mv_add(inst),
            6 => expand_c_swsp(inst),
            7 => expand_c_sdsp(inst),
            _ => 0,
        },
        _ => 0,
    }
}

fn c_rd_prime(inst: u32) -> u32 { ((inst >> 2) & 0x7) + 8 }
fn c_rs1_prime(inst: u32) -> u32 { ((inst >> 7) & 0x7) + 8 }

fn expand_c_addi4spn(inst: u32) -> u32 {
    let nzuimm = ((inst >> 6) & 0x1) << 2
        | ((inst >> 5) & 0x1) << 3
        | ((inst >> 11) & 0x3) << 4
        | ((inst >> 7) & 0xF) << 6;
    if nzuimm == 0 { return 0; }
    let rd = c_rd_prime(inst);
    // ADDI rd', x2, nzuimm
    (nzuimm << 20) | (2 << 15) | (0 << 12) | (rd << 7) | 0x13
}

fn expand_c_lw(inst: u32) -> u32 {
    let offset = ((inst >> 6) & 0x1) << 2
        | ((inst >> 10) & 0x7) << 3
        | ((inst >> 5) & 0x1) << 6;
    let rs1 = c_rs1_prime(inst);
    let rd = c_rd_prime(inst);
    (offset << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x03
}

fn expand_c_ld(inst: u32) -> u32 {
    let offset = ((inst >> 10) & 0x7) << 3
        | ((inst >> 5) & 0x3) << 6;
    let rs1 = c_rs1_prime(inst);
    let rd = c_rd_prime(inst);
    (offset << 20) | (rs1 << 15) | (3 << 12) | (rd << 7) | 0x03
}

fn expand_c_sw(inst: u32) -> u32 {
    let offset = ((inst >> 6) & 0x1) << 2
        | ((inst >> 10) & 0x7) << 3
        | ((inst >> 5) & 0x1) << 6;
    let rs1 = c_rs1_prime(inst);
    let rs2 = c_rd_prime(inst);
    let imm11_5 = (offset >> 5) & 0x7F;
    let imm4_0 = offset & 0x1F;
    (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | (imm4_0 << 7) | 0x23
}

fn expand_c_sd(inst: u32) -> u32 {
    let offset = ((inst >> 10) & 0x7) << 3
        | ((inst >> 5) & 0x3) << 6;
    let rs1 = c_rs1_prime(inst);
    let rs2 = c_rd_prime(inst);
    let imm11_5 = (offset >> 5) & 0x7F;
    let imm4_0 = offset & 0x1F;
    (imm11_5 << 25) | (rs2 << 20) | (rs1 << 15) | (3 << 12) | (imm4_0 << 7) | 0x23
}

fn expand_c_addi(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let imm = (((inst >> 12) & 0x1) << 5) | ((inst >> 2) & 0x1F);
    let imm = ((imm as i32) << 26 >> 26) as u32;
    ((imm & 0xFFF) << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x13
}

fn expand_c_addiw(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let imm = (((inst >> 12) & 0x1) << 5) | ((inst >> 2) & 0x1F);
    let imm = ((imm as i32) << 26 >> 26) as u32;
    ((imm & 0xFFF) << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x1B
}

fn expand_c_li(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let imm = (((inst >> 12) & 0x1) << 5) | ((inst >> 2) & 0x1F);
    let imm = ((imm as i32) << 26 >> 26) as u32;
    ((imm & 0xFFF) << 20) | (0 << 15) | (0 << 12) | (rd << 7) | 0x13
}

fn expand_c_addi16sp(inst: u32) -> u32 {
    let imm = (((inst >> 12) & 0x1) << 9)
        | (((inst >> 6) & 0x1) << 4)
        | (((inst >> 5) & 0x1) << 6)
        | (((inst >> 3) & 0x3) << 7)
        | (((inst >> 2) & 0x1) << 5);
    let imm = ((imm as i32) << 22 >> 22) as u32;
    ((imm & 0xFFF) << 20) | (2 << 15) | (0 << 12) | (2 << 7) | 0x13
}

fn expand_c_lui(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let imm = (((inst >> 12) & 0x1) << 17) | (((inst >> 2) & 0x1F) << 12);
    let imm = ((imm as i32) << 14 >> 14) as u32;
    (imm & 0xFFFFF000) | (rd << 7) | 0x37
}

fn expand_c_alu(inst: u32) -> u32 {
    let funct2 = (inst >> 10) & 0x3;
    let rd = c_rs1_prime(inst);
    let rs2 = c_rd_prime(inst);

    match funct2 {
        0 => { // C.SRLI
            let shamt = (((inst >> 12) & 0x1) << 5) | ((inst >> 2) & 0x1F);
            (shamt << 20) | (rd << 15) | (5 << 12) | (rd << 7) | 0x13
        }
        1 => { // C.SRAI
            let shamt = (((inst >> 12) & 0x1) << 5) | ((inst >> 2) & 0x1F);
            ((0x20 << 25) | (shamt << 20) | (rd << 15) | (5 << 12) | (rd << 7) | 0x13)
        }
        2 => { // C.ANDI
            let imm = (((inst >> 12) & 0x1) << 5) | ((inst >> 2) & 0x1F);
            let imm = ((imm as i32) << 26 >> 26) as u32;
            ((imm & 0xFFF) << 20) | (rd << 15) | (7 << 12) | (rd << 7) | 0x13
        }
        3 => {
            let funct1 = (inst >> 12) & 0x1;
            let funct2b = (inst >> 5) & 0x3;
            match (funct1, funct2b) {
                (0, 0) => (0x20 << 25) | (rs2 << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x33, // C.SUB
                (0, 1) => (rs2 << 20) | (rd << 15) | (4 << 12) | (rd << 7) | 0x33, // C.XOR
                (0, 2) => (rs2 << 20) | (rd << 15) | (6 << 12) | (rd << 7) | 0x33, // C.OR
                (0, 3) => (rs2 << 20) | (rd << 15) | (7 << 12) | (rd << 7) | 0x33, // C.AND
                (1, 0) => (0x20 << 25) | (rs2 << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x3B, // C.SUBW
                (1, 1) => (rs2 << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x3B, // C.ADDW
                _ => 0,
            }
        }
        _ => 0,
    }
}

fn expand_c_j(inst: u32) -> u32 {
    let imm = (((inst >> 12) & 0x1) << 11)
        | (((inst >> 11) & 0x1) << 4)
        | (((inst >> 9) & 0x3) << 8)
        | (((inst >> 8) & 0x1) << 10)
        | (((inst >> 7) & 0x1) << 6)
        | (((inst >> 6) & 0x1) << 7)
        | (((inst >> 3) & 0x7) << 1)
        | (((inst >> 2) & 0x1) << 5);
    let imm = ((imm as i32) << 20 >> 20) as u32;
    // JAL x0, imm
    let b20 = (imm >> 20) & 1;
    let b10_1 = (imm >> 1) & 0x3FF;
    let b11 = (imm >> 11) & 1;
    let b19_12 = (imm >> 12) & 0xFF;
    (b20 << 31) | (b10_1 << 21) | (b11 << 20) | (b19_12 << 12) | (0 << 7) | 0x6F
}

fn expand_c_beqz(inst: u32) -> u32 {
    let rs1 = c_rs1_prime(inst);
    let imm = (((inst >> 12) & 0x1) << 8)
        | (((inst >> 10) & 0x3) << 3)
        | (((inst >> 5) & 0x3) << 6)
        | (((inst >> 3) & 0x3) << 1)
        | (((inst >> 2) & 0x1) << 5);
    let imm = ((imm as i32) << 23 >> 23) as u32;
    let b12 = (imm >> 12) & 1;
    let b11 = (imm >> 11) & 1;
    let b10_5 = (imm >> 5) & 0x3F;
    let b4_1 = (imm >> 1) & 0xF;
    (b12 << 31) | (b10_5 << 25) | (0 << 20) | (rs1 << 15) | (0 << 12) | (b4_1 << 8) | (b11 << 7) | 0x63
}

fn expand_c_bnez(inst: u32) -> u32 {
    let rs1 = c_rs1_prime(inst);
    let imm = (((inst >> 12) & 0x1) << 8)
        | (((inst >> 10) & 0x3) << 3)
        | (((inst >> 5) & 0x3) << 6)
        | (((inst >> 3) & 0x3) << 1)
        | (((inst >> 2) & 0x1) << 5);
    let imm = ((imm as i32) << 23 >> 23) as u32;
    let b12 = (imm >> 12) & 1;
    let b11 = (imm >> 11) & 1;
    let b10_5 = (imm >> 5) & 0x3F;
    let b4_1 = (imm >> 1) & 0xF;
    (b12 << 31) | (b10_5 << 25) | (0 << 20) | (rs1 << 15) | (1 << 12) | (b4_1 << 8) | (b11 << 7) | 0x63
}

fn expand_c_slli(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let shamt = (((inst >> 12) & 0x1) << 5) | ((inst >> 2) & 0x1F);
    (shamt << 20) | (rd << 15) | (1 << 12) | (rd << 7) | 0x13
}

fn expand_c_lwsp(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let offset = (((inst >> 12) & 0x1) << 5)
        | (((inst >> 4) & 0x7) << 2)
        | (((inst >> 2) & 0x3) << 6);
    (offset << 20) | (2 << 15) | (2 << 12) | (rd << 7) | 0x03
}

fn expand_c_ldsp(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let offset = (((inst >> 12) & 0x1) << 5)
        | (((inst >> 5) & 0x3) << 3)
        | (((inst >> 2) & 0x7) << 6);
    (offset << 20) | (2 << 15) | (3 << 12) | (rd << 7) | 0x03
}

fn expand_c_jr_mv_add(inst: u32) -> u32 {
    let rd = (inst >> 7) & 0x1F;
    let rs2 = (inst >> 2) & 0x1F;
    let bit12 = (inst >> 12) & 0x1;
    if bit12 == 0 {
        if rs2 == 0 {
            // C.JR: JALR x0, rs1, 0
            (rd << 15) | (0 << 12) | (0 << 7) | 0x67
        } else {
            // C.MV: ADD rd, x0, rs2
            (rs2 << 20) | (0 << 15) | (0 << 12) | (rd << 7) | 0x33
        }
    } else {
        if rs2 == 0 {
            if rd == 0 {
                // C.EBREAK
                0x00100073
            } else {
                // C.JALR: JALR x1, rs1, 0
                (rd << 15) | (0 << 12) | (1 << 7) | 0x67
            }
        } else {
            // C.ADD: ADD rd, rd, rs2
            (rs2 << 20) | (rd << 15) | (0 << 12) | (rd << 7) | 0x33
        }
    }
}

fn expand_c_swsp(inst: u32) -> u32 {
    let rs2 = (inst >> 2) & 0x1F;
    let offset = (((inst >> 9) & 0xF) << 2) | (((inst >> 7) & 0x3) << 6);
    let imm11_5 = (offset >> 5) & 0x7F;
    let imm4_0 = offset & 0x1F;
    (imm11_5 << 25) | (rs2 << 20) | (2 << 15) | (2 << 12) | (imm4_0 << 7) | 0x23
}

fn expand_c_sdsp(inst: u32) -> u32 {
    let rs2 = (inst >> 2) & 0x1F;
    let offset = (((inst >> 10) & 0x7) << 3) | (((inst >> 7) & 0x7) << 6);
    let imm11_5 = (offset >> 5) & 0x7F;
    let imm4_0 = offset & 0x1F;
    (imm11_5 << 25) | (rs2 << 20) | (2 << 15) | (3 << 12) | (imm4_0 << 7) | 0x23
}
