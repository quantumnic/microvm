//! RISC-V instruction disassembler for trace output.
//! Supports RV64GC (IMAFDCSU) + Zba/Zbb/Zbs/Zbc/Zbkb/Zbkx/Zknd/Zkne/Zknh extensions.

const REG_NAMES: [&str; 32] = [
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4",
    "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4",
    "t5", "t6",
];

const FREG_NAMES: [&str; 32] = [
    "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1", "fa2",
    "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7", "fs8", "fs9",
    "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
];

fn r(idx: usize) -> &'static str {
    REG_NAMES[idx & 0x1F]
}

fn f(idx: usize) -> &'static str {
    FREG_NAMES[idx & 0x1F]
}

fn csr_name(addr: u16) -> &'static str {
    match addr {
        0x000 => "ustatus",
        0x001 => "fflags",
        0x002 => "frm",
        0x003 => "fcsr",
        0x100 => "sstatus",
        0x104 => "sie",
        0x105 => "stvec",
        0x106 => "scounteren",
        0x10A => "senvcfg",
        0x140 => "sscratch",
        0x141 => "sepc",
        0x142 => "scause",
        0x143 => "stval",
        0x144 => "sip",
        0x14D => "stimecmp",
        0x180 => "satp",
        0x300 => "mstatus",
        0x301 => "misa",
        0x302 => "medeleg",
        0x303 => "mideleg",
        0x304 => "mie",
        0x305 => "mtvec",
        0x306 => "mcounteren",
        0x30A => "menvcfg",
        0x320 => "mcountinhibit",
        0x340 => "mscratch",
        0x341 => "mepc",
        0x342 => "mcause",
        0x343 => "mtval",
        0x344 => "mip",
        0x3A0 => "pmpcfg0",
        0x3A2 => "pmpcfg2",
        0x3B0 => "pmpaddr0",
        0xB00 => "mcycle",
        0xB02 => "minstret",
        0xC00 => "cycle",
        0xC01 => "time",
        0xC02 => "instret",
        0xF11 => "mvendorid",
        0xF12 => "marchid",
        0xF13 => "mimpid",
        0xF14 => "mhartid",
        _ => "",
    }
}

/// Disassemble a single 32-bit RISC-V instruction at the given PC.
/// Returns a human-readable string.
pub fn disassemble(raw: u32, pc: u64) -> String {
    let opcode = raw & 0x7F;
    let rd = ((raw >> 7) & 0x1F) as usize;
    let funct3 = (raw >> 12) & 0x7;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let funct7 = (raw >> 25) & 0x7F;
    let imm_i = ((raw as i32) >> 20) as i64;
    let imm_s = {
        let v = ((funct7 as i32) << 5) | ((rd as i32) & 0x1F);
        ((v << 20) >> 20) as i64
    };
    let imm_b = {
        let b12 = (raw >> 31) & 1;
        let b11 = (raw >> 7) & 1;
        let b10_5 = (raw >> 25) & 0x3F;
        let b4_1 = (raw >> 8) & 0xF;
        let imm = (b12 << 12) | (b11 << 11) | (b10_5 << 5) | (b4_1 << 1);
        (((imm as i32) << 19) >> 19) as i64
    };
    let imm_u = (raw & 0xFFFFF000) as i32 as i64;
    let imm_j = {
        let b20 = (raw >> 31) & 1;
        let b19_12 = (raw >> 12) & 0xFF;
        let b11 = (raw >> 20) & 1;
        let b10_1 = (raw >> 21) & 0x3FF;
        let imm = (b20 << 20) | (b19_12 << 12) | (b11 << 11) | (b10_1 << 1);
        (((imm as i32) << 11) >> 11) as i64
    };

    match opcode {
        0x37 => format!("lui     {}, {:#x}", r(rd), (imm_u as u64) >> 12),
        0x17 => {
            let target = pc.wrapping_add(imm_u as u64);
            format!(
                "auipc   {}, {:#x}  # {:#x}",
                r(rd),
                (imm_u as u64) >> 12,
                target
            )
        }
        0x6F => {
            let target = pc.wrapping_add(imm_j as u64);
            if rd == 0 {
                format!("j       {:#x}", target)
            } else {
                format!("jal     {}, {:#x}", r(rd), target)
            }
        }
        0x67 => {
            if rd == 0 && imm_i == 0 && rs1 == 1 {
                "ret".to_string()
            } else if rd == 0 && imm_i == 0 {
                format!("jr      {}", r(rs1))
            } else {
                format!("jalr    {}, {}({})", r(rd), imm_i, r(rs1))
            }
        }
        0x63 => {
            let target = pc.wrapping_add(imm_b as u64);
            let op = match funct3 {
                0 => "beq",
                1 => "bne",
                4 => "blt",
                5 => "bge",
                6 => "bltu",
                7 => "bgeu",
                _ => "b??",
            };
            format!("{:<8}{}, {}, {:#x}", op, r(rs1), r(rs2), target)
        }
        0x03 => {
            let op = match funct3 {
                0 => "lb",
                1 => "lh",
                2 => "lw",
                3 => "ld",
                4 => "lbu",
                5 => "lhu",
                6 => "lwu",
                _ => "l??",
            };
            format!("{:<8}{}, {}({})", op, r(rd), imm_i, r(rs1))
        }
        0x23 => {
            let op = match funct3 {
                0 => "sb",
                1 => "sh",
                2 => "sw",
                3 => "sd",
                _ => "s??",
            };
            format!("{:<8}{}, {}({})", op, r(rs2), imm_s, r(rs1))
        }
        0x13 => disasm_op_imm(raw, rd, rs1, funct3, funct7, imm_i),
        0x1B => disasm_op_imm_w(raw, rd, rs1, funct3, funct7, imm_i),
        0x33 => disasm_op(rd, rs1, rs2, funct3, funct7),
        0x3B => disasm_op_w(rd, rs1, rs2, funct3, funct7),
        0x07 => {
            // FP loads
            let op = match funct3 {
                2 => "flw",
                3 => "fld",
                _ => "fl?",
            };
            format!("{:<8}{}, {}({})", op, f(rd), imm_i, r(rs1))
        }
        0x27 => {
            // FP stores
            let op = match funct3 {
                2 => "fsw",
                3 => "fsd",
                _ => "fs?",
            };
            format!("{:<8}{}, {}({})", op, f(rs2), imm_s, r(rs1))
        }
        0x53 => disasm_fp(raw, rd, rs1, rs2, funct7),
        0x43 | 0x47 | 0x4B | 0x4F => {
            let rs3 = ((raw >> 27) & 0x1F) as usize;
            let op = match opcode {
                0x43 => "fmadd",
                0x47 => "fmsub",
                0x4B => "fnmsub",
                0x4F => "fnmadd",
                _ => unreachable!(),
            };
            let suffix = if (raw >> 25) & 3 == 1 { ".d" } else { ".s" };
            format!(
                "{}{} {}, {}, {}, {}",
                op,
                suffix,
                f(rd),
                f(rs1),
                f(rs2),
                f(rs3)
            )
        }
        0x2F => disasm_atomic(raw, rd, rs1, rs2, funct3, funct7),
        0x0F => {
            if funct3 == 0 {
                "fence".to_string()
            } else if funct3 == 1 {
                "fence.i".to_string()
            } else if raw == 0x0180000F {
                "fence.tso".to_string()
            } else {
                format!("fence?  {:#010x}", raw)
            }
        }
        0x73 => disasm_system(raw, rd, rs1, funct3),
        _ => format!(".word   {:#010x}", raw),
    }
}

fn disasm_op_imm(raw: u32, rd: usize, rs1: usize, funct3: u32, funct7: u32, imm: i64) -> String {
    match funct3 {
        0 => {
            if rs1 == 0 {
                format!("li      {}, {}", r(rd), imm)
            } else if imm == 0 {
                format!("mv      {}, {}", r(rd), r(rs1))
            } else {
                format!("addi    {}, {}, {}", r(rd), r(rs1), imm)
            }
        }
        1 => {
            let shamt = (raw >> 20) & 0x3F;
            let top = funct7 >> 1;
            match top {
                0 => format!("slli    {}, {}, {}", r(rd), r(rs1), shamt),
                0x04 if shamt == 0 => format!("sext.b  {}, {}", r(rd), r(rs1)), // Zbb
                0x04 if shamt == 1 => format!("sext.h  {}, {}", r(rd), r(rs1)), // Zbb
                0x30 => match shamt {
                    0 => format!("clz     {}, {}", r(rd), r(rs1)),
                    1 => format!("ctz     {}, {}", r(rd), r(rs1)),
                    2 => format!("cpop    {}, {}", r(rd), r(rs1)),
                    _ => format!("zbb?    {}, {}, {}", r(rd), r(rs1), shamt),
                },
                // Zknh: SHA-256
                0x04 if shamt == 0 => format!("sha256sum0 {}, {}", r(rd), r(rs1)),
                0x04 if shamt == 1 => format!("sha256sum1 {}, {}", r(rd), r(rs1)),
                0x04 if shamt == 2 => format!("sha256sig0 {}, {}", r(rd), r(rs1)),
                0x04 if shamt == 3 => format!("sha256sig1 {}, {}", r(rd), r(rs1)),
                // Zknh: SHA-512
                0x04 if shamt == 4 => format!("sha512sum0 {}, {}", r(rd), r(rs1)),
                0x04 if shamt == 5 => format!("sha512sum1 {}, {}", r(rd), r(rs1)),
                0x04 if shamt == 6 => format!("sha512sig0 {}, {}", r(rd), r(rs1)),
                0x04 if shamt == 7 => format!("sha512sig1 {}, {}", r(rd), r(rs1)),
                // Zknd: AES64IM
                0x0C if shamt == 0 => format!("aes64im {}, {}", r(rd), r(rs1)),
                // Zkne: AES64KS1I
                0x0C if shamt & 0x10 != 0 => {
                    format!("aes64ks1i {}, {}, {}", r(rd), r(rs1), shamt & 0xF)
                }
                _ => format!("slli?   {}, {}, {}", r(rd), r(rs1), shamt),
            }
        }
        2 => format!("slti    {}, {}, {}", r(rd), r(rs1), imm),
        3 => {
            if imm == 1 {
                format!("seqz    {}, {}", r(rd), r(rs1))
            } else {
                format!("sltiu   {}, {}, {}", r(rd), r(rs1), imm)
            }
        }
        4 => {
            if rs1 == 0 {
                format!("li      {}, {}", r(rd), imm)
            } else {
                format!("xori    {}, {}, {}", r(rd), r(rs1), imm)
            }
        }
        5 => {
            let shamt = (raw >> 20) & 0x3F;
            let funct6 = (raw >> 26) & 0x3F;
            if funct6 == 0x10 {
                format!("srai    {}, {}, {}", r(rd), r(rs1), shamt)
            } else if funct6 == 0x18 {
                format!("rori    {}, {}, {}", r(rd), r(rs1), shamt) // Zbb
            } else if funct6 == 0x12 {
                format!("bexti   {}, {}, {}", r(rd), r(rs1), shamt) // Zbs
            } else {
                let funct12 = (raw >> 20) & 0xFFF;
                if funct12 == 0x287 {
                    format!("orc.b   {}, {}", r(rd), r(rs1)) // Zbb
                } else if funct12 == 0x687 {
                    format!("brev8   {}, {}", r(rd), r(rs1)) // Zbkb
                } else if funct12 == 0x6B8 {
                    format!("rev8    {}, {}", r(rd), r(rs1)) // Zbb
                } else {
                    format!("srli    {}, {}, {}", r(rd), r(rs1), shamt)
                }
            }
        }
        6 => format!("ori     {}, {}, {}", r(rd), r(rs1), imm),
        7 => {
            if imm == -1 {
                format!("not     {}, {}", r(rd), r(rs1))
            } else {
                format!("andi    {}, {}, {}", r(rd), r(rs1), imm)
            }
        }
        _ => format!("opimm?  {:#010x}", raw),
    }
}

fn disasm_op_imm_w(_raw: u32, rd: usize, rs1: usize, funct3: u32, funct7: u32, imm: i64) -> String {
    match funct3 {
        0 => {
            if rs1 == 0 {
                format!("li      {}, {}", r(rd), imm as i32)
            } else if imm == 0 {
                format!("sext.w  {}, {}", r(rd), r(rs1))
            } else {
                format!("addiw   {}, {}, {}", r(rd), r(rs1), imm)
            }
        }
        1 => {
            let shamt = imm & 0x1F;
            if funct7 == 0x04 {
                format!("slli.uw {}, {}, {}", r(rd), r(rs1), shamt) // Zba
            } else {
                format!("slliw   {}, {}, {}", r(rd), r(rs1), shamt)
            }
        }
        5 => {
            let shamt = imm & 0x1F;
            if funct7 == 0x20 {
                format!("sraiw   {}, {}, {}", r(rd), r(rs1), shamt)
            } else if funct7 == 0x30 {
                format!("roriw   {}, {}, {}", r(rd), r(rs1), shamt) // Zbb
            } else {
                format!("srliw   {}, {}, {}", r(rd), r(rs1), shamt)
            }
        }
        _ => format!("opimmw? funct3={}", funct3),
    }
}

fn disasm_op(rd: usize, rs1: usize, rs2: usize, funct3: u32, funct7: u32) -> String {
    match (funct3, funct7) {
        (0, 0x00) => format!("add     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (0, 0x20) => {
            if rs1 == 0 {
                format!("neg     {}, {}", r(rd), r(rs2))
            } else {
                format!("sub     {}, {}, {}", r(rd), r(rs1), r(rs2))
            }
        }
        (0, 0x01) => format!("mul     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (1, 0x00) => format!("sll     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (1, 0x01) => format!("mulh    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (2, 0x00) => format!("slt     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (2, 0x01) => format!("mulhsu  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (3, 0x00) => {
            if rs1 == 0 {
                format!("snez    {}, {}", r(rd), r(rs2))
            } else {
                format!("sltu    {}, {}, {}", r(rd), r(rs1), r(rs2))
            }
        }
        (3, 0x01) => format!("mulhu   {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (4, 0x00) => format!("xor     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (4, 0x01) => format!("div     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (4, 0x20) => format!("xnor    {}, {}, {}", r(rd), r(rs1), r(rs2)), // Zbb
        (5, 0x00) => format!("srl     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x01) => format!("divu    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x20) => format!("sra     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x30) => format!("ror     {}, {}, {}", r(rd), r(rs1), r(rs2)), // Zbb
        (6, 0x00) => format!("or      {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (6, 0x01) => format!("rem     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (6, 0x20) => format!("orn     {}, {}, {}", r(rd), r(rs1), r(rs2)), // Zbb
        (7, 0x00) => format!("and     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (7, 0x01) => format!("remu    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (7, 0x20) => format!("andn    {}, {}, {}", r(rd), r(rs1), r(rs2)), // Zbb
        // Zba
        (2, 0x10) => format!("sh1add  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (4, 0x10) => format!("sh2add  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (6, 0x10) => format!("sh3add  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zbb min/max
        (4, 0x05) => format!("min     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x05) => format!("minu    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (6, 0x05) => format!("max     {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (7, 0x05) => format!("maxu    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zbs
        (1, 0x24) => format!("bclr    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (1, 0x14) => format!("bset    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (1, 0x34) => format!("binv    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x24) => format!("bext    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zbc
        (1, 0x05) => format!("clmul   {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (3, 0x05) => format!("clmulh  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (2, 0x05) => format!("clmulr  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zbkb
        (4, 0x04) => format!("pack    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (7, 0x04) => format!("packh   {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zbkx
        (2, 0x14) => format!("xperm4  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (4, 0x14) => format!("xperm8  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zkne
        (0, 0x19) => format!("aes64es {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (0, 0x1B) => format!("aes64esm {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zknd
        (0, 0x1D) => format!("aes64ds {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (0, 0x1F) => format!("aes64dsm {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zkne/Zknd
        (0, 0x3F) => format!("aes64ks2 {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zicond
        (5, 0x07) => format!("czero.eqz {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (7, 0x07) => format!("czero.nez {}, {}, {}", r(rd), r(rs1), r(rs2)),
        _ => format!("op?     funct3={}, funct7={:#x}", funct3, funct7),
    }
}

fn disasm_op_w(rd: usize, rs1: usize, rs2: usize, funct3: u32, funct7: u32) -> String {
    match (funct3, funct7) {
        (0, 0x00) => format!("addw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (0, 0x20) => format!("subw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (0, 0x01) => format!("mulw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (1, 0x00) => format!("sllw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (4, 0x01) => format!("divw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x00) => format!("srlw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x01) => format!("divuw   {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x20) => format!("sraw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (6, 0x01) => format!("remw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (7, 0x01) => format!("remuw   {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zba
        (0, 0x04) => format!("add.uw  {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (2, 0x10) => format!("sh1add.uw {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (4, 0x10) => format!("sh2add.uw {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (6, 0x10) => format!("sh3add.uw {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zbb
        (1, 0x30) => format!("rolw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        (5, 0x30) => format!("rorw    {}, {}, {}", r(rd), r(rs1), r(rs2)),
        // Zbkb
        (4, 0x04) => format!("packw   {}, {}, {}", r(rd), r(rs1), r(rs2)),
        _ => format!("opw?    funct3={}, funct7={:#x}", funct3, funct7),
    }
}

fn disasm_fp(raw: u32, rd: usize, rs1: usize, rs2: usize, funct7: u32) -> String {
    let fmt = if funct7 & 3 == 1 { ".d" } else { ".s" };
    match funct7 >> 2 {
        0 => format!("fadd{}  {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
        1 => format!("fsub{}  {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
        2 => format!("fmul{}  {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
        3 => format!("fdiv{}  {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
        0xB => format!("fsqrt{} {}, {}", fmt, f(rd), f(rs1)),
        4 => {
            let rm = (raw >> 12) & 7;
            match rm {
                0 => format!("fsgnj{}  {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
                1 => format!("fsgnjn{} {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
                2 => format!("fsgnjx{} {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
                _ => format!("fsgn?{}", fmt),
            }
        }
        5 => {
            let rm = (raw >> 12) & 7;
            match rm {
                0 => format!("fmin{}  {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
                1 => format!("fmax{}  {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
                2 => format!("fminm{} {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
                3 => format!("fmaxm{} {}, {}, {}", fmt, f(rd), f(rs1), f(rs2)),
                _ => format!("fminmax?{}", fmt),
            }
        }
        0x18 => {
            if rs2 == 8 {
                format!("fcvtmod.w.d {}, {}, rtz", r(rd), f(rs1))
            } else {
                format!("fcvt.w{} {}, {}", fmt, r(rd), f(rs1))
            }
        }
        0x1A => format!("fcvt{}.w {}, {}", fmt, f(rd), r(rs1)),
        0x1C => {
            let rm = (raw >> 12) & 7;
            if rm == 0 {
                format!(
                    "fmv.x{} {}, {}",
                    if funct7 & 3 == 1 { ".d" } else { ".w" },
                    r(rd),
                    f(rs1)
                )
            } else {
                format!("fclass{} {}, {}", fmt, r(rd), f(rs1))
            }
        }
        0x1E => {
            if rs2 == 1 {
                format!("fli{}   {}, {}", fmt, f(rd), rs1)
            } else {
                format!(
                    "fmv{}.x {}, {}",
                    if funct7 & 3 == 1 { ".d" } else { ".w" },
                    f(rd),
                    r(rs1)
                )
            }
        }
        0x14 => {
            let rm = (raw >> 12) & 7;
            match rm {
                0 => format!("fle{}   {}, {}, {}", fmt, r(rd), f(rs1), f(rs2)),
                1 => format!("flt{}   {}, {}, {}", fmt, r(rd), f(rs1), f(rs2)),
                2 => format!("feq{}   {}, {}, {}", fmt, r(rd), f(rs1), f(rs2)),
                4 => format!("fleq{}  {}, {}, {}", fmt, r(rd), f(rs1), f(rs2)),
                5 => format!("fltq{}  {}, {}, {}", fmt, r(rd), f(rs1), f(rs2)),
                _ => format!("fcmp?{}", fmt),
            }
        }
        8 => match rs2 {
            4 => format!("fround{} {}, {}", fmt, f(rd), f(rs1)),
            5 => format!("froundnx{} {}, {}", fmt, f(rd), f(rs1)),
            _ => {
                if funct7 & 3 == 1 {
                    format!("fcvt.d.s {}, {}", f(rd), f(rs1))
                } else {
                    format!("fcvt.s.d {}, {}", f(rd), f(rs1))
                }
            }
        },
        _ => format!("fp?     {:#010x}", raw),
    }
}

fn disasm_atomic(_raw: u32, rd: usize, rs1: usize, rs2: usize, funct3: u32, funct7: u32) -> String {
    let suffix = match funct3 {
        0 => ".b",
        1 => ".h",
        2 => ".w",
        3 => ".d",
        _ => ".?",
    };
    let funct5 = funct7 >> 2;
    match funct5 {
        0x02 => format!("lr{}    {}, ({})", suffix, r(rd), r(rs1)),
        0x03 => format!("sc{}    {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x05 => format!("amocas{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x01 => format!("amoswap{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x00 => format!("amoadd{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x04 => format!("amoxor{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x08 => format!("amoor{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x0C => format!("amoand{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x10 => format!("amomin{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x14 => format!("amomax{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x18 => format!("amominu{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        0x1C => format!("amomaxu{} {}, {}, ({})", suffix, r(rd), r(rs2), r(rs1)),
        _ => format!("amo?{} funct5={:#x}", suffix, funct5),
    }
}

fn disasm_system(raw: u32, rd: usize, rs1: usize, funct3: u32) -> String {
    if funct3 == 0 {
        return match raw {
            0x00000073 => "ecall".to_string(),
            0x00100073 => "ebreak".to_string(),
            0x10200073 => "sret".to_string(),
            0x30200073 => "mret".to_string(),
            0x10500073 => "wfi".to_string(),
            0x01800073 => "wrs.nto".to_string(),
            0x01D00073 => "wrs.sto".to_string(),
            _ => {
                // SFENCE.VMA, SINVAL.VMA, etc.
                let funct7 = (raw >> 25) & 0x7F;
                match funct7 {
                    0x09 => format!(
                        "sfence.vma {}, {}",
                        r(rs1),
                        r(((raw >> 20) & 0x1F) as usize)
                    ),
                    0x0B => format!(
                        "sinval.vma {}, {}",
                        r(rs1),
                        r(((raw >> 20) & 0x1F) as usize)
                    ),
                    0x0C => "sfence.w.inval".to_string(),
                    0x0D => "sfence.inval.ir".to_string(),
                    _ => format!("system  {:#010x}", raw),
                }
            }
        };
    }

    // Zimop: May-Be-Operations (funct3 = 4)
    if funct3 == 4 {
        let f7 = (raw >> 25) & 0x7F;
        let rs2_field = (raw >> 20) & 0x1F;
        let is_mop_r = (f7 & 0x59) == 0x40 && (rs2_field & 0x1C) == 0x1C;
        let is_mop_rr = (f7 & 0x59) == 0x41;
        if is_mop_r {
            let n = ((f7 >> 5) & 1) << 4 | ((f7 >> 1) & 3) << 2 | (rs2_field & 3);
            return format!("mop.r.{}  {}, {}", n, r(rd), r(rs1));
        }
        if is_mop_rr {
            let n = ((f7 >> 5) & 1) << 2 | ((f7 >> 1) & 3);
            let rs2 = rs2_field as usize;
            return format!("mop.rr.{} {}, {}, {}", n, r(rd), r(rs1), r(rs2));
        }
        return format!("system  {:#010x}", raw);
    }

    let csr_addr = ((raw >> 20) & 0xFFF) as u16;
    let name = csr_name(csr_addr);
    let csr_str = if name.is_empty() {
        format!("{:#x}", csr_addr)
    } else {
        name.to_string()
    };

    match funct3 {
        1 => {
            if rs1 == 0 {
                format!("csrr    {}, {}", r(rd), csr_str)
            } else if rd == 0 {
                format!("csrw    {}, {}", csr_str, r(rs1))
            } else {
                format!("csrrw   {}, {}, {}", r(rd), csr_str, r(rs1))
            }
        }
        2 => {
            if rd == 0 {
                format!("csrs    {}, {}", csr_str, r(rs1))
            } else if rs1 == 0 {
                format!("csrr    {}, {}", r(rd), csr_str)
            } else {
                format!("csrrs   {}, {}, {}", r(rd), csr_str, r(rs1))
            }
        }
        3 => {
            if rd == 0 {
                format!("csrc    {}, {}", csr_str, r(rs1))
            } else {
                format!("csrrc   {}, {}, {}", r(rd), csr_str, r(rs1))
            }
        }
        5 => {
            if rd == 0 {
                format!("csrwi   {}, {}", csr_str, rs1)
            } else {
                format!("csrrwi  {}, {}, {}", r(rd), csr_str, rs1)
            }
        }
        6 => {
            if rd == 0 {
                format!("csrsi   {}, {}", csr_str, rs1)
            } else {
                format!("csrrsi  {}, {}, {}", r(rd), csr_str, rs1)
            }
        }
        7 => {
            if rd == 0 {
                format!("csrci   {}, {}", csr_str, rs1)
            } else {
                format!("csrrci  {}, {}, {}", r(rd), csr_str, rs1)
            }
        }
        _ => format!("csr?    {:#010x}", raw),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_instructions() {
        assert_eq!(disassemble(0x00000013, 0), "li      zero, 0");
        assert_eq!(disassemble(0x30200073, 0), "mret");
        assert_eq!(disassemble(0x10200073, 0), "sret");
        assert_eq!(disassemble(0x00100073, 0), "ebreak");
        assert_eq!(disassemble(0x00000073, 0), "ecall");
        assert_eq!(disassemble(0x10500073, 0), "wfi");
    }

    #[test]
    fn test_load_store() {
        // ld a0, 0(sp)
        assert!(disassemble(0x00013503, 0).starts_with("ld"));
        // sd a0, 0(sp)
        assert!(disassemble(0x00a13023, 0).starts_with("sd"));
    }

    #[test]
    fn test_branch() {
        // beq a0, a1, +8
        let s = disassemble(0x00b50463, 0x1000);
        assert!(s.starts_with("beq"));
    }

    #[test]
    fn test_csr() {
        // csrr a0, mstatus
        let s = disassemble(0x30002573, 0);
        assert!(s.contains("mstatus"));
        assert!(s.contains("csrr"));
    }

    #[test]
    fn test_jal_ret() {
        assert_eq!(disassemble(0x00008067, 0), "ret");
    }

    #[test]
    fn test_lui_auipc() {
        let s = disassemble(0x800002B7, 0);
        assert!(s.starts_with("lui"));
        let s = disassemble(0x00000297, 0x1000);
        assert!(s.starts_with("auipc"));
    }

    #[test]
    fn test_atomic() {
        // lr.d a0, (a1): funct5=0x02, rs2=0, rs1=x11, funct3=3, rd=x10
        let s = disassemble(0x1005B52F, 0);
        assert!(s.contains("lr.d"), "got: {}", s);
    }
}

/// Fast instruction mnemonic classifier for profiling.
/// Returns a static string identifying the instruction type.
pub fn mnemonic(inst: u32) -> &'static str {
    let opcode = inst & 0x7F;
    let funct3 = ((inst >> 12) & 7) as u8;
    let funct7 = ((inst >> 25) & 0x7F) as u8;

    match opcode {
        0x37 => "lui",
        0x17 => "auipc",
        0x6F => "jal",
        0x67 => "jalr",
        0x63 => match funct3 {
            0 => "beq",
            1 => "bne",
            4 => "blt",
            5 => "bge",
            6 => "bltu",
            7 => "bgeu",
            _ => "branch?",
        },
        0x03 => match funct3 {
            0 => "lb",
            1 => "lh",
            2 => "lw",
            3 => "ld",
            4 => "lbu",
            5 => "lhu",
            6 => "lwu",
            _ => "load?",
        },
        0x23 => match funct3 {
            0 => "sb",
            1 => "sh",
            2 => "sw",
            3 => "sd",
            _ => "store?",
        },
        0x13 => match funct3 {
            0 => "addi",
            1 => match funct7 >> 1 {
                0 => "slli",
                _ => "shli?",
            },
            2 => "slti",
            3 => "sltiu",
            4 => "xori",
            5 => match funct7 >> 1 {
                0 => "srli",
                0x10 => "srai",
                _ => "shri?",
            },
            6 => "ori",
            7 => "andi",
            _ => "imm?",
        },
        0x1B => match funct3 {
            0 => "addiw",
            1 => "slliw",
            5 => {
                if funct7 == 0x20 {
                    "sraiw"
                } else {
                    "srliw"
                }
            }
            _ => "immw?",
        },
        0x33 => match (funct7, funct3) {
            (0x00, 0) => "add",
            (0x20, 0) => "sub",
            (0x00, 1) => "sll",
            (0x00, 2) => "slt",
            (0x00, 3) => "sltu",
            (0x00, 4) => "xor",
            (0x00, 5) => "srl",
            (0x20, 5) => "sra",
            (0x00, 6) => "or",
            (0x00, 7) => "and",
            (0x01, 0) => "mul",
            (0x01, 1) => "mulh",
            (0x01, 2) => "mulhsu",
            (0x01, 3) => "mulhu",
            (0x01, 4) => "div",
            (0x01, 5) => "divu",
            (0x01, 6) => "rem",
            (0x01, 7) => "remu",
            _ => "alu?",
        },
        0x3B => match (funct7, funct3) {
            (0x00, 0) => "addw",
            (0x20, 0) => "subw",
            (0x00, 1) => "sllw",
            (0x00, 5) => "srlw",
            (0x20, 5) => "sraw",
            (0x01, 0) => "mulw",
            (0x01, 4) => "divw",
            (0x01, 5) => "divuw",
            (0x01, 6) => "remw",
            (0x01, 7) => "remuw",
            _ => "aluw?",
        },
        0x2F => "atomic",
        0x0F => "fence",
        0x73 => match funct3 {
            0 => {
                let imm = inst >> 20;
                match imm {
                    0x000 => "ecall",
                    0x001 => "ebreak",
                    0x102 => "sret",
                    0x302 => "mret",
                    0x105 => "wfi",
                    _ => "system",
                }
            }
            1 => "csrrw",
            2 => "csrrs",
            3 => "csrrc",
            5 => "csrrwi",
            6 => "csrrsi",
            7 => "csrrci",
            4 => "mop",
            _ => "csr?",
        },
        0x07 => {
            // Could be FP load or vector load
            match funct3 {
                0 | 5 | 6 | 7 => "vload",
                _ => "fload",
            }
        }
        0x27 => match funct3 {
            0 | 5 | 6 | 7 => "vstore",
            _ => "fstore",
        },
        0x57 => {
            if funct3 == 7 {
                "vsetcfg"
            } else if (funct3 == 1 || funct3 == 5) && funct7 >> 1 >= 0b110000 {
                "vwfpu"
            } else if funct3 == 1 || funct3 == 5 {
                "vfpu"
            } else if funct3 == 0 && funct7 >> 1 == 0b100111 && (funct7 & 1) == 1 {
                "vmove" // vmvNr.v (whole-register move)
            } else if (funct3 == 0 || funct3 == 3 || funct3 == 4)
                && matches!(
                    funct7 >> 1,
                    0b100111 | 0b101010 | 0b101011 | 0b101110 | 0b101111
                )
            {
                "vfixpt"
            } else if (funct3 == 2 || funct3 == 6)
                && funct7 >> 1 >= 0b10000
                && funct7 >> 1 <= 0b10011
            {
                "vmuldiv"
            } else if (funct3 == 2 || funct3 == 6) && funct7 >> 1 >= 0b11000 {
                "vwide"
            } else {
                let f6 = funct7 >> 1;
                if f6 == 0b001100 || f6 == 0b001110 || f6 == 0b001111 || f6 == 0b010111 {
                    "vperm"
                } else if (funct3 == 2) && (0b011000..=0b011111).contains(&f6) {
                    "vmask"
                } else if f6 == 0b100000 || f6 == 0b100001 || f6 == 0b100010 || f6 == 0b100011 {
                    "vsat"
                } else {
                    "valu"
                }
            }
        }
        0x43 | 0x47 | 0x4B | 0x4F => "fmadd",
        0x53 => "fpu",
        _ => "unknown",
    }
}
