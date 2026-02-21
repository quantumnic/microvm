// RISC-V Vector Extension (V) 1.0
//
// VLEN = 128 bits, ELEN = 64 bits
// 32 vector registers, each VLEN bits wide

use super::csr;
use super::mmu::AccessType;
use super::Cpu;
use crate::memory::Bus;

/// VLEN in bits
pub const VLEN: usize = 128;
/// VLEN in bytes
pub const VLENB: usize = VLEN / 8;
/// Maximum ELEN in bits
#[allow(dead_code)]
pub const ELEN: usize = 64;

/// Vector register file: 32 registers × VLENB bytes each
pub struct VectorRegFile {
    /// Raw bytes for all 32 vector registers
    pub data: [[u8; VLENB]; 32],
}

impl Default for VectorRegFile {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorRegFile {
    pub fn new() -> Self {
        Self {
            data: [[0u8; VLENB]; 32],
        }
    }

    /// Read element `idx` of register `reg` as the given SEW width
    pub fn read_elem(&self, reg: usize, sew: u32, idx: usize) -> u64 {
        let off = idx * (sew as usize / 8);
        let b = &self.data[reg];
        match sew {
            8 => b[off] as u64,
            16 => u16::from_le_bytes([b[off], b[off + 1]]) as u64,
            32 => u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) as u64,
            64 => u64::from_le_bytes([
                b[off],
                b[off + 1],
                b[off + 2],
                b[off + 3],
                b[off + 4],
                b[off + 5],
                b[off + 6],
                b[off + 7],
            ]),
            _ => 0,
        }
    }

    /// Write element `idx` of register `reg` as the given SEW width
    pub fn write_elem(&mut self, reg: usize, sew: u32, idx: usize, val: u64) {
        let off = idx * (sew as usize / 8);
        let b = &mut self.data[reg];
        match sew {
            8 => b[off] = val as u8,
            16 => {
                let le = (val as u16).to_le_bytes();
                b[off] = le[0];
                b[off + 1] = le[1];
            }
            32 => b[off..off + 4].copy_from_slice(&(val as u32).to_le_bytes()),
            64 => b[off..off + 8].copy_from_slice(&val.to_le_bytes()),
            _ => {}
        }
    }

    /// Check mask bit for element idx in v0
    pub fn mask_bit(&self, idx: usize) -> bool {
        (self.data[0][idx / 8] >> (idx % 8)) & 1 != 0
    }

    /// Set mask bit for element idx in register vd
    pub fn set_mask_bit(&mut self, vd: usize, idx: usize, val: bool) {
        let byte_idx = idx / 8;
        let bit_idx = idx % 8;
        if val {
            self.data[vd][byte_idx] |= 1 << bit_idx;
        } else {
            self.data[vd][byte_idx] &= !(1 << bit_idx);
        }
    }
}

/// Decoded vtype fields
#[derive(Debug, Clone, Copy)]
pub struct Vtype {
    pub sew: u32,
    pub lmul_num: u32,
    pub lmul_den: u32,
    pub vta: bool,
    pub vma: bool,
    pub vill: bool,
}

const VILL_TYPE: Vtype = Vtype {
    sew: 8,
    lmul_num: 1,
    lmul_den: 1,
    vta: false,
    vma: false,
    vill: true,
};

impl Vtype {
    pub fn decode(raw: u64) -> Self {
        if raw >> 63 != 0 {
            return VILL_TYPE;
        }
        let vsew = (raw >> 3) & 0x7;
        let sew = match vsew {
            0 => 8,
            1 => 16,
            2 => 32,
            3 => 64,
            _ => return VILL_TYPE,
        };
        let vlmul = raw & 0x7;
        let (lmul_num, lmul_den) = match vlmul {
            0 => (1, 1),
            1 => (2, 1),
            2 => (4, 1),
            3 => (8, 1),
            5 => (1, 8),
            6 => (1, 4),
            7 => (1, 2),
            _ => return VILL_TYPE,
        };
        // VLMAX must be >= 1
        if (VLEN as u32) * lmul_num < sew * lmul_den {
            return Vtype {
                sew,
                lmul_num,
                lmul_den,
                vta: false,
                vma: false,
                vill: true,
            };
        }
        Vtype {
            sew,
            lmul_num,
            lmul_den,
            vta: (raw >> 6) & 1 != 0,
            vma: (raw >> 7) & 1 != 0,
            vill: false,
        }
    }

    pub fn vlmax(&self) -> u64 {
        if self.vill {
            return 0;
        }
        (VLEN as u64) * (self.lmul_num as u64) / ((self.sew as u64) * (self.lmul_den as u64))
    }

    pub fn encode(&self) -> u64 {
        if self.vill {
            return 1u64 << 63;
        }
        let vsew = match self.sew {
            8 => 0,
            16 => 1,
            32 => 2,
            64 => 3,
            _ => 0,
        };
        let vlmul = match (self.lmul_num, self.lmul_den) {
            (1, 1) => 0,
            (2, 1) => 1,
            (4, 1) => 2,
            (8, 1) => 3,
            (1, 8) => 5,
            (1, 4) => 6,
            (1, 2) => 7,
            _ => 0,
        };
        vlmul | (vsew << 3) | ((self.vta as u64) << 6) | ((self.vma as u64) << 7)
    }
}

/// Check if vector instructions are enabled (VS field in mstatus != Off)
pub fn vector_enabled(cpu: &Cpu) -> bool {
    (cpu.csrs.read(csr::MSTATUS) >> 9) & 3 != 0
}

/// Mark vector state as Dirty in mstatus
fn set_vs_dirty(cpu: &mut Cpu) {
    let mstatus = cpu.csrs.read(csr::MSTATUS);
    if (mstatus >> 9) & 3 != 3 {
        let new = (mstatus & !(3u64 << 9)) | (3u64 << 9) | (1u64 << 63);
        cpu.csrs.write_raw(csr::MSTATUS, new);
    }
}

fn current_vtype(cpu: &Cpu) -> Vtype {
    Vtype::decode(cpu.csrs.read(csr::VTYPE))
}

fn current_vl(cpu: &Cpu) -> u64 {
    cpu.csrs.read(csr::VL)
}

/// Execution context passed to vector operation helpers
struct VCtx {
    funct6: u32,
    vd: usize,
    vs1: usize,
    vs2: usize,
    vm: u32,
    vl: u64,
    sew: u32,
}

/// Execute a vector instruction. Returns true if handled.
pub fn execute_vector(cpu: &mut Cpu, bus: &mut Bus, raw: u32, inst_len: u64) -> bool {
    let opcode = raw & 0x7F;
    match opcode {
        0x57 => execute_v_arith(cpu, bus, raw, inst_len),
        0x07 => execute_v_load(cpu, bus, raw, inst_len),
        0x27 => execute_v_store(cpu, bus, raw, inst_len),
        _ => false,
    }
}

fn execute_v_arith(cpu: &mut Cpu, bus: &mut Bus, raw: u32, inst_len: u64) -> bool {
    let funct3 = (raw >> 12) & 0x7;
    let rd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let funct6 = (raw >> 26) & 0x3F;
    let vm = (raw >> 25) & 1;

    // vsetvli / vsetivli / vsetvl
    if funct3 == 7 {
        let bit31 = (raw >> 31) & 1;
        let bit30 = (raw >> 30) & 1;

        if bit31 == 0 {
            let zimm = (raw >> 20) & 0x7FF;
            let vtype = Vtype::decode(zimm as u64);
            let avl = if rs1 != 0 {
                cpu.regs[rs1]
            } else if rd != 0 {
                u64::MAX
            } else {
                current_vl(cpu)
            };
            set_vl(cpu, rd, avl, vtype);
        } else if bit30 == 1 {
            let uimm = rs1 as u64;
            let zimm = (raw >> 20) & 0x3FF;
            let vtype = Vtype::decode(zimm as u64);
            set_vl(cpu, rd, uimm, vtype);
        } else {
            let vtype_val = cpu.regs[rs2];
            let vtype = Vtype::decode(vtype_val);
            let avl = if rs1 != 0 {
                cpu.regs[rs1]
            } else if rd != 0 {
                u64::MAX
            } else {
                current_vl(cpu)
            };
            set_vl(cpu, rd, avl, vtype);
        }
        cpu.pc += inst_len;
        return true;
    }

    let vtype = current_vtype(cpu);
    if vtype.vill {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }
    let vl = current_vl(cpu);
    let sew = vtype.sew;
    set_vs_dirty(cpu);

    let ctx = VCtx {
        funct6,
        vd: rd,
        vs1: rs1,
        vs2: rs2,
        vm,
        vl,
        sew,
    };

    match funct3 {
        0 => {
            execute_vv_int(cpu, &ctx);
            cpu.pc += inst_len;
            true
        }
        3 => {
            let simm5 = ((rs1 as i32) << 27 >> 27) as u64;
            execute_vxi_int(cpu, &ctx, simm5);
            cpu.pc += inst_len;
            true
        }
        4 => {
            let scalar = cpu.regs[rs1];
            execute_vxi_int(cpu, &ctx, scalar);
            cpu.pc += inst_len;
            true
        }
        2 => {
            execute_mvv(cpu, &ctx);
            cpu.pc += inst_len;
            true
        }
        6 => {
            let scalar = cpu.regs[rs1];
            execute_mvx(cpu, &ctx, scalar);
            cpu.pc += inst_len;
            true
        }
        _ => false,
    }
}

fn set_vl(cpu: &mut Cpu, rd: usize, avl: u64, vtype: Vtype) {
    if vtype.vill {
        cpu.csrs.write_raw(csr::VTYPE, 1u64 << 63);
        cpu.csrs.write_raw(csr::VL, 0);
        if rd != 0 {
            cpu.regs[rd] = 0;
        }
        return;
    }
    let vlmax = vtype.vlmax();
    let vl = if avl == u64::MAX {
        vlmax
    } else {
        avl.min(vlmax)
    };
    cpu.csrs.write_raw(csr::VTYPE, vtype.encode());
    cpu.csrs.write_raw(csr::VL, vl);
    cpu.csrs.write_raw(csr::VSTART, 0);
    if rd != 0 {
        cpu.regs[rd] = vl;
    }
}

fn elem_active(cpu: &Cpu, vm: u32, idx: usize) -> bool {
    vm == 1 || cpu.vregs.mask_bit(idx)
}

fn trunc_sew(val: u64, sew: u32) -> u64 {
    match sew {
        8 => val & 0xFF,
        16 => val & 0xFFFF,
        32 => val & 0xFFFF_FFFF,
        _ => val,
    }
}

fn sext_sew(val: u64, sew: u32) -> i64 {
    match sew {
        8 => val as u8 as i8 as i64,
        16 => val as u16 as i16 as i64,
        32 => val as u32 as i32 as i64,
        _ => val as i64,
    }
}

// ============================================================================
// Vector-vector integer operations (OPIVV, funct3=0)
// ============================================================================
fn execute_vv_int(cpu: &mut Cpu, ctx: &VCtx) {
    let VCtx {
        funct6,
        vd,
        vs1,
        vs2,
        vm,
        vl,
        sew,
    } = *ctx;

    for i in 0..vl as usize {
        if !elem_active(cpu, vm, i) {
            continue;
        }
        let a = cpu.vregs.read_elem(vs2, sew, i);
        let b = cpu.vregs.read_elem(vs1, sew, i);
        let is_cmp = matches!(funct6, 0b011000..=0b011101);
        let result = match funct6 {
            0b000000 => trunc_sew(a.wrapping_add(b), sew),
            0b000010 => trunc_sew(a.wrapping_sub(b), sew),
            0b001001 => a & b,
            0b001010 => a | b,
            0b001011 => a ^ b,
            0b010111 => {
                if vm == 1 || cpu.vregs.mask_bit(i) {
                    trunc_sew(b, sew)
                } else {
                    trunc_sew(a, sew)
                }
            }
            0b000100 => trunc_sew(a.min(b), sew),
            0b000101 => trunc_sew(sext_sew(a, sew).min(sext_sew(b, sew)) as u64, sew),
            0b000110 => trunc_sew(a.max(b), sew),
            0b000111 => trunc_sew(sext_sew(a, sew).max(sext_sew(b, sew)) as u64, sew),
            0b011000 => u64::from(a == b),
            0b011001 => u64::from(a != b),
            0b011010 => u64::from(a < b),
            0b011011 => u64::from(sext_sew(a, sew) < sext_sew(b, sew)),
            0b011100 => u64::from(a <= b),
            0b011101 => u64::from(sext_sew(a, sew) <= sext_sew(b, sew)),
            _ => continue,
        };

        if is_cmp {
            cpu.vregs.set_mask_bit(vd, i, result != 0);
        } else {
            cpu.vregs.write_elem(vd, sew, i, result);
        }
    }
}

// ============================================================================
// Vector-scalar/immediate integer operations (OPIVX/OPIVI, funct3=3,4)
// ============================================================================
fn execute_vxi_int(cpu: &mut Cpu, ctx: &VCtx, scalar: u64) {
    let VCtx {
        funct6,
        vd,
        vs2,
        vm,
        vl,
        sew,
        ..
    } = *ctx;

    for i in 0..vl as usize {
        if !elem_active(cpu, vm, i) {
            continue;
        }
        let a = cpu.vregs.read_elem(vs2, sew, i);
        let b = scalar;
        let is_cmp = matches!(funct6, 0b011000..=0b011111);
        let result = match funct6 {
            0b000000 => trunc_sew(a.wrapping_add(b), sew),
            0b000011 => trunc_sew(b.wrapping_sub(a), sew),
            0b001001 => a & b,
            0b001010 => a | b,
            0b001011 => a ^ b,
            0b010111 => {
                if vm == 1 || cpu.vregs.mask_bit(i) {
                    trunc_sew(b, sew)
                } else {
                    trunc_sew(a, sew)
                }
            }
            0b100101 => trunc_sew(a << (b & (sew as u64 - 1)), sew),
            0b101000 => trunc_sew(trunc_sew(a, sew) >> (b & (sew as u64 - 1)), sew),
            0b101001 => trunc_sew((sext_sew(a, sew) >> (b & (sew as u64 - 1))) as u64, sew),
            0b011000 => u64::from(a == b),
            0b011001 => u64::from(a != b),
            0b011100 => u64::from(a <= b),
            0b011101 => u64::from(sext_sew(a, sew) <= sext_sew(b, sew)),
            0b011110 => u64::from(a > b),
            0b011111 => u64::from(sext_sew(a, sew) > sext_sew(b, sew)),
            _ => continue,
        };

        if is_cmp {
            cpu.vregs.set_mask_bit(vd, i, result != 0);
        } else {
            cpu.vregs.write_elem(vd, sew, i, result);
        }
    }
}

// ============================================================================
// OPMVV (funct3=2): reductions
// ============================================================================
fn execute_mvv(cpu: &mut Cpu, ctx: &VCtx) {
    let VCtx {
        funct6,
        vd,
        vs1,
        vs2,
        vm,
        vl,
        sew,
    } = *ctx;

    match funct6 {
        0b000000 => {
            // vredsum
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = trunc_sew(acc.wrapping_add(cpu.vregs.read_elem(vs2, sew, i)), sew);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, acc);
        }
        0b000001 => {
            // vredand
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc &= cpu.vregs.read_elem(vs2, sew, i);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, trunc_sew(acc, sew));
        }
        0b000010 => {
            // vredor
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc |= cpu.vregs.read_elem(vs2, sew, i);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, trunc_sew(acc, sew));
        }
        0b000011 => {
            // vredxor
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc ^= cpu.vregs.read_elem(vs2, sew, i);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, trunc_sew(acc, sew));
        }
        0b000100 => {
            // vredminu
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = acc.min(cpu.vregs.read_elem(vs2, sew, i));
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, trunc_sew(acc, sew));
        }
        0b000101 => {
            // vredmin
            let mut acc = sext_sew(cpu.vregs.read_elem(vs1, sew, 0), sew);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = acc.min(sext_sew(cpu.vregs.read_elem(vs2, sew, i), sew));
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, trunc_sew(acc as u64, sew));
        }
        0b000110 => {
            // vredmaxu
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = acc.max(cpu.vregs.read_elem(vs2, sew, i));
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, trunc_sew(acc, sew));
        }
        0b000111 => {
            // vredmax
            let mut acc = sext_sew(cpu.vregs.read_elem(vs1, sew, 0), sew);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = acc.max(sext_sew(cpu.vregs.read_elem(vs2, sew, i), sew));
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, trunc_sew(acc as u64, sew));
        }
        _ => {}
    }
}

// ============================================================================
// OPMVX (funct3=6): scalar-vector moves
// ============================================================================
fn execute_mvx(cpu: &mut Cpu, ctx: &VCtx, scalar: u64) {
    if ctx.funct6 == 0b010000 && ctx.vl > 0 {
        // vmv.s.x
        cpu.vregs
            .write_elem(ctx.vd, ctx.sew, 0, trunc_sew(scalar, ctx.sew));
    }
}

// ============================================================================
// Vector loads (opcode 0x07)
// ============================================================================
fn execute_v_load(cpu: &mut Cpu, bus: &mut Bus, raw: u32, inst_len: u64) -> bool {
    let width = (raw >> 12) & 0x7;
    let vd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let vm = (raw >> 25) & 1;
    let mop = (raw >> 26) & 0x3;
    let nf = ((raw >> 29) & 0x7) as usize;
    let lumop = ((raw >> 20) & 0x1F) as usize;

    let eew = match width {
        0 => 8u32,
        5 => 16,
        6 => 32,
        7 => 64,
        _ => return false,
    };

    if mop != 0 {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }

    let vtype = current_vtype(cpu);
    if vtype.vill && lumop != 0b01000 {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }

    set_vs_dirty(cpu);
    let base = cpu.regs[rs1];

    if lumop == 0b01000 {
        // Whole register load
        let num_regs = nf + 1;
        for r in 0..num_regs {
            for b in 0..VLENB {
                let addr = base + (r * VLENB + b) as u64;
                match cpu
                    .mmu
                    .translate(addr, AccessType::Read, cpu.mode, &cpu.csrs, bus)
                {
                    Ok(phys) => cpu.vregs.data[vd + r][b] = bus.read8(phys),
                    Err(e) => {
                        cpu.handle_exception(e, addr, bus);
                        return true;
                    }
                }
            }
        }
    } else {
        let vl = current_vl(cpu);
        let eew_bytes = eew as u64 / 8;
        for i in 0..vl as usize {
            if !elem_active(cpu, vm, i) {
                continue;
            }
            let addr = base + (i as u64) * eew_bytes;
            let phys = match cpu
                .mmu
                .translate(addr, AccessType::Read, cpu.mode, &cpu.csrs, bus)
            {
                Ok(a) => a,
                Err(e) => {
                    cpu.handle_exception(e, addr, bus);
                    return true;
                }
            };
            let val = match eew {
                8 => bus.read8(phys) as u64,
                16 => bus.read16(phys) as u64,
                32 => bus.read32(phys) as u64,
                64 => bus.read64(phys),
                _ => 0,
            };
            cpu.vregs.write_elem(vd, eew, i, val);
        }
    }

    cpu.pc += inst_len;
    true
}

// ============================================================================
// Vector stores (opcode 0x27)
// ============================================================================
fn execute_v_store(cpu: &mut Cpu, bus: &mut Bus, raw: u32, inst_len: u64) -> bool {
    let width = (raw >> 12) & 0x7;
    let vs3 = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let vm = (raw >> 25) & 1;
    let mop = (raw >> 26) & 0x3;
    let nf = ((raw >> 29) & 0x7) as usize;
    let sumop = ((raw >> 20) & 0x1F) as usize;

    let eew = match width {
        0 => 8u32,
        5 => 16,
        6 => 32,
        7 => 64,
        _ => return false,
    };

    if mop != 0 {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }

    let vtype = current_vtype(cpu);
    if vtype.vill && sumop != 0b01000 {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }

    let base = cpu.regs[rs1];

    if sumop == 0b01000 {
        // Whole register store
        let num_regs = nf + 1;
        for r in 0..num_regs {
            for b in 0..VLENB {
                let addr = base + (r * VLENB + b) as u64;
                match cpu
                    .mmu
                    .translate(addr, AccessType::Write, cpu.mode, &cpu.csrs, bus)
                {
                    Ok(phys) => bus.write8(phys, cpu.vregs.data[vs3 + r][b]),
                    Err(e) => {
                        cpu.handle_exception(e, addr, bus);
                        return true;
                    }
                }
            }
        }
    } else {
        let vl = current_vl(cpu);
        let eew_bytes = eew as u64 / 8;
        for i in 0..vl as usize {
            if !elem_active(cpu, vm, i) {
                continue;
            }
            let addr = base + (i as u64) * eew_bytes;
            let phys = match cpu
                .mmu
                .translate(addr, AccessType::Write, cpu.mode, &cpu.csrs, bus)
            {
                Ok(a) => a,
                Err(e) => {
                    cpu.handle_exception(e, addr, bus);
                    return true;
                }
            };
            let val = cpu.vregs.read_elem(vs3, eew, i);
            match eew {
                8 => bus.write8(phys, val as u8),
                16 => bus.write16(phys, val as u16),
                32 => bus.write32(phys, val as u32),
                64 => bus.write64(phys, val),
                _ => {}
            }
        }
    }

    cpu.pc += inst_len;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vtype_decode_basic() {
        let vt = Vtype::decode(0b0_0_010_000); // SEW=32, LMUL=1
        assert_eq!(vt.sew, 32);
        assert_eq!(vt.lmul_num, 1);
        assert_eq!(vt.lmul_den, 1);
        assert!(!vt.vill);
        assert_eq!(vt.vlmax(), (VLEN as u64) / 32);
    }

    #[test]
    fn vtype_decode_lmul2() {
        let vt = Vtype::decode(0b0_0_001_001); // SEW=16, LMUL=2
        assert_eq!(vt.sew, 16);
        assert_eq!(vt.lmul_num, 2);
        assert_eq!(vt.vlmax(), (VLEN as u64) / 16 * 2);
    }

    #[test]
    fn vtype_decode_fractional_lmul() {
        let vt = Vtype::decode(0b0_0_000_111); // SEW=8, LMUL=1/2
        assert_eq!(vt.sew, 8);
        assert_eq!(vt.lmul_num, 1);
        assert_eq!(vt.lmul_den, 2);
        assert_eq!(vt.vlmax(), (VLEN as u64) / 8 / 2);
    }

    #[test]
    fn vtype_vill_on_invalid_sew() {
        let vt = Vtype::decode(0b0_0_100_000); // vsew=4 reserved
        assert!(vt.vill);
    }

    #[test]
    fn vtype_vill_on_sew_gt_lmul_elen() {
        let vt = Vtype::decode(0b0_0_011_101); // SEW=64, LMUL=1/8
        assert!(vt.vill);
    }

    #[test]
    fn vtype_roundtrip() {
        let raw = 0b1_1_010_001u64; // VTA, VMA, SEW=32, LMUL=2
        let vt = Vtype::decode(raw);
        assert_eq!(vt.sew, 32);
        assert!(vt.vta);
        assert!(vt.vma);
        assert_eq!(vt.encode(), raw);
    }

    #[test]
    fn vreg_read_write_elem() {
        let mut vrf = VectorRegFile::new();
        vrf.write_elem(5, 32, 0, 0xDEADBEEF);
        assert_eq!(vrf.read_elem(5, 32, 0), 0xDEADBEEF);
        vrf.write_elem(5, 32, 1, 0xCAFEBABE);
        assert_eq!(vrf.read_elem(5, 32, 1), 0xCAFEBABE);
        assert_eq!(vrf.read_elem(5, 32, 0), 0xDEADBEEF);
    }

    #[test]
    fn vreg_different_sew() {
        let mut vrf = VectorRegFile::new();
        vrf.write_elem(1, 64, 0, 0x0102030405060708);
        assert_eq!(vrf.read_elem(1, 8, 0), 0x08);
        assert_eq!(vrf.read_elem(1, 8, 1), 0x07);
        assert_eq!(vrf.read_elem(1, 8, 7), 0x01);
    }

    #[test]
    fn vreg_mask_bit() {
        let mut vrf = VectorRegFile::new();
        vrf.data[0][0] = 0b10110101;
        assert!(vrf.mask_bit(0));
        assert!(!vrf.mask_bit(1));
        assert!(vrf.mask_bit(2));
        assert!(!vrf.mask_bit(3));
        assert!(vrf.mask_bit(4));
        assert!(vrf.mask_bit(5));
        assert!(!vrf.mask_bit(6));
        assert!(vrf.mask_bit(7));
    }

    #[test]
    fn trunc_sew_values() {
        assert_eq!(trunc_sew(0x1234, 8), 0x34);
        assert_eq!(trunc_sew(0x12345678, 16), 0x5678);
        assert_eq!(trunc_sew(0x123456789ABCDEF0, 32), 0x9ABCDEF0);
        assert_eq!(trunc_sew(0x123456789ABCDEF0, 64), 0x123456789ABCDEF0);
    }

    #[test]
    fn sext_sew_values() {
        assert_eq!(sext_sew(0xFF, 8), -1);
        assert_eq!(sext_sew(0x7F, 8), 127);
        assert_eq!(sext_sew(0xFFFF, 16), -1);
        assert_eq!(sext_sew(0xFFFFFFFF, 32), -1);
    }
}
