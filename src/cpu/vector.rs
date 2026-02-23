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

    /// Read element `idx` of register group starting at `reg` as the given SEW width.
    /// Handles LMUL>1 by spanning across consecutive registers.
    pub fn read_elem(&self, reg: usize, sew: u32, idx: usize) -> u64 {
        let byte_off = idx * (sew as usize / 8);
        let r = reg + byte_off / VLENB;
        let off = byte_off % VLENB;
        if r >= 32 {
            return 0;
        }
        let b = &self.data[r];
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

    /// Write element `idx` of register group starting at `reg` as the given SEW width.
    /// Handles LMUL>1 by spanning across consecutive registers.
    pub fn write_elem(&mut self, reg: usize, sew: u32, idx: usize, val: u64) {
        let byte_off = idx * (sew as usize / 8);
        let r = reg + byte_off / VLENB;
        let off = byte_off % VLENB;
        if r >= 32 {
            return;
        }
        let b = &mut self.data[r];
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

    /// Read mask bit from any register (for vcpop, vfirst, vmsbf, etc.)
    pub fn mask_bit_of(&self, vreg: usize, idx: usize) -> bool {
        (self.data[vreg][idx / 8] >> (idx % 8)) & 1 != 0
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
        0x77 => execute_v_crypto(cpu, raw, inst_len),
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

    // Whole-register move: vmv<nr>r.v — doesn't need valid vtype
    // funct3=0 (OPIVV), funct6=0b100111, vm=1, vs1 encodes (nr-1)
    if funct3 == 0 && funct6 == 0b100111 && vm == 1 {
        let nr = rs1 + 1; // vs1 field = nr-1
        if matches!(nr, 1 | 2 | 4 | 8) {
            set_vs_dirty(cpu);
            for r in 0..nr {
                cpu.vregs.data[rd + r] = cpu.vregs.data[rs2 + r];
            }
            cpu.pc += inst_len;
            return true;
        }
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
        1 => {
            // OPFVV: vector-vector floating-point
            execute_fvv(cpu, &ctx);
            cpu.pc += inst_len;
            true
        }
        5 => {
            // OPFVF: vector-scalar floating-point
            let scalar = cpu.fregs[rs1];
            execute_fvf(cpu, &ctx, scalar);
            cpu.pc += inst_len;
            true
        }
        _ => false,
    }
}

// ============================================================================
// Floating-point helpers
// ============================================================================

fn f32_add(a: u64, b: u64) -> u64 {
    (f32::from_bits(a as u32) + f32::from_bits(b as u32)).to_bits() as u64
}
fn f32_sub(a: u64, b: u64) -> u64 {
    (f32::from_bits(a as u32) - f32::from_bits(b as u32)).to_bits() as u64
}
fn f32_mul(a: u64, b: u64) -> u64 {
    (f32::from_bits(a as u32) * f32::from_bits(b as u32)).to_bits() as u64
}
fn f32_div(a: u64, b: u64) -> u64 {
    (f32::from_bits(a as u32) / f32::from_bits(b as u32)).to_bits() as u64
}
fn f32_min(a: u64, b: u64) -> u64 {
    let fa = f32::from_bits(a as u32);
    let fb = f32::from_bits(b as u32);
    if fa.is_nan() && fb.is_nan() {
        return 0x7FC00000; // canonical NaN
    }
    if fa.is_nan() {
        return b & 0xFFFFFFFF;
    }
    if fb.is_nan() {
        return a & 0xFFFFFFFF;
    }
    // -0 < +0 per IEEE 754-2019
    if fa == fb {
        return if fa.to_bits() & 0x80000000 != 0 {
            a & 0xFFFFFFFF
        } else {
            b & 0xFFFFFFFF
        };
    }
    if fa < fb {
        a & 0xFFFFFFFF
    } else {
        b & 0xFFFFFFFF
    }
}
fn f32_max(a: u64, b: u64) -> u64 {
    let fa = f32::from_bits(a as u32);
    let fb = f32::from_bits(b as u32);
    if fa.is_nan() && fb.is_nan() {
        return 0x7FC00000;
    }
    if fa.is_nan() {
        return b & 0xFFFFFFFF;
    }
    if fb.is_nan() {
        return a & 0xFFFFFFFF;
    }
    if fa == fb {
        return if fa.to_bits() & 0x80000000 == 0 {
            a & 0xFFFFFFFF
        } else {
            b & 0xFFFFFFFF
        };
    }
    if fa > fb {
        a & 0xFFFFFFFF
    } else {
        b & 0xFFFFFFFF
    }
}
fn f32_sqrt(a: u64) -> u64 {
    f32::from_bits(a as u32).sqrt().to_bits() as u64
}
fn f32_neg(a: u64) -> u64 {
    (a ^ 0x80000000) & 0xFFFFFFFF
}
fn f64_add(a: u64, b: u64) -> u64 {
    (f64::from_bits(a) + f64::from_bits(b)).to_bits()
}
fn f64_sub(a: u64, b: u64) -> u64 {
    (f64::from_bits(a) - f64::from_bits(b)).to_bits()
}
fn f64_mul(a: u64, b: u64) -> u64 {
    (f64::from_bits(a) * f64::from_bits(b)).to_bits()
}
fn f64_div(a: u64, b: u64) -> u64 {
    (f64::from_bits(a) / f64::from_bits(b)).to_bits()
}
fn f64_min(a: u64, b: u64) -> u64 {
    let fa = f64::from_bits(a);
    let fb = f64::from_bits(b);
    if fa.is_nan() && fb.is_nan() {
        return 0x7FF8000000000000;
    }
    if fa.is_nan() {
        return b;
    }
    if fb.is_nan() {
        return a;
    }
    if fa == fb {
        return if fa.to_bits() & (1u64 << 63) != 0 {
            a
        } else {
            b
        };
    }
    if fa < fb {
        a
    } else {
        b
    }
}
fn f64_max(a: u64, b: u64) -> u64 {
    let fa = f64::from_bits(a);
    let fb = f64::from_bits(b);
    if fa.is_nan() && fb.is_nan() {
        return 0x7FF8000000000000;
    }
    if fa.is_nan() {
        return b;
    }
    if fb.is_nan() {
        return a;
    }
    if fa == fb {
        return if fa.to_bits() & (1u64 << 63) == 0 {
            a
        } else {
            b
        };
    }
    if fa > fb {
        a
    } else {
        b
    }
}
fn f64_sqrt(a: u64) -> u64 {
    f64::from_bits(a).sqrt().to_bits()
}
fn f64_neg(a: u64) -> u64 {
    a ^ (1u64 << 63)
}

/// Apply a binary FP op at current SEW
fn fp_binop(
    sew: u32,
    a: u64,
    b: u64,
    f32_op: fn(u64, u64) -> u64,
    f64_op: fn(u64, u64) -> u64,
) -> u64 {
    match sew {
        32 => f32_op(a, b),
        64 => f64_op(a, b),
        _ => 0,
    }
}

fn fp_unop(sew: u32, a: u64, f32_op: fn(u64) -> u64, f64_op: fn(u64) -> u64) -> u64 {
    match sew {
        32 => f32_op(a),
        64 => f64_op(a),
        _ => 0,
    }
}

fn fp_eq(sew: u32, a: u64, b: u64) -> bool {
    match sew {
        32 => f32::from_bits(a as u32) == f32::from_bits(b as u32),
        64 => f64::from_bits(a) == f64::from_bits(b),
        _ => false,
    }
}
fn fp_lt(sew: u32, a: u64, b: u64) -> bool {
    match sew {
        32 => f32::from_bits(a as u32) < f32::from_bits(b as u32),
        64 => f64::from_bits(a) < f64::from_bits(b),
        _ => false,
    }
}
fn fp_le(sew: u32, a: u64, b: u64) -> bool {
    match sew {
        32 => f32::from_bits(a as u32) <= f32::from_bits(b as u32),
        64 => f64::from_bits(a) <= f64::from_bits(b),
        _ => false,
    }
}
fn fp_is_nan(sew: u32, a: u64) -> bool {
    match sew {
        32 => f32::from_bits(a as u32).is_nan(),
        64 => f64::from_bits(a).is_nan(),
        _ => false,
    }
}

/// FP fused multiply-add: a*b+c
fn fp_fma(sew: u32, a: u64, b: u64, c: u64) -> u64 {
    match sew {
        32 => f32::from_bits(a as u32)
            .mul_add(f32::from_bits(b as u32), f32::from_bits(c as u32))
            .to_bits() as u64,
        64 => f64::from_bits(a)
            .mul_add(f64::from_bits(b), f64::from_bits(c))
            .to_bits(),
        _ => 0,
    }
}

fn fp_neg(sew: u32, a: u64) -> u64 {
    match sew {
        32 => f32_neg(a),
        64 => f64_neg(a),
        _ => 0,
    }
}

/// Convert float to signed int (truncate)
fn fp_to_int(sew: u32, a: u64) -> u64 {
    match sew {
        32 => {
            let f = f32::from_bits(a as u32);
            if f.is_nan() {
                return trunc_sew(i32::MAX as u64, 32);
            }
            trunc_sew(f as i32 as u64, 32)
        }
        64 => {
            let f = f64::from_bits(a);
            if f.is_nan() {
                return i64::MAX as u64;
            }
            f as i64 as u64
        }
        _ => 0,
    }
}

/// Convert float to unsigned int (truncate)
fn fp_to_uint(sew: u32, a: u64) -> u64 {
    match sew {
        32 => {
            let f = f32::from_bits(a as u32);
            if f.is_nan() || f < 0.0 {
                return if f < 0.0 {
                    0
                } else {
                    trunc_sew(u32::MAX as u64, 32)
                };
            }
            trunc_sew(f as u32 as u64, 32)
        }
        64 => {
            let f = f64::from_bits(a);
            if f.is_nan() || f < 0.0 {
                return if f < 0.0 { 0 } else { u64::MAX };
            }
            f as u64
        }
        _ => 0,
    }
}

/// Convert signed int to float
fn int_to_fp(sew: u32, a: u64) -> u64 {
    match sew {
        32 => (sext_sew(a, 32) as f32).to_bits() as u64,
        64 => (a as i64 as f64).to_bits(),
        _ => 0,
    }
}

/// Convert unsigned int to float
fn uint_to_fp(sew: u32, a: u64) -> u64 {
    match sew {
        32 => (trunc_sew(a, 32) as u32 as f32).to_bits() as u64,
        64 => (a as f64).to_bits(),
        _ => 0,
    }
}

/// Approximate reciprocal (vfrec7)
fn fp_rec7(sew: u32, a: u64) -> u64 {
    match sew {
        32 => (1.0f32 / f32::from_bits(a as u32)).to_bits() as u64,
        64 => (1.0f64 / f64::from_bits(a)).to_bits(),
        _ => 0,
    }
}

/// Approximate reciprocal square root (vfrsqrt7)
fn fp_rsqrt7(sew: u32, a: u64) -> u64 {
    match sew {
        32 => (1.0f32 / f32::from_bits(a as u32).sqrt()).to_bits() as u64,
        64 => (1.0f64 / f64::from_bits(a).sqrt()).to_bits(),
        _ => 0,
    }
}

/// FP sign-injection: copy sign of b to a
fn fp_sgnj(sew: u32, a: u64, b: u64) -> u64 {
    match sew {
        32 => (a & 0x7FFFFFFF) | (b & 0x80000000),
        64 => (a & 0x7FFFFFFFFFFFFFFF) | (b & (1u64 << 63)),
        _ => 0,
    }
}

/// FP sign-injection negated: copy negated sign of b to a
fn fp_sgnjn(sew: u32, a: u64, b: u64) -> u64 {
    match sew {
        32 => (a & 0x7FFFFFFF) | ((b ^ 0x80000000) & 0x80000000),
        64 => (a & 0x7FFFFFFFFFFFFFFF) | ((b ^ (1u64 << 63)) & (1u64 << 63)),
        _ => 0,
    }
}

/// FP sign-injection XOR: XOR signs
fn fp_sgnjx(sew: u32, a: u64, b: u64) -> u64 {
    match sew {
        32 => a ^ (b & 0x80000000),
        64 => a ^ (b & (1u64 << 63)),
        _ => 0,
    }
}

// ============================================================================
// Widening FP helpers: SEW→2*SEW (only f32→f64 supported, since VLEN=128, ELEN=64)
// ============================================================================

/// Widen a f32 value to f64 bits
fn fp_widen(val: u64) -> u64 {
    let f = f32::from_bits(val as u32);
    (f as f64).to_bits()
}

/// Narrow a f64 value to f32 bits
#[allow(dead_code)]
fn fp_narrow(val: u64) -> u64 {
    let f = f64::from_bits(val);
    (f as f32).to_bits() as u64
}

/// Widening FP binary op: read two SEW operands, widen to 2*SEW, apply f64 op
fn fp_widen_binop(a: u64, b: u64, sew: u32, op: fn(u64, u64) -> u64) -> u64 {
    if sew == 32 {
        let wa = fp_widen(a);
        let wb = fp_widen(b);
        op(wa, wb)
    } else {
        0 // SEW=64 would need f128, not supported
    }
}

/// Widening FP: vs2 is already 2*SEW, vs1 is SEW (.wv variant)
fn fp_widen_w_binop(a_wide: u64, b: u64, sew: u32, op: fn(u64, u64) -> u64) -> u64 {
    if sew == 32 {
        let wb = fp_widen(b);
        op(a_wide, wb)
    } else {
        0
    }
}

/// Widening FP FMA: all SEW inputs, result in 2*SEW
fn fp_widen_fma(a: u64, b: u64, c: u64, sew: u32) -> u64 {
    if sew == 32 {
        let wa = fp_widen(a);
        let wb = fp_widen(b);
        // c is already 2*SEW (f64)
        fp_fma(64, wa, wb, c)
    } else {
        0
    }
}

/// Widening FP conversion (vfwcvt): f32→f64
fn fp_widen_cvt_f(sew: u32, a: u64) -> u64 {
    if sew == 32 {
        fp_widen(a)
    } else {
        0
    }
}

/// Widening int→FP: SEW int → 2*SEW FP
fn fp_widen_cvt_xu(sew: u32, a: u64) -> u64 {
    if sew == 32 {
        let val = trunc_sew(a, sew) as u32;
        (val as f64).to_bits()
    } else {
        0
    }
}

fn fp_widen_cvt_x(sew: u32, a: u64) -> u64 {
    if sew == 32 {
        let val = sext_sew(a, sew) as i32;
        (val as f64).to_bits()
    } else {
        0
    }
}

/// Narrowing FP conversion (vfncvt): f64→f32
fn fp_narrow_cvt_f(sew: u32, a: u64) -> u64 {
    // sew is the destination SEW; source is 2*SEW
    if sew == 32 {
        fp_narrow(a)
    } else {
        0
    }
}

/// Narrowing FP→int: 2*SEW FP → SEW int
fn fp_narrow_cvt_x(sew: u32, a: u64) -> u64 {
    if sew == 32 {
        // a is f64, convert to i32
        let f = f64::from_bits(a);
        let clamped = f.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32;
        trunc_sew(clamped as u64, 32)
    } else {
        0
    }
}

fn fp_narrow_cvt_xu(sew: u32, a: u64) -> u64 {
    if sew == 32 {
        let f = f64::from_bits(a);
        let clamped = f.round().clamp(0.0, u32::MAX as f64) as u32;
        clamped as u64
    } else {
        0
    }
}

// ============================================================================
// OPFVV: vector-vector floating-point (funct3=1)
// ============================================================================
fn execute_fvv(cpu: &mut Cpu, ctx: &VCtx) {
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
        // Reductions
        0b000001 => {
            // vfredusum
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = fp_binop(sew, acc, cpu.vregs.read_elem(vs2, sew, i), f32_add, f64_add);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, acc);
        }
        0b000011 => {
            // vfredosum (ordered reduction — same as unordered in sequential emulator)
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = fp_binop(sew, acc, cpu.vregs.read_elem(vs2, sew, i), f32_add, f64_add);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, acc);
        }
        0b000101 => {
            // vfredmin
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = fp_binop(sew, acc, cpu.vregs.read_elem(vs2, sew, i), f32_min, f64_min);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, acc);
        }
        0b000111 => {
            // vfredmax
            let mut acc = cpu.vregs.read_elem(vs1, sew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    acc = fp_binop(sew, acc, cpu.vregs.read_elem(vs2, sew, i), f32_max, f64_max);
                }
            }
            cpu.vregs.write_elem(vd, sew, 0, acc);
        }
        // Widening FP reductions (SEW→2*SEW)
        0b110001 => {
            // vfwredusum: widening unordered FP sum reduction
            let dsew = sew * 2;
            let mut acc = cpu.vregs.read_elem(vs1, dsew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    let widened = fp_widen_cvt_f(sew, cpu.vregs.read_elem(vs2, sew, i));
                    acc = f64_add(acc, widened);
                }
            }
            cpu.vregs.write_elem(vd, dsew, 0, acc);
        }
        0b110011 => {
            // vfwredosum: widening ordered FP sum reduction
            let dsew = sew * 2;
            let mut acc = cpu.vregs.read_elem(vs1, dsew, 0);
            for i in 0..vl as usize {
                if elem_active(cpu, vm, i) {
                    let widened = fp_widen_cvt_f(sew, cpu.vregs.read_elem(vs2, sew, i));
                    acc = f64_add(acc, widened);
                }
            }
            cpu.vregs.write_elem(vd, dsew, 0, acc);
        }
        0b010000 => {
            // vfmv.f.s: f[rd] = vs2[0]
            if vl > 0 {
                let val = cpu.vregs.read_elem(vs2, sew, 0);
                match sew {
                    32 => {
                        // NaN-box: upper bits all 1s
                        cpu.fregs[vd] = 0xFFFF_FFFF_0000_0000 | (val & 0xFFFF_FFFF);
                    }
                    _ => {
                        cpu.fregs[vd] = val;
                    }
                }
            }
        }
        _ => {
            // Element-wise ops
            execute_fvv_elemwise(cpu, ctx);
        }
    }
}

fn execute_fvv_elemwise(cpu: &mut Cpu, ctx: &VCtx) {
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

        let is_cmp = matches!(funct6, 0b011000 | 0b011001 | 0b011011 | 0b011100 | 0b011101);

        let result = match funct6 {
            0b000000 => fp_binop(sew, a, b, f32_add, f64_add), // vfadd
            0b000010 => fp_binop(sew, a, b, f32_sub, f64_sub), // vfsub
            0b001000 => fp_binop(sew, a, b, f32_mul, f64_mul), // vfmul
            0b100000 => fp_binop(sew, a, b, f32_div, f64_div), // vfdiv
            0b000100 => fp_binop(sew, a, b, f32_min, f64_min), // vfmin
            0b000110 => fp_binop(sew, a, b, f32_max, f64_max), // vfmax
            0b100100 => fp_sgnj(sew, a, b),                    // vfsgnj
            0b100101 => fp_sgnjn(sew, a, b),                   // vfsgnjn
            0b100110 => fp_sgnjx(sew, a, b),                   // vfsgnjx

            // Unary ops encoded in vs1 field (funct6=0b010010)
            0b010010 => {
                let subfunct = vs1;
                match subfunct {
                    0b00000 => fp_unop(sew, a, f32_sqrt, f64_sqrt), // vfsqrt
                    0b00100 => fp_rsqrt7(sew, a),                   // vfrsqrt7
                    0b00101 => fp_rec7(sew, a),                     // vfrec7
                    0b10000 => fp_to_uint(sew, a),                  // vfcvt.xu.f
                    0b10001 => fp_to_int(sew, a),                   // vfcvt.x.f
                    0b10010 => uint_to_fp(sew, a),                  // vfcvt.f.xu
                    0b10011 => int_to_fp(sew, a),                   // vfcvt.f.x
                    0b10110 => fp_to_uint(sew, a),                  // vfcvt.rtz.xu.f
                    0b10111 => fp_to_int(sew, a),                   // vfcvt.rtz.x.f
                    // --- Widening FP conversions (vfwcvt, SEW→2*SEW) ---
                    0b01000 => {
                        // vfwcvt.xu.f.v: f(SEW) → uint(2*SEW)
                        let dsew = sew * 2;
                        let val = fp_to_uint(sew, a);
                        cpu.vregs.write_elem(vd, dsew, i, trunc_sew(val, dsew));
                        continue;
                    }
                    0b01001 => {
                        // vfwcvt.x.f.v: f(SEW) → int(2*SEW)
                        let dsew = sew * 2;
                        let val = fp_to_int(sew, a);
                        cpu.vregs.write_elem(
                            vd,
                            dsew,
                            i,
                            trunc_sew(sext_sew(val, sew) as u64, dsew),
                        );
                        continue;
                    }
                    0b01010 => {
                        // vfwcvt.f.xu.v: uint(SEW) → f(2*SEW)
                        let dsew = sew * 2;
                        cpu.vregs.write_elem(vd, dsew, i, fp_widen_cvt_xu(sew, a));
                        continue;
                    }
                    0b01011 => {
                        // vfwcvt.f.x.v: int(SEW) → f(2*SEW)
                        let dsew = sew * 2;
                        cpu.vregs.write_elem(vd, dsew, i, fp_widen_cvt_x(sew, a));
                        continue;
                    }
                    0b01100 => {
                        // vfwcvt.f.f.v: f(SEW) → f(2*SEW)
                        let dsew = sew * 2;
                        cpu.vregs.write_elem(vd, dsew, i, fp_widen_cvt_f(sew, a));
                        continue;
                    }
                    0b01110 => {
                        // vfwcvt.rtz.xu.f.v
                        let dsew = sew * 2;
                        cpu.vregs
                            .write_elem(vd, dsew, i, trunc_sew(fp_to_uint(sew, a), dsew));
                        continue;
                    }
                    0b01111 => {
                        // vfwcvt.rtz.x.f.v
                        let dsew = sew * 2;
                        let val = fp_to_int(sew, a);
                        cpu.vregs.write_elem(
                            vd,
                            dsew,
                            i,
                            trunc_sew(sext_sew(val, sew) as u64, dsew),
                        );
                        continue;
                    }
                    // --- Narrowing FP conversions (vfncvt, 2*SEW→SEW) ---
                    0b11000 => {
                        // vfncvt.xu.f.w: f(2*SEW) → uint(SEW)
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs
                            .write_elem(vd, sew, i, fp_narrow_cvt_xu(sew, wide));
                        continue;
                    }
                    0b11001 => {
                        // vfncvt.x.f.w: f(2*SEW) → int(SEW)
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs.write_elem(vd, sew, i, fp_narrow_cvt_x(sew, wide));
                        continue;
                    }
                    0b11010 => {
                        // vfncvt.f.xu.w: uint(2*SEW) → f(SEW)
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs.write_elem(vd, sew, i, uint_to_fp(sew, wide));
                        continue;
                    }
                    0b11011 => {
                        // vfncvt.f.x.w: int(2*SEW) → f(SEW)
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs.write_elem(vd, sew, i, int_to_fp(sew, wide));
                        continue;
                    }
                    0b11100 => {
                        // vfncvt.f.f.w: f(2*SEW) → f(SEW)
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs.write_elem(vd, sew, i, fp_narrow_cvt_f(sew, wide));
                        continue;
                    }
                    0b11101 => {
                        // vfncvt.rod.f.f.w
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs.write_elem(vd, sew, i, fp_narrow_cvt_f(sew, wide));
                        continue;
                    }
                    0b11110 => {
                        // vfncvt.rtz.xu.f.w
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs
                            .write_elem(vd, sew, i, fp_narrow_cvt_xu(sew, wide));
                        continue;
                    }
                    0b11111 => {
                        // vfncvt.rtz.x.f.w
                        let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                        cpu.vregs.write_elem(vd, sew, i, fp_narrow_cvt_x(sew, wide));
                        continue;
                    }
                    _ => continue,
                }
            }

            // vfclass (per-element FP classification → bit mask)
            0b010011 if vs1 == 0b10000 => match sew {
                32 => classify_f32(a) as u64,
                64 => classify_f64(a) as u64,
                _ => continue,
            },

            // Fused multiply-add family
            0b101000 => fp_fma(sew, a, cpu.vregs.read_elem(vd, sew, i), b), // vfmadd: vd=vs2*vd+vs1
            0b101001 => fp_fma(sew, fp_neg(sew, a), cpu.vregs.read_elem(vd, sew, i), b), // vfnmadd
            0b101010 => fp_fma(sew, a, cpu.vregs.read_elem(vd, sew, i), fp_neg(sew, b)), // vfmsub
            0b101011 => fp_fma(
                sew,
                fp_neg(sew, a),
                cpu.vregs.read_elem(vd, sew, i),
                fp_neg(sew, b),
            ), // vfnmsub
            0b101100 => fp_fma(sew, a, b, cpu.vregs.read_elem(vd, sew, i)), // vfmacc: vd=vs2*vs1+vd
            0b101101 => fp_neg(sew, fp_fma(sew, a, b, cpu.vregs.read_elem(vd, sew, i))), // vfnmacc
            0b101110 => fp_fma(sew, a, b, fp_neg(sew, cpu.vregs.read_elem(vd, sew, i))), // vfmsac
            0b101111 => fp_neg(
                sew,
                fp_fma(sew, a, b, fp_neg(sew, cpu.vregs.read_elem(vd, sew, i))),
            ), // vfnmsac

            // Comparisons
            0b011000 => u64::from(fp_eq(sew, a, b)), // vmfeq
            0b011001 => u64::from(fp_le(sew, a, b)), // vmfle
            0b011011 => u64::from(fp_lt(sew, a, b)), // vmflt
            0b011100 => u64::from(!fp_eq(sew, a, b) && !fp_is_nan(sew, a) && !fp_is_nan(sew, b)), // vmfne (ordered)
            0b011101 => u64::from(!fp_le(sew, a, b) && !fp_is_nan(sew, a)), // vmfgt (redundant enc)

            // --- Widening FP ops (SEW→2*SEW) ---
            0b110000 => {
                // vfwadd.vv
                let dsew = sew * 2;
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_binop(a, b, sew, f64_add));
                continue;
            }
            0b110010 => {
                // vfwsub.vv
                let dsew = sew * 2;
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_binop(a, b, sew, f64_sub));
                continue;
            }
            0b110100 => {
                // vfwadd.wv (vs2 is 2*SEW, vs1 is SEW)
                let dsew = sew * 2;
                let a_wide = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_w_binop(a_wide, b, sew, f64_add));
                continue;
            }
            0b110110 => {
                // vfwsub.wv (vs2 is 2*SEW, vs1 is SEW)
                let dsew = sew * 2;
                let a_wide = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_w_binop(a_wide, b, sew, f64_sub));
                continue;
            }
            0b111000 => {
                // vfwmul.vv
                let dsew = sew * 2;
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_binop(a, b, sew, f64_mul));
                continue;
            }
            // Widening FP FMA (vd is 2*SEW accumulator, vs2/vs1 are SEW)
            0b111100 => {
                // vfwmacc.vv: vd += vs2 * vs1 (widening)
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_fma(a, b, d, sew));
                continue;
            }
            0b111101 => {
                // vfwnmacc.vv: vd = -(vs2 * vs1) - vd
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_neg(dsew, fp_widen_fma(a, b, d, sew)));
                continue;
            }
            0b111110 => {
                // vfwmsac.vv: vd = vs2 * vs1 - vd
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_fma(a, b, fp_neg(dsew, d), sew));
                continue;
            }
            0b111111 => {
                // vfwnmsac.vv: vd = -(vs2 * vs1) + vd
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                let neg_prod_plus_d = fp_neg(dsew, fp_widen_fma(a, b, fp_neg(dsew, d), sew));
                cpu.vregs.write_elem(vd, dsew, i, neg_prod_plus_d);
                continue;
            }

            // --- Widening/narrowing FP conversions (encoded as unary ops) ---
            _ => continue,
        };

        if is_cmp {
            cpu.vregs.set_mask_bit(vd, i, result != 0);
        } else {
            cpu.vregs.write_elem(vd, sew, i, result);
        }
    }
}

/// FP classify for f32: returns 10-bit classification mask
fn classify_f32(bits: u64) -> u32 {
    let b = bits as u32;
    let sign = (b >> 31) & 1;
    let exp = (b >> 23) & 0xFF;
    let frac = b & 0x7FFFFF;
    match (sign, exp, frac) {
        (1, 0xFF, 0) => 1 << 0,                          // -inf
        (1, 0xFF, _) if frac & (1 << 22) == 0 => 1 << 8, // sNaN
        (1, 0xFF, _) => 1 << 9,                          // qNaN
        (1, 0, 0) => 1 << 3,                             // -0
        (1, 0, _) => 1 << 2,                             // -subnormal
        (1, _, _) => 1 << 1,                             // -normal
        (0, 0xFF, 0) => 1 << 7,                          // +inf
        (0, 0xFF, _) if frac & (1 << 22) == 0 => 1 << 8,
        (0, 0xFF, _) => 1 << 9,
        (0, 0, 0) => 1 << 4, // +0
        (0, 0, _) => 1 << 5, // +subnormal
        (0, _, _) => 1 << 6, // +normal
        _ => 0,
    }
}

/// FP classify for f64: returns 10-bit classification mask
fn classify_f64(bits: u64) -> u32 {
    let sign = (bits >> 63) & 1;
    let exp = ((bits >> 52) & 0x7FF) as u32;
    let frac = bits & 0xFFFFFFFFFFFFF;
    match (sign, exp, frac) {
        (1, 0x7FF, 0) => 1 << 0,
        (1, 0x7FF, _) if frac & (1 << 51) == 0 => 1 << 8,
        (1, 0x7FF, _) => 1 << 9,
        (1, 0, 0) => 1 << 3,
        (1, 0, _) => 1 << 2,
        (1, _, _) => 1 << 1,
        (0, 0x7FF, 0) => 1 << 7,
        (0, 0x7FF, _) if frac & (1 << 51) == 0 => 1 << 8,
        (0, 0x7FF, _) => 1 << 9,
        (0, 0, 0) => 1 << 4,
        (0, 0, _) => 1 << 5,
        (0, _, _) => 1 << 6,
        _ => 0,
    }
}

// ============================================================================
// OPFVF: vector-scalar floating-point (funct3=5)
// ============================================================================
fn execute_fvf(cpu: &mut Cpu, ctx: &VCtx, scalar: u64) {
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

        let is_cmp = matches!(funct6, 0b011000 | 0b011001 | 0b011011 | 0b011100 | 0b011101);

        let result = match funct6 {
            0b000000 => fp_binop(sew, a, b, f32_add, f64_add), // vfadd
            0b000010 => fp_binop(sew, a, b, f32_sub, f64_sub), // vfsub
            0b100111 => fp_binop(sew, b, a, f32_sub, f64_sub), // vfrsub
            0b001000 => fp_binop(sew, a, b, f32_mul, f64_mul), // vfmul
            0b100000 => fp_binop(sew, a, b, f32_div, f64_div), // vfdiv
            0b100001 => fp_binop(sew, b, a, f32_div, f64_div), // vfrdiv
            0b000100 => fp_binop(sew, a, b, f32_min, f64_min), // vfmin
            0b000110 => fp_binop(sew, a, b, f32_max, f64_max), // vfmax
            0b100100 => fp_sgnj(sew, a, b),                    // vfsgnj
            0b100101 => fp_sgnjn(sew, a, b),                   // vfsgnjn
            0b100110 => fp_sgnjx(sew, a, b),                   // vfsgnjx

            // vfmerge/vfmv
            0b010111 => {
                if vm == 1 {
                    // vfmv.v.f
                    b
                } else if cpu.vregs.mask_bit(i) {
                    b
                } else {
                    a
                }
            }

            // Fused multiply-add family
            0b101000 => fp_fma(sew, a, cpu.vregs.read_elem(vd, sew, i), b), // vfmadd
            0b101001 => fp_fma(sew, fp_neg(sew, a), cpu.vregs.read_elem(vd, sew, i), b), // vfnmadd
            0b101010 => fp_fma(sew, a, cpu.vregs.read_elem(vd, sew, i), fp_neg(sew, b)), // vfmsub
            0b101011 => fp_fma(
                sew,
                fp_neg(sew, a),
                cpu.vregs.read_elem(vd, sew, i),
                fp_neg(sew, b),
            ), // vfnmsub
            0b101100 => fp_fma(sew, a, b, cpu.vregs.read_elem(vd, sew, i)), // vfmacc
            0b101101 => fp_neg(sew, fp_fma(sew, a, b, cpu.vregs.read_elem(vd, sew, i))), // vfnmacc
            0b101110 => fp_fma(sew, a, b, fp_neg(sew, cpu.vregs.read_elem(vd, sew, i))), // vfmsac
            0b101111 => fp_neg(
                sew,
                fp_fma(sew, a, b, fp_neg(sew, cpu.vregs.read_elem(vd, sew, i))),
            ), // vfnmsac

            // Comparisons
            0b011000 => u64::from(fp_eq(sew, a, b)),
            0b011001 => u64::from(fp_le(sew, a, b)),
            0b011011 => u64::from(fp_lt(sew, a, b)),
            0b011100 => u64::from(!fp_eq(sew, a, b) && !fp_is_nan(sew, a) && !fp_is_nan(sew, b)),
            0b011101 => u64::from(!fp_le(sew, b, a)), // vmfgt (a > b)

            // --- Widening FP ops with scalar (.vf) ---
            0b110000 => {
                // vfwadd.vf
                let dsew = sew * 2;
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_binop(a, b, sew, f64_add));
                continue;
            }
            0b110010 => {
                // vfwsub.vf
                let dsew = sew * 2;
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_binop(a, b, sew, f64_sub));
                continue;
            }
            0b110100 => {
                // vfwadd.wf (vs2 is 2*SEW, scalar is SEW)
                let dsew = sew * 2;
                let a_wide = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_w_binop(a_wide, b, sew, f64_add));
                continue;
            }
            0b110110 => {
                // vfwsub.wf (vs2 is 2*SEW, scalar is SEW)
                let dsew = sew * 2;
                let a_wide = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_w_binop(a_wide, b, sew, f64_sub));
                continue;
            }
            0b111000 => {
                // vfwmul.vf
                let dsew = sew * 2;
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_binop(a, b, sew, f64_mul));
                continue;
            }
            0b111100 => {
                // vfwmacc.vf
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_fma(a, b, d, sew));
                continue;
            }
            0b111101 => {
                // vfwnmacc.vf
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_neg(dsew, fp_widen_fma(a, b, d, sew)));
                continue;
            }
            0b111110 => {
                // vfwmsac.vf
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs
                    .write_elem(vd, dsew, i, fp_widen_fma(a, b, fp_neg(dsew, d), sew));
                continue;
            }
            0b111111 => {
                // vfwnmsac.vf
                let dsew = sew * 2;
                let d = cpu.vregs.read_elem(vd, dsew, i);
                let neg_prod_plus_d = fp_neg(dsew, fp_widen_fma(a, b, fp_neg(dsew, d), sew));
                cpu.vregs.write_elem(vd, dsew, i, neg_prod_plus_d);
                continue;
            }

            _ => continue,
        };

        if is_cmp {
            cpu.vregs.set_mask_bit(vd, i, result != 0);
        } else {
            cpu.vregs.write_elem(vd, sew, i, result);
        }
    }

    // Handle vfmv.s.f separately (funct6=0b010000, vs2=0)
    if funct6 == 0b010000 && vl > 0 {
        cpu.vregs.write_elem(
            vd,
            sew,
            0,
            match sew {
                32 => scalar & 0xFFFFFFFF,
                _ => scalar,
            },
        );
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
// Saturating arithmetic helpers
// ============================================================================

/// Saturating unsigned add
fn sat_addu(a: u64, b: u64, sew: u32, cpu: &mut Cpu) -> u64 {
    let max = trunc_sew(u64::MAX, sew);
    let sum = a.wrapping_add(b);
    let result = trunc_sew(sum, sew);
    if a > max - (trunc_sew(b, sew)) {
        cpu.csrs.write(csr::VXSAT, 1);
        max
    } else {
        result
    }
}

/// Saturating signed add
fn sat_add(a: u64, b: u64, sew: u32, cpu: &mut Cpu) -> u64 {
    let sa = sext_sew(a, sew);
    let sb = sext_sew(b, sew);
    let sum = sa.wrapping_add(sb);
    let max = (1i64 << (sew - 1)) - 1;
    let min = -(1i64 << (sew - 1));
    if sum > max {
        cpu.csrs.write(csr::VXSAT, 1);
        trunc_sew(max as u64, sew)
    } else if sum < min {
        cpu.csrs.write(csr::VXSAT, 1);
        trunc_sew(min as u64, sew)
    } else {
        trunc_sew(sum as u64, sew)
    }
}

/// Saturating unsigned subtract
fn sat_subu(a: u64, b: u64, sew: u32, cpu: &mut Cpu) -> u64 {
    let ta = trunc_sew(a, sew);
    let tb = trunc_sew(b, sew);
    if ta < tb {
        cpu.csrs.write(csr::VXSAT, 1);
        0
    } else {
        trunc_sew(ta - tb, sew)
    }
}

/// Saturating signed subtract
fn sat_sub(a: u64, b: u64, sew: u32, cpu: &mut Cpu) -> u64 {
    let sa = sext_sew(a, sew);
    let sb = sext_sew(b, sew);
    let diff = sa.wrapping_sub(sb);
    let max = (1i64 << (sew - 1)) - 1;
    let min = -(1i64 << (sew - 1));
    if diff > max {
        cpu.csrs.write(csr::VXSAT, 1);
        trunc_sew(max as u64, sew)
    } else if diff < min {
        cpu.csrs.write(csr::VXSAT, 1);
        trunc_sew(min as u64, sew)
    } else {
        trunc_sew(diff as u64, sew)
    }
}

// ============================================================================
// Fixed-point helpers
// ============================================================================

/// vsmul: signed saturating fractional multiply (Q-format)
/// result = clip(roundoff_signed(vs2[i]*vs1[i], SEW-1))
fn vsmul(a: u64, b: u64, sew: u32, cpu: &mut Cpu) -> u64 {
    let sa = sext_sew(a, sew) as i128;
    let sb = sext_sew(b, sew) as i128;
    let product = sa * sb;
    let shift = sew - 1;
    let vxrm = (cpu.csrs.read(csr::VXRM) & 3) as u32;
    let round_inc = rounding_increment(product as u64 as u128, shift, vxrm);
    let shifted = (product >> shift) + round_inc as i128;
    let max = (1i128 << (sew - 1)) - 1;
    let min = -(1i128 << (sew - 1));
    if shifted > max {
        cpu.csrs
            .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
        trunc_sew(max as u64, sew)
    } else if shifted < min {
        cpu.csrs
            .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
        trunc_sew(min as u64, sew)
    } else {
        trunc_sew(shifted as u64, sew)
    }
}

/// Rounding increment based on vxrm mode
fn rounding_increment(val: u128, shift: u32, vxrm: u32) -> u64 {
    if shift == 0 {
        return 0;
    }
    let d = ((val >> (shift - 1)) & 1) != 0; // bit to be shifted out
    match vxrm {
        0 => u64::from(d), // rnu: round to nearest, ties up
        1 => {
            // rne: round to nearest, ties to even
            let odd = if shift >= 2 {
                (val & ((1u128 << (shift - 1)) - 1)) != 0
            } else {
                false
            };
            let lsb = ((val >> shift) & 1) != 0;
            u64::from(d && (odd || lsb))
        }
        2 => 0, // rdn: round down (truncate)
        3 => {
            // rod: round to odd
            let d_or_lower = (val & ((1u128 << shift) - 1)) != 0;
            let lsb = ((val >> shift) & 1) != 0;
            u64::from(!lsb && d_or_lower)
        }
        _ => 0,
    }
}

/// vssrl: scaling shift right logical with rounding
fn vssrl_op(a: u64, shift: u32, sew: u32, cpu: &Cpu) -> u64 {
    let val = trunc_sew(a, sew);
    if shift == 0 {
        return val;
    }
    let vxrm = (cpu.csrs.read(csr::VXRM) & 3) as u32;
    let round_inc = rounding_increment(val as u128, shift, vxrm);
    trunc_sew((val >> shift).wrapping_add(round_inc), sew)
}

/// vssra: scaling shift right arithmetic with rounding
fn vssra_op(a: u64, shift: u32, sew: u32, cpu: &Cpu) -> u64 {
    let val = sext_sew(a, sew);
    if shift == 0 {
        return trunc_sew(val as u64, sew);
    }
    let vxrm = (cpu.csrs.read(csr::VXRM) & 3) as u32;
    let round_inc = rounding_increment(a as u128, shift, vxrm);
    trunc_sew((val >> shift) as u64 + round_inc, sew)
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
            0b000001 => a & !trunc_sew(b, sew), // Zvbb: vandn.vv
            0b000010 => trunc_sew(a.wrapping_sub(b), sew),
            0b001001 => a & b,
            0b001010 => a | b,
            0b001011 => a ^ b,
            // Zvbb: vror.vv — rotate right
            0b010100 => {
                let shift = b & (sew as u64 - 1);
                let val = trunc_sew(a, sew);
                trunc_sew(
                    (val >> shift) | (val << ((sew as u64 - shift) & (sew as u64 - 1))),
                    sew,
                )
            }
            // Zvbb: vrol.vv — rotate left
            0b010101 => {
                let shift = b & (sew as u64 - 1);
                let val = trunc_sew(a, sew);
                trunc_sew(
                    (val << shift) | (val >> ((sew as u64 - shift) & (sew as u64 - 1))),
                    sew,
                )
            }
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
            // vrgather.vv: vd[i] = vs2[vs1[i]] (gather by index)
            0b001100 => {
                let vlmax = (VLEN as u64) / (sew as u64);
                let idx = b; // vs1[i] is the index
                if idx < vlmax {
                    cpu.vregs.read_elem(vs2, sew, idx as usize)
                } else {
                    0 // out-of-range → 0
                }
            }
            // vrgatherei16.vv: vd[i] = vs2[vs1[i]] (index is SEW=16)
            0b001110 => {
                let vlmax = (VLEN as u64) / (sew as u64);
                let idx = cpu.vregs.read_elem(vs1, 16, i) & 0xFFFF;
                let val = if idx < vlmax {
                    cpu.vregs.read_elem(vs2, sew, idx as usize)
                } else {
                    0
                };
                cpu.vregs.write_elem(vd, sew, i, val);
                continue;
            }
            // --- Saturating add/sub (OPIVV) ---
            0b100000 => sat_addu(a, b, sew, cpu), // vsaddu.vv
            0b100001 => sat_add(a, b, sew, cpu),  // vsadd.vv
            0b100010 => sat_subu(a, b, sew, cpu), // vssubu.vv
            0b100011 => sat_sub(a, b, sew, cpu),  // vssub.vv
            0b100111 => vsmul(a, b, sew, cpu),    // vsmul.vv
            0b101010 => {
                // vssrl.vv: scaling shift right logical (with rounding)
                let shift = b & ((sew - 1) as u64);
                vssrl_op(a, shift as u32, sew, cpu)
            }
            0b101011 => {
                // vssra.vv: scaling shift right arithmetic (with rounding)
                let shift = b & ((sew - 1) as u64);
                vssra_op(a, shift as u32, sew, cpu)
            }
            0b101110 => {
                // vnclipu.wv: narrowing clip unsigned (vs2 is 2*SEW)
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = cpu.vregs.read_elem(vs1, sew, i) & ((sew * 2 - 1) as u64);
                let rounded = vssrl_op(wide, shift as u32, sew * 2, cpu);
                let max = trunc_sew(u64::MAX, sew);
                if rounded > max {
                    cpu.csrs
                        .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
                    cpu.vregs.write_elem(vd, sew, i, max);
                } else {
                    cpu.vregs.write_elem(vd, sew, i, trunc_sew(rounded, sew));
                }
                continue;
            }
            0b101111 => {
                // vnclip.wv: narrowing clip signed (vs2 is 2*SEW)
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = cpu.vregs.read_elem(vs1, sew, i) & ((sew * 2 - 1) as u64);
                let rounded = vssra_op(wide, shift as u32, sew * 2, cpu) as i64;
                let sew_bits = sew as i64;
                let lo = -(1i64 << (sew_bits - 1));
                let hi = (1i64 << (sew_bits - 1)) - 1;
                let clamped = sext_sew(rounded as u64, sew * 2);
                if clamped < lo {
                    cpu.csrs
                        .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
                    cpu.vregs.write_elem(vd, sew, i, trunc_sew(lo as u64, sew));
                } else if clamped > hi {
                    cpu.csrs
                        .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
                    cpu.vregs.write_elem(vd, sew, i, trunc_sew(hi as u64, sew));
                } else {
                    cpu.vregs
                        .write_elem(vd, sew, i, trunc_sew(clamped as u64, sew));
                }
                continue;
            }
            0b011000 => u64::from(a == b),
            0b011001 => u64::from(a != b),
            0b011010 => u64::from(a < b),
            0b011011 => u64::from(sext_sew(a, sew) < sext_sew(b, sew)),
            0b011100 => u64::from(a <= b),
            0b011101 => u64::from(sext_sew(a, sew) <= sext_sew(b, sew)),
            // Narrowing shifts (vs2 is 2*SEW, vs1 is SEW shift amount, result is SEW)
            0b101100 => {
                // vnsrl.wv: narrow shift right logical
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = cpu.vregs.read_elem(vs1, sew, i) & ((sew * 2 - 1) as u64);
                trunc_sew(trunc_sew(wide, sew * 2) >> shift, sew)
            }
            0b101101 => {
                // vnsra.wv: narrow shift right arithmetic
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = cpu.vregs.read_elem(vs1, sew, i) & ((sew * 2 - 1) as u64);
                trunc_sew((sext_sew(wide, sew * 2) >> shift) as u64, sew)
            }
            // Zvbb: vwsll.vv — widening shift left logical (SEW → 2*SEW)
            0b110101 => {
                let dsew = sew * 2;
                let val = trunc_sew(a, sew);
                let shift = b & (dsew as u64 - 1);
                cpu.vregs
                    .write_elem(vd, dsew, i, trunc_sew(val << shift, dsew));
                continue;
            }
            _ => continue,
        };

        if is_cmp {
            cpu.vregs.set_mask_bit(vd, i, result != 0);
        } else if matches!(funct6, 0b101100 | 0b101101) {
            // Narrowing: write at SEW width
            cpu.vregs.write_elem(vd, sew, i, result);
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
            0b000001 => a & !trunc_sew(b, sew), // Zvbb: vandn.vx
            0b000011 => trunc_sew(b.wrapping_sub(a), sew),
            0b001001 => a & b,
            0b001010 => a | b,
            0b001011 => a ^ b,
            // Zvbb: vror.vx / vror.vi — rotate right
            0b010100 => {
                let shift = b & (sew as u64 - 1);
                let val = trunc_sew(a, sew);
                trunc_sew(
                    (val >> shift) | (val << ((sew as u64 - shift) & (sew as u64 - 1))),
                    sew,
                )
            }
            // Zvbb: vrol.vx — rotate left
            0b010101 => {
                let shift = b & (sew as u64 - 1);
                let val = trunc_sew(a, sew);
                trunc_sew(
                    (val << shift) | (val >> ((sew as u64 - shift) & (sew as u64 - 1))),
                    sew,
                )
            }
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
            // vrgather.vx / vrgather.vi: vd[i] = vs2[scalar]
            0b001100 => {
                let vlmax = (VLEN as u64) / (sew as u64);
                if b < vlmax {
                    cpu.vregs.read_elem(vs2, sew, b as usize)
                } else {
                    0
                }
            }
            // vslideup.vx / vslideup.vi
            0b001110 => {
                let offset = b as usize;
                if i >= offset {
                    cpu.vregs.read_elem(vs2, sew, i - offset)
                } else {
                    // elements below offset keep their original value in vd
                    continue;
                }
            }
            // vslidedown.vx / vslidedown.vi
            0b001111 => {
                let offset = b as usize;
                let vlmax = (VLEN as u64 / sew as u64) as usize;
                let src = i + offset;
                if src < vlmax {
                    cpu.vregs.read_elem(vs2, sew, src)
                } else {
                    0
                }
            }
            // --- Saturating add/sub (OPIVX/OPIVI) ---
            0b100000 => sat_addu(a, b, sew, cpu), // vsaddu.vx
            0b100001 => sat_add(a, b, sew, cpu),  // vsadd.vx
            0b100010 => sat_subu(a, b, sew, cpu), // vssubu.vx
            0b100011 => sat_sub(a, b, sew, cpu),  // vssub.vx
            0b100111 => vsmul(a, b, sew, cpu),    // vsmul.vx
            0b101010 => {
                // vssrl.vx / vssrl.vi
                let shift = b & ((sew - 1) as u64);
                vssrl_op(a, shift as u32, sew, cpu)
            }
            0b101011 => {
                // vssra.vx / vssra.vi
                let shift = b & ((sew - 1) as u64);
                vssra_op(a, shift as u32, sew, cpu)
            }
            0b101110 => {
                // vnclipu.wx / vnclipu.wi
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = b & ((sew * 2 - 1) as u64);
                let rounded = vssrl_op(wide, shift as u32, sew * 2, cpu);
                let max = trunc_sew(u64::MAX, sew);
                if rounded > max {
                    cpu.csrs
                        .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
                    cpu.vregs.write_elem(vd, sew, i, max);
                } else {
                    cpu.vregs.write_elem(vd, sew, i, trunc_sew(rounded, sew));
                }
                continue;
            }
            0b101111 => {
                // vnclip.wx / vnclip.wi
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = b & ((sew * 2 - 1) as u64);
                let rounded = vssra_op(wide, shift as u32, sew * 2, cpu) as i64;
                let sew_bits = sew as i64;
                let lo = -(1i64 << (sew_bits - 1));
                let hi = (1i64 << (sew_bits - 1)) - 1;
                let clamped = sext_sew(rounded as u64, sew * 2);
                if clamped < lo {
                    cpu.csrs
                        .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
                    cpu.vregs.write_elem(vd, sew, i, trunc_sew(lo as u64, sew));
                } else if clamped > hi {
                    cpu.csrs
                        .write_raw(csr::VXSAT, cpu.csrs.read(csr::VXSAT) | 1);
                    cpu.vregs.write_elem(vd, sew, i, trunc_sew(hi as u64, sew));
                } else {
                    cpu.vregs
                        .write_elem(vd, sew, i, trunc_sew(clamped as u64, sew));
                }
                continue;
            }
            0b011000 => u64::from(a == b),
            0b011001 => u64::from(a != b),
            0b011100 => u64::from(a <= b),
            0b011101 => u64::from(sext_sew(a, sew) <= sext_sew(b, sew)),
            0b011110 => u64::from(a > b),
            0b011111 => u64::from(sext_sew(a, sew) > sext_sew(b, sew)),
            // Narrowing shifts with scalar/immediate shift amount
            0b101100 => {
                // vnsrl.wx / vnsrl.wi
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = b & ((sew * 2 - 1) as u64);
                trunc_sew(trunc_sew(wide, sew * 2) >> shift, sew)
            }
            0b101101 => {
                // vnsra.wx / vnsra.wi
                let wide = cpu.vregs.read_elem(vs2, sew * 2, i);
                let shift = b & ((sew * 2 - 1) as u64);
                trunc_sew((sext_sew(wide, sew * 2) >> shift) as u64, sew)
            }
            // Zvbb: vwsll.vx / vwsll.vi — widening shift left logical
            0b110101 => {
                let dsew = sew * 2;
                let val = trunc_sew(a, sew);
                let shift = b & (dsew as u64 - 1);
                cpu.vregs
                    .write_elem(vd, dsew, i, trunc_sew(val << shift, dsew));
                continue;
            }
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
// Integer multiply helpers (full-width multiply for upper-half)
// ============================================================================

/// Unsigned full multiply, return high half
fn mulhu_sew(a: u64, b: u64, sew: u32) -> u64 {
    match sew {
        8 => ((a as u8 as u16).wrapping_mul(b as u8 as u16) >> 8) as u64,
        16 => ((a as u16 as u32).wrapping_mul(b as u16 as u32) >> 16) as u64,
        32 => u64::from(a as u32).wrapping_mul(u64::from(b as u32)) >> 32,
        _ => ((a as u128).wrapping_mul(b as u128) >> 64) as u64,
    }
}

/// Signed full multiply, return high half
fn mulh_sew(a: u64, b: u64, sew: u32) -> u64 {
    match sew {
        8 => ((sext_sew(a, 8) as i16).wrapping_mul(sext_sew(b, 8) as i16) >> 8) as u64,
        16 => ((sext_sew(a, 16) as i32).wrapping_mul(sext_sew(b, 16) as i32) >> 16) as u64,
        32 => {
            let sa = sext_sew(a, 32) as i128;
            let sb = sext_sew(b, 32) as i128;
            (sa.wrapping_mul(sb) >> 32) as u64
        }
        _ => ((sext_sew(a, 64) as i128).wrapping_mul(sext_sew(b, 64) as i128) >> 64) as u64,
    }
}

/// Signed×unsigned multiply, return high half (rs2 signed, rs1 unsigned)
fn mulhsu_sew(a: u64, b: u64, sew: u32) -> u64 {
    // a = vs2 (signed), b = vs1 (unsigned)
    match sew {
        8 => ((sext_sew(a, 8) as i16).wrapping_mul(b as u8 as i16) >> 8) as u64,
        16 => ((sext_sew(a, 16) as i32).wrapping_mul(b as u16 as i32) >> 16) as u64,
        32 => {
            let sa = sext_sew(a, 32) as i128;
            let ub = u64::from(b as u32) as i128;
            (sa.wrapping_mul(ub) >> 32) as u64
        }
        _ => ((sext_sew(a, 64) as i128).wrapping_mul(b as i128) >> 64) as u64,
    }
}

/// Signed division with RISC-V overflow/div-by-zero semantics
fn div_sew(a: u64, b: u64, sew: u32) -> u64 {
    let sa = sext_sew(a, sew);
    let sb = sext_sew(b, sew);
    if sb == 0 {
        // Division by zero → all ones
        u64::MAX
    } else if sa == sext_sew(1u64 << (sew - 1), sew) && sb == -1 {
        // Overflow: min_signed / -1 → min_signed
        trunc_sew(a, sew)
    } else {
        trunc_sew(sa.wrapping_div(sb) as u64, sew)
    }
}

fn divu_sew(a: u64, b: u64, sew: u32) -> u64 {
    let ua = trunc_sew(a, sew);
    let ub = trunc_sew(b, sew);
    if ub == 0 {
        trunc_sew(u64::MAX, sew)
    } else {
        trunc_sew(ua / ub, sew)
    }
}

fn rem_sew(a: u64, b: u64, sew: u32) -> u64 {
    let sa = sext_sew(a, sew);
    let sb = sext_sew(b, sew);
    if sb == 0 {
        trunc_sew(a, sew)
    } else if sa == sext_sew(1u64 << (sew - 1), sew) && sb == -1 {
        0
    } else {
        trunc_sew(sa.wrapping_rem(sb) as u64, sew)
    }
}

fn remu_sew(a: u64, b: u64, sew: u32) -> u64 {
    let ua = trunc_sew(a, sew);
    let ub = trunc_sew(b, sew);
    if ub == 0 {
        trunc_sew(a, sew)
    } else {
        trunc_sew(ua % ub, sew)
    }
}

// ============================================================================
// Widening helpers: operate on SEW-width elements, produce 2*SEW results
// ============================================================================

/// Unsigned widen: zero-extend to 2*SEW, add
fn wop_addu(a: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(trunc_sew(a, sew).wrapping_add(trunc_sew(b, sew)), sew * 2)
}
fn wop_add(a: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(
        sext_sew(a, sew).wrapping_add(sext_sew(b, sew)) as u64,
        sew * 2,
    )
}
fn wop_subu(a: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(trunc_sew(a, sew).wrapping_sub(trunc_sew(b, sew)), sew * 2)
}
fn wop_sub(a: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(
        sext_sew(a, sew).wrapping_sub(sext_sew(b, sew)) as u64,
        sew * 2,
    )
}
/// .wv variants: vs2 is already 2*SEW, vs1 is SEW
fn wop_waddu(a2w: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(
        trunc_sew(a2w, sew * 2).wrapping_add(trunc_sew(b, sew)),
        sew * 2,
    )
}
fn wop_wadd(a2w: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(
        (sext_sew(a2w, sew * 2)).wrapping_add(sext_sew(b, sew)) as u64,
        sew * 2,
    )
}
fn wop_wsubu(a2w: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(
        trunc_sew(a2w, sew * 2).wrapping_sub(trunc_sew(b, sew)),
        sew * 2,
    )
}
fn wop_wsub(a2w: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(
        (sext_sew(a2w, sew * 2)).wrapping_sub(sext_sew(b, sew)) as u64,
        sew * 2,
    )
}

fn wmul_uu(a: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(trunc_sew(a, sew).wrapping_mul(trunc_sew(b, sew)), sew * 2)
}
fn wmul_ss(a: u64, b: u64, sew: u32) -> u64 {
    trunc_sew(
        (sext_sew(a, sew)).wrapping_mul(sext_sew(b, sew)) as u64,
        sew * 2,
    )
}
fn wmul_su(a: u64, b: u64, sew: u32) -> u64 {
    // a signed, b unsigned
    trunc_sew(
        (sext_sew(a, sew)).wrapping_mul(trunc_sew(b, sew) as i64) as u64,
        sew * 2,
    )
}

// ============================================================================
// OPMVV (funct3=2): reductions, multiply, divide, widening, extensions
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
        // --- Reductions ---
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

        // --- vmv.x.s / vcpop.m / vfirst.m (funct6=0b010000) ---
        0b010000 => {
            match vs1 {
                0b00000 => {
                    // vmv.x.s: x[rd] = vs2[0]
                    let val = if vl > 0 {
                        sext_sew(cpu.vregs.read_elem(vs2, sew, 0), sew) as u64
                    } else {
                        0
                    };
                    cpu.regs[vd] = val;
                }
                0b10000 => {
                    // vcpop.m: count set bits in mask vs2
                    let mut count = 0u64;
                    for i in 0..vl as usize {
                        if elem_active(cpu, vm, i) && cpu.vregs.mask_bit_of(vs2, i) {
                            count += 1;
                        }
                    }
                    cpu.regs[vd] = count;
                }
                0b10001 => {
                    // vfirst.m: find first set bit in mask vs2
                    let mut result: i64 = -1;
                    for i in 0..vl as usize {
                        if elem_active(cpu, vm, i) && cpu.vregs.mask_bit_of(vs2, i) {
                            result = i as i64;
                            break;
                        }
                    }
                    cpu.regs[vd] = result as u64;
                }
                _ => {}
            }
        }

        // --- Mask-register logical ops (funct6=0b010100) ---
        0b010100 => {
            match vs1 {
                0b00001 => {
                    // vmsbf.m: set-before-first mask bit
                    let mut found = false;
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        if !found && cpu.vregs.mask_bit_of(vs2, i) {
                            found = true;
                            cpu.vregs.set_mask_bit(vd, i, false);
                        } else {
                            cpu.vregs.set_mask_bit(vd, i, !found);
                        }
                    }
                }
                0b00010 => {
                    // vmsof.m: set-only-first mask bit
                    let mut found = false;
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        if !found && cpu.vregs.mask_bit_of(vs2, i) {
                            found = true;
                            cpu.vregs.set_mask_bit(vd, i, true);
                        } else {
                            cpu.vregs.set_mask_bit(vd, i, false);
                        }
                    }
                }
                0b00011 => {
                    // vmsif.m: set-including-first mask bit
                    let mut found = false;
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        if !found {
                            cpu.vregs.set_mask_bit(vd, i, true);
                            if cpu.vregs.mask_bit_of(vs2, i) {
                                found = true;
                            }
                        } else {
                            cpu.vregs.set_mask_bit(vd, i, false);
                        }
                    }
                }
                0b10000 => {
                    // viota.m: iota (prefix sum of mask bits)
                    let mut count = 0u64;
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        cpu.vregs.write_elem(vd, sew, i, count);
                        if cpu.vregs.mask_bit_of(vs2, i) {
                            count += 1;
                        }
                    }
                }
                0b10001 => {
                    // vid.v: vector of element indices
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        cpu.vregs.write_elem(vd, sew, i, i as u64);
                    }
                }
                _ => {}
            }
        }

        // --- vcompress.vm (funct6=0b010111) ---
        0b010111 => {
            // compress: gather active elements from vs2 using vs1 as mask, pack into vd
            let mut j = 0usize;
            for i in 0..vl as usize {
                if cpu.vregs.mask_bit_of(vs1, i) {
                    let val = cpu.vregs.read_elem(vs2, sew, i);
                    cpu.vregs.write_elem(vd, sew, j, val);
                    j += 1;
                }
            }
            // remaining elements in vd are unchanged (tail undisturbed by default)
        }

        // --- Averaging add/sub (OPMVV) ---
        0b001000 => {
            // vaaddu.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i) as u128;
                let b = cpu.vregs.read_elem(vs1, sew, i) as u128;
                let sum = a + b;
                let rnd = (cpu.csrs.read(csr::VXRM) & 3) as u128;
                let r = match rnd {
                    0 => sum >> 1,       // rnu
                    1 => (sum + 1) >> 1, // rne (round to nearest, ties to even — simplified)
                    2 => sum >> 1,       // rdn
                    _ => sum >> 1,       // rod
                };
                cpu.vregs.write_elem(vd, sew, i, trunc_sew(r as u64, sew));
            }
        }
        0b001001 => {
            // vaadd.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = sext_sew(cpu.vregs.read_elem(vs2, sew, i), sew) as i128;
                let b = sext_sew(cpu.vregs.read_elem(vs1, sew, i), sew) as i128;
                let sum = a + b;
                let r = sum >> 1;
                cpu.vregs.write_elem(vd, sew, i, trunc_sew(r as u64, sew));
            }
        }
        0b001010 => {
            // vasubu.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i) as u128;
                let b = cpu.vregs.read_elem(vs1, sew, i) as u128;
                let diff = a.wrapping_sub(b);
                let r = diff >> 1;
                cpu.vregs.write_elem(vd, sew, i, trunc_sew(r as u64, sew));
            }
        }
        0b001011 => {
            // vasub.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = sext_sew(cpu.vregs.read_elem(vs2, sew, i), sew) as i128;
                let b = sext_sew(cpu.vregs.read_elem(vs1, sew, i), sew) as i128;
                let diff = a - b;
                let r = diff >> 1;
                cpu.vregs.write_elem(vd, sew, i, trunc_sew(r as u64, sew));
            }
        }

        // --- vzext / vsext / Zvbb unary ops (funct6=0b010010, vs1 encodes variant) ---
        0b010010 => {
            match vs1 {
                // Zvbb unary operations
                0b01000 => {
                    // vbrev8.v: byte-reverse within each byte (= reverse bits in each byte)
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        let val = cpu.vregs.read_elem(vs2, sew, i);
                        let mut result = 0u64;
                        for byte_idx in 0..(sew / 8) as usize {
                            let b = ((val >> (byte_idx * 8)) & 0xFF) as u8;
                            let reversed = b.reverse_bits();
                            result |= (reversed as u64) << (byte_idx * 8);
                        }
                        cpu.vregs.write_elem(vd, sew, i, trunc_sew(result, sew));
                    }
                }
                0b01001 => {
                    // vrev8.v: reverse byte order within each element
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        let val = cpu.vregs.read_elem(vs2, sew, i);
                        let nbytes = (sew / 8) as usize;
                        let mut result = 0u64;
                        for byte_idx in 0..nbytes {
                            let b = (val >> (byte_idx * 8)) & 0xFF;
                            result |= b << ((nbytes - 1 - byte_idx) * 8);
                        }
                        cpu.vregs.write_elem(vd, sew, i, trunc_sew(result, sew));
                    }
                }
                0b01010 => {
                    // vbrev.v: reverse all bits within each element
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        let val = cpu.vregs.read_elem(vs2, sew, i);
                        let result = match sew {
                            8 => (val as u8).reverse_bits() as u64,
                            16 => (val as u16).reverse_bits() as u64,
                            32 => (val as u32).reverse_bits() as u64,
                            64 => val.reverse_bits(),
                            _ => val,
                        };
                        cpu.vregs.write_elem(vd, sew, i, result);
                    }
                }
                0b01100 => {
                    // vclz.v: count leading zeros within each element
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        let val = cpu.vregs.read_elem(vs2, sew, i);
                        let result = match sew {
                            8 => (val as u8).leading_zeros() as u64,
                            16 => (val as u16).leading_zeros() as u64,
                            32 => (val as u32).leading_zeros() as u64,
                            64 => val.leading_zeros() as u64,
                            _ => 0,
                        };
                        cpu.vregs.write_elem(vd, sew, i, result);
                    }
                }
                0b01101 => {
                    // vctz.v: count trailing zeros within each element
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        let val = cpu.vregs.read_elem(vs2, sew, i);
                        let result = match sew {
                            8 => {
                                if val & 0xFF == 0 {
                                    8
                                } else {
                                    (val as u8).trailing_zeros() as u64
                                }
                            }
                            16 => {
                                if val & 0xFFFF == 0 {
                                    16
                                } else {
                                    (val as u16).trailing_zeros() as u64
                                }
                            }
                            32 => (val as u32).trailing_zeros() as u64,
                            64 => val.trailing_zeros() as u64,
                            _ => 0,
                        };
                        cpu.vregs.write_elem(vd, sew, i, result);
                    }
                }
                0b01110 => {
                    // vcpop.v: population count (count ones) within each element
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        let val = cpu.vregs.read_elem(vs2, sew, i);
                        let result = trunc_sew(val, sew).count_ones() as u64;
                        cpu.vregs.write_elem(vd, sew, i, result);
                    }
                }
                // vzext / vsext
                0b00010..=0b00111 => {
                    let src_sew = match vs1 {
                        0b00010 | 0b00011 => sew / 8,
                        0b00100 | 0b00101 => sew / 4,
                        _ => sew / 2,
                    };
                    if src_sew < 8 {
                        return;
                    }
                    let signed = vs1 & 1 != 0;
                    for i in 0..vl as usize {
                        if !elem_active(cpu, vm, i) {
                            continue;
                        }
                        let val = cpu.vregs.read_elem(vs2, src_sew, i);
                        let result = if signed {
                            trunc_sew(sext_sew(val, src_sew) as u64, sew)
                        } else {
                            trunc_sew(val, sew)
                        };
                        cpu.vregs.write_elem(vd, sew, i, result);
                    }
                }
                _ => (),
            }
        }

        // --- Integer multiply ---
        0b100100 => {
            // vmulhu.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(mulhu_sew(a, b, sew), sew));
            }
        }
        0b100101 => {
            // vmul.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(a.wrapping_mul(b), sew));
            }
        }
        0b100110 => {
            // vmulhsu.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(mulhsu_sew(a, b, sew), sew));
            }
        }
        0b100111 => {
            // vmulh.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(mulh_sew(a, b, sew), sew));
            }
        }

        // --- Integer divide ---
        0b100000 => {
            // vdivu.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, sew, i, divu_sew(a, b, sew));
            }
        }
        0b100001 => {
            // vdiv.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, sew, i, div_sew(a, b, sew));
            }
        }
        0b100010 => {
            // vremu.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, sew, i, remu_sew(a, b, sew));
            }
        }
        0b100011 => {
            // vrem.vv
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, sew, i, rem_sew(a, b, sew));
            }
        }

        // --- Vector multiply-add (accumulate into vd) ---
        0b101101 => {
            // vmacc.vv: vd[i] = (vs1[i] * vs2[i]) + vd[i]
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs1, sew, i);
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(a.wrapping_mul(b).wrapping_add(d), sew),
                );
            }
        }
        0b101111 => {
            // vnmsac.vv: vd[i] = -(vs1[i] * vs2[i]) + vd[i]
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs1, sew, i);
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(d.wrapping_sub(a.wrapping_mul(b)), sew),
                );
            }
        }
        0b101001 => {
            // vmadd.vv: vd[i] = (vs1[i] * vd[i]) + vs2[i]
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs1, sew, i);
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(a.wrapping_mul(d).wrapping_add(b), sew),
                );
            }
        }
        0b101011 => {
            // vnmsub.vv: vd[i] = -(vs1[i] * vd[i]) + vs2[i]
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs1, sew, i);
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(b.wrapping_sub(a.wrapping_mul(d)), sew),
                );
            }
        }

        // --- Widening integer add/sub (SEW→2*SEW) ---
        0b110000 => {
            // vwaddu.vv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_addu(a, b, sew));
            }
        }
        0b110001 => {
            // vwadd.vv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_add(a, b, sew));
            }
        }
        0b110010 => {
            // vwsubu.vv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_subu(a, b, sew));
            }
        }
        0b110011 => {
            // vwsub.vv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_sub(a, b, sew));
            }
        }
        0b110100 => {
            // vwaddu.wv (vs2 is 2*SEW, vs1 is SEW)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_waddu(a, b, sew));
            }
        }
        0b110101 => {
            // vwadd.wv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_wadd(a, b, sew));
            }
        }
        0b110110 => {
            // vwsubu.wv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_wsubu(a, b, sew));
            }
        }
        0b110111 => {
            // vwsub.wv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_wsub(a, b, sew));
            }
        }

        // --- Widening multiply ---
        0b111000 => {
            // vwmulu.vv
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wmul_uu(a, b, sew));
            }
        }
        0b111010 => {
            // vwmulsu.vv (vs2 signed, vs1 unsigned)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wmul_su(a, b, sew));
            }
        }
        0b111011 => {
            // vwmul.vv (both signed)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                let b = cpu.vregs.read_elem(vs1, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wmul_ss(a, b, sew));
            }
        }

        // --- Widening multiply-accumulate ---
        0b111100 => {
            // vwmaccu.vv: vd[i] += vs1[i] * vs2[i] (unsigned, widening)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs1, sew, i);
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs.write_elem(
                    vd,
                    dsew,
                    i,
                    trunc_sew(d.wrapping_add(wmul_uu(a, b, sew)), dsew),
                );
            }
        }
        0b111101 => {
            // vwmacc.vv: vd[i] += vs1[i] * vs2[i] (signed, widening)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs1, sew, i);
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs.write_elem(
                    vd,
                    dsew,
                    i,
                    trunc_sew(d.wrapping_add(wmul_ss(a, b, sew)), dsew),
                );
            }
        }
        0b111110 => {
            // vwmaccsu.vv: vd[i] += vs2[i](signed) * vs1[i](unsigned)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs1, sew, i);
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs.write_elem(
                    vd,
                    dsew,
                    i,
                    trunc_sew(d.wrapping_add(wmul_su(b, a, sew)), dsew),
                );
            }
        }

        // --- Mask-register logical operations ---
        0b011000 => {
            // vmand.mm
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, a && b);
            }
        }
        0b011001 => {
            // vmnand.mm
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, !(a && b));
            }
        }
        0b011010 => {
            // vmandn.mm (vmandnot)
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, a && !b);
            }
        }
        0b011011 => {
            // vmxor.mm
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, a ^ b);
            }
        }
        0b011100 => {
            // vmor.mm
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, a || b);
            }
        }
        0b011101 => {
            // vmnor.mm
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, !(a || b));
            }
        }
        0b011110 => {
            // vmorn.mm (vmornot)
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, a || !b);
            }
        }
        0b011111 => {
            // vmxnor.mm
            for i in 0..vl as usize {
                let a = cpu.vregs.mask_bit_of(vs2, i);
                let b = cpu.vregs.mask_bit_of(vs1, i);
                cpu.vregs.set_mask_bit(vd, i, a == b);
            }
        }

        _ => {}
    }
}

// ============================================================================
// OP-P (opcode 0x77): Vector crypto instructions (Zvkned, Zvknhb)
// ============================================================================
fn execute_v_crypto(cpu: &mut Cpu, raw: u32, inst_len: u64) -> bool {
    let funct3 = (raw >> 12) & 0x7;
    let vd = ((raw >> 7) & 0x1F) as usize;
    let vs1 = ((raw >> 15) & 0x1F) as usize;
    let vs2 = ((raw >> 20) & 0x1F) as usize;
    let funct6 = (raw >> 26) & 0x3F;

    let vtype = current_vtype(cpu);
    if vtype.vill {
        return false;
    }

    // Only OPMVV encoding (funct3=2)
    if funct3 != 2 {
        return false;
    }

    // Dispatch Zvknhb (SHA-2) instructions — accept SEW=32 or SEW=64
    match funct6 {
        0b101101..=0b101111 if vtype.sew == 32 || vtype.sew == 64 => {
            return execute_v_sha2(cpu, vd, vs1, vs2, funct6, vtype.sew, inst_len);
        }
        _ => {}
    }

    // All Zvkned instructions require SEW=32
    if vtype.sew != 32 {
        return false;
    }
    let vl = current_vl(cpu);
    let num_groups = vl as usize / 4;
    if num_groups == 0 {
        cpu.pc += inst_len;
        return true;
    }

    set_vs_dirty(cpu);

    match funct6 {
        0b101000 if matches!(vs1, 0..=3) => {
            // vaes*.vv: vaesdm(0), vaesdf(1), vaesem(2), vaesef(3)
            for g in 0..num_groups {
                let base = g * 4;
                let mut state = aes_read_group(cpu, vd, base);
                let rk = aes_read_group(cpu, vs2, base);
                match vs1 {
                    0 => aes_decrypt_middle(&mut state, &rk),
                    1 => aes_decrypt_final(&mut state, &rk),
                    2 => aes_encrypt_middle(&mut state, &rk),
                    3 => aes_encrypt_final(&mut state, &rk),
                    _ => unreachable!(),
                }
                aes_write_group(cpu, vd, base, &state);
            }
        }
        0b101001 if matches!(vs1, 0..=3) => {
            // vaes*.vs: scalar round key from vs2[0]
            let rk = aes_read_group(cpu, vs2, 0);
            for g in 0..num_groups {
                let base = g * 4;
                let mut state = aes_read_group(cpu, vd, base);
                match vs1 {
                    0 => aes_decrypt_middle(&mut state, &rk),
                    1 => aes_decrypt_final(&mut state, &rk),
                    2 => aes_encrypt_middle(&mut state, &rk),
                    3 => aes_encrypt_final(&mut state, &rk),
                    _ => unreachable!(),
                }
                aes_write_group(cpu, vd, base, &state);
            }
        }
        0b100010 => {
            // vaeskf1.vi — AES-128 key schedule
            let rnum = vs1 as u32;
            for g in 0..num_groups {
                let base = g * 4;
                let current_key = aes_read_group(cpu, vs2, base);
                let new_key = aes_keyschedule_128(&current_key, rnum);
                aes_write_group(cpu, vd, base, &new_key);
            }
        }
        0b101010 => {
            // vaeskf2.vi — AES-256 key schedule
            let rnum = vs1 as u32;
            for g in 0..num_groups {
                let base = g * 4;
                let prev_key = aes_read_group(cpu, vs2, base);
                let current_key = aes_read_group(cpu, vd, base);
                let new_key = aes_keyschedule_256(&prev_key, &current_key, rnum);
                aes_write_group(cpu, vd, base, &new_key);
            }
        }
        _ => return false,
    }

    cpu.pc += inst_len;
    true
}

// ============================================================================
// Zvknhb: Vector SHA-2 (SHA-256 with SEW=32, SHA-512 with SEW=64)
// ============================================================================

/// Read a 4-element group at SEW width from a vector register.
fn sha2_read_group_u32(cpu: &Cpu, vreg: usize, base: usize) -> [u32; 4] {
    [
        cpu.vregs.read_elem(vreg, 32, base) as u32,
        cpu.vregs.read_elem(vreg, 32, base + 1) as u32,
        cpu.vregs.read_elem(vreg, 32, base + 2) as u32,
        cpu.vregs.read_elem(vreg, 32, base + 3) as u32,
    ]
}

fn sha2_write_group_u32(cpu: &mut Cpu, vreg: usize, base: usize, g: &[u32; 4]) {
    for (i, &val) in g.iter().enumerate() {
        cpu.vregs.write_elem(vreg, 32, base + i, val as u64);
    }
}

fn sha2_read_group_u64(cpu: &Cpu, vreg: usize, base: usize) -> [u64; 4] {
    [
        cpu.vregs.read_elem(vreg, 64, base),
        cpu.vregs.read_elem(vreg, 64, base + 1),
        cpu.vregs.read_elem(vreg, 64, base + 2),
        cpu.vregs.read_elem(vreg, 64, base + 3),
    ]
}

fn sha2_write_group_u64(cpu: &mut Cpu, vreg: usize, base: usize, g: &[u64; 4]) {
    for (i, &val) in g.iter().enumerate() {
        cpu.vregs.write_elem(vreg, 64, base + i, val);
    }
}

// SHA-256 sigma functions (lowercase = message schedule)
#[inline]
fn sha256_sig0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}
#[inline]
fn sha256_sig1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}
// SHA-256 Sigma functions (uppercase = compression)
#[inline]
fn sha256_sum0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}
#[inline]
fn sha256_sum1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

// SHA-512 sigma functions
#[inline]
fn sha512_sig0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}
#[inline]
fn sha512_sig1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}
// SHA-512 Sigma functions
#[inline]
fn sha512_sum0(x: u64) -> u64 {
    x.rotate_right(28) ^ x.rotate_right(34) ^ x.rotate_right(39)
}
#[inline]
fn sha512_sum1(x: u64) -> u64 {
    x.rotate_right(14) ^ x.rotate_right(18) ^ x.rotate_right(41)
}

#[inline]
fn sha_ch<
    T: std::ops::BitAnd<Output = T> + std::ops::BitXor<Output = T> + std::ops::Not<Output = T> + Copy,
>(
    x: T,
    y: T,
    z: T,
) -> T {
    (x & y) ^ ((!x) & z)
}
#[inline]
fn sha_maj<T: std::ops::BitAnd<Output = T> + std::ops::BitXor<Output = T> + Copy>(
    x: T,
    y: T,
    z: T,
) -> T {
    (x & y) ^ (x & z) ^ (y & z)
}

fn execute_v_sha2(
    cpu: &mut Cpu,
    vd: usize,
    vs1: usize,
    vs2: usize,
    funct6: u32,
    sew: u32,
    inst_len: u64,
) -> bool {
    let vl = current_vl(cpu);
    let num_groups = vl as usize / 4;
    if num_groups == 0 {
        cpu.pc += inst_len;
        return true;
    }

    set_vs_dirty(cpu);

    match sew {
        32 => execute_v_sha2_32(cpu, vd, vs1, vs2, funct6, num_groups),
        64 => execute_v_sha2_64(cpu, vd, vs1, vs2, funct6, num_groups),
        _ => return false,
    }

    cpu.pc += inst_len;
    true
}

fn execute_v_sha2_32(
    cpu: &mut Cpu,
    vd: usize,
    vs1: usize,
    vs2: usize,
    funct6: u32,
    num_groups: usize,
) {
    for g in 0..num_groups {
        let base = g * 4;
        match funct6 {
            0b101101 => {
                // vsha2ms.vv — SHA-256 message schedule
                let w_vd = sha2_read_group_u32(cpu, vd, base); // {W[3], W[2], W[1], W[0]}
                let w_vs2 = sha2_read_group_u32(cpu, vs2, base); // {W[11], W[10], W[9], W[4]}
                let w_vs1 = sha2_read_group_u32(cpu, vs1, base); // {W[15], W[14], W[13], W[12]}
                let w16 = sha256_sig1(w_vs1[2])
                    .wrapping_add(w_vs2[1])
                    .wrapping_add(sha256_sig0(w_vd[1]))
                    .wrapping_add(w_vd[0]);
                let w17 = sha256_sig1(w_vs1[3])
                    .wrapping_add(w_vs2[2])
                    .wrapping_add(sha256_sig0(w_vd[2]))
                    .wrapping_add(w_vd[1]);
                let w18 = sha256_sig1(w16)
                    .wrapping_add(w_vs2[3])
                    .wrapping_add(sha256_sig0(w_vd[3]))
                    .wrapping_add(w_vd[2]);
                let w19 = sha256_sig1(w17)
                    .wrapping_add(w_vs1[0])
                    .wrapping_add(sha256_sig0(w_vs2[0]))
                    .wrapping_add(w_vd[3]);
                sha2_write_group_u32(cpu, vd, base, &[w16, w17, w18, w19]);
            }
            0b101110 => {
                // vsha2ch.vv — SHA-256 compression high (uses words [3:2] from vs1)
                sha2_compress_32(cpu, vd, vs1, vs2, base, true);
            }
            0b101111 => {
                // vsha2cl.vv — SHA-256 compression low (uses words [1:0] from vs1)
                sha2_compress_32(cpu, vd, vs1, vs2, base, false);
            }
            _ => {}
        }
    }
}

#[allow(unused_assignments)]
fn sha2_compress_32(cpu: &mut Cpu, vd: usize, vs1: usize, vs2: usize, base: usize, high: bool) {
    let abef = sha2_read_group_u32(cpu, vs2, base); // {a, b, e, f}
    let cdgh = sha2_read_group_u32(cpu, vd, base); // {c, d, g, h}
    let msg = sha2_read_group_u32(cpu, vs1, base); // MessageSchedPlusC[3:0]

    let (w0, w1) = if high {
        (msg[2], msg[3])
    } else {
        (msg[0], msg[1])
    };

    let (mut a, mut b, mut c, mut d) = (abef[3], abef[2], cdgh[3], cdgh[2]);
    let (mut e, mut f, mut g, mut h) = (abef[1], abef[0], cdgh[1], cdgh[0]);

    // Round 0
    let t1 = h
        .wrapping_add(sha256_sum1(e))
        .wrapping_add(sha_ch(e, f, g))
        .wrapping_add(w0);
    let t2 = sha256_sum0(a).wrapping_add(sha_maj(a, b, c));
    h = g;
    g = f;
    f = e;
    e = d.wrapping_add(t1);
    d = c;
    c = b;
    b = a;
    a = t1.wrapping_add(t2);

    // Round 1
    let t1 = h
        .wrapping_add(sha256_sum1(e))
        .wrapping_add(sha_ch(e, f, g))
        .wrapping_add(w1);
    let t2 = sha256_sum0(a).wrapping_add(sha_maj(a, b, c));
    h = g;
    g = f;
    f = e;
    e = d.wrapping_add(t1);
    d = c;
    c = b;
    b = a;
    a = t1.wrapping_add(t2);

    // Output: {a, b, e, f} — the new state written to vd
    sha2_write_group_u32(cpu, vd, base, &[f, e, b, a]);
}

fn execute_v_sha2_64(
    cpu: &mut Cpu,
    vd: usize,
    vs1: usize,
    vs2: usize,
    funct6: u32,
    num_groups: usize,
) {
    for g in 0..num_groups {
        let base = g * 4;
        match funct6 {
            0b101101 => {
                // vsha2ms.vv — SHA-512 message schedule
                let w_vd = sha2_read_group_u64(cpu, vd, base);
                let w_vs2 = sha2_read_group_u64(cpu, vs2, base);
                let w_vs1 = sha2_read_group_u64(cpu, vs1, base);
                let w16 = sha512_sig1(w_vs1[2])
                    .wrapping_add(w_vs2[1])
                    .wrapping_add(sha512_sig0(w_vd[1]))
                    .wrapping_add(w_vd[0]);
                let w17 = sha512_sig1(w_vs1[3])
                    .wrapping_add(w_vs2[2])
                    .wrapping_add(sha512_sig0(w_vd[2]))
                    .wrapping_add(w_vd[1]);
                let w18 = sha512_sig1(w16)
                    .wrapping_add(w_vs2[3])
                    .wrapping_add(sha512_sig0(w_vd[3]))
                    .wrapping_add(w_vd[2]);
                let w19 = sha512_sig1(w17)
                    .wrapping_add(w_vs1[0])
                    .wrapping_add(sha512_sig0(w_vs2[0]))
                    .wrapping_add(w_vd[3]);
                sha2_write_group_u64(cpu, vd, base, &[w16, w17, w18, w19]);
            }
            0b101110 => {
                // vsha2ch.vv — SHA-512 compression high
                sha2_compress_64(cpu, vd, vs1, vs2, base, true);
            }
            0b101111 => {
                // vsha2cl.vv — SHA-512 compression low
                sha2_compress_64(cpu, vd, vs1, vs2, base, false);
            }
            _ => {}
        }
    }
}

#[allow(unused_assignments)]
fn sha2_compress_64(cpu: &mut Cpu, vd: usize, vs1: usize, vs2: usize, base: usize, high: bool) {
    let abef = sha2_read_group_u64(cpu, vs2, base);
    let cdgh = sha2_read_group_u64(cpu, vd, base);
    let msg = sha2_read_group_u64(cpu, vs1, base);

    let (w0, w1) = if high {
        (msg[2], msg[3])
    } else {
        (msg[0], msg[1])
    };

    let (mut a, mut b, mut c, mut d) = (abef[3], abef[2], cdgh[3], cdgh[2]);
    let (mut e, mut f, mut g, mut h) = (abef[1], abef[0], cdgh[1], cdgh[0]);

    let t1 = h
        .wrapping_add(sha512_sum1(e))
        .wrapping_add(sha_ch(e, f, g))
        .wrapping_add(w0);
    let t2 = sha512_sum0(a).wrapping_add(sha_maj(a, b, c));
    h = g;
    g = f;
    f = e;
    e = d.wrapping_add(t1);
    d = c;
    c = b;
    b = a;
    a = t1.wrapping_add(t2);

    let t1 = h
        .wrapping_add(sha512_sum1(e))
        .wrapping_add(sha_ch(e, f, g))
        .wrapping_add(w1);
    let t2 = sha512_sum0(a).wrapping_add(sha_maj(a, b, c));
    h = g;
    g = f;
    f = e;
    e = d.wrapping_add(t1);
    d = c;
    c = b;
    b = a;
    a = t1.wrapping_add(t2);

    sha2_write_group_u64(cpu, vd, base, &[f, e, b, a]);
}

// ============================================================================
// Zvkned: AES helpers for vector crypto
// ============================================================================

/// Read a 128-bit element group (4 × SEW=32 elements) from a vector register.
fn aes_read_group(cpu: &Cpu, vreg: usize, base: usize) -> [u32; 4] {
    [
        cpu.vregs.read_elem(vreg, 32, base) as u32,
        cpu.vregs.read_elem(vreg, 32, base + 1) as u32,
        cpu.vregs.read_elem(vreg, 32, base + 2) as u32,
        cpu.vregs.read_elem(vreg, 32, base + 3) as u32,
    ]
}

/// Write a 128-bit element group back.
fn aes_write_group(cpu: &mut Cpu, vreg: usize, base: usize, group: &[u32; 4]) {
    for (i, &val) in group.iter().enumerate() {
        cpu.vregs.write_elem(vreg, 32, base + i, val as u64);
    }
}

/// Get byte at position from the 4×u32 state (column-major).
/// State layout: col0=state[0], col1=state[1], col2=state[2], col3=state[3]
/// Each column: byte0=LSB .. byte3=MSB → row 0..3
#[inline]
fn aes_get_byte(state: &[u32; 4], row: usize, col: usize) -> u8 {
    ((state[col] >> (row * 8)) & 0xFF) as u8
}

/// Set byte at position in state.
#[inline]
fn aes_set_byte(state: &mut [u32; 4], row: usize, col: usize, val: u8) {
    state[col] = (state[col] & !(0xFF << (row * 8))) | ((val as u32) << (row * 8));
}

/// AES SubBytes (forward S-box on all 16 bytes).
fn aes_sub_bytes(state: &mut [u32; 4]) {
    for w in state.iter_mut() {
        let b0 = super::execute::AES_SBOX[(*w & 0xFF) as usize] as u32;
        let b1 = super::execute::AES_SBOX[((*w >> 8) & 0xFF) as usize] as u32;
        let b2 = super::execute::AES_SBOX[((*w >> 16) & 0xFF) as usize] as u32;
        let b3 = super::execute::AES_SBOX[((*w >> 24) & 0xFF) as usize] as u32;
        *w = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
}

/// AES InvSubBytes (inverse S-box on all 16 bytes).
fn aes_inv_sub_bytes(state: &mut [u32; 4]) {
    for w in state.iter_mut() {
        let b0 = super::execute::AES_INV_SBOX[(*w & 0xFF) as usize] as u32;
        let b1 = super::execute::AES_INV_SBOX[((*w >> 8) & 0xFF) as usize] as u32;
        let b2 = super::execute::AES_INV_SBOX[((*w >> 16) & 0xFF) as usize] as u32;
        let b3 = super::execute::AES_INV_SBOX[((*w >> 24) & 0xFF) as usize] as u32;
        *w = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    }
}

/// AES ShiftRows: rotate rows left by 0/1/2/3.
fn aes_shift_rows(state: &mut [u32; 4]) {
    // Row 0: no shift
    // Row 1: shift left by 1
    let t = aes_get_byte(state, 1, 0);
    aes_set_byte(state, 1, 0, aes_get_byte(state, 1, 1));
    aes_set_byte(state, 1, 1, aes_get_byte(state, 1, 2));
    aes_set_byte(state, 1, 2, aes_get_byte(state, 1, 3));
    aes_set_byte(state, 1, 3, t);
    // Row 2: shift left by 2
    let t0 = aes_get_byte(state, 2, 0);
    let t1 = aes_get_byte(state, 2, 1);
    aes_set_byte(state, 2, 0, aes_get_byte(state, 2, 2));
    aes_set_byte(state, 2, 1, aes_get_byte(state, 2, 3));
    aes_set_byte(state, 2, 2, t0);
    aes_set_byte(state, 2, 3, t1);
    // Row 3: shift left by 3 (= right by 1)
    let t = aes_get_byte(state, 3, 3);
    aes_set_byte(state, 3, 3, aes_get_byte(state, 3, 2));
    aes_set_byte(state, 3, 2, aes_get_byte(state, 3, 1));
    aes_set_byte(state, 3, 1, aes_get_byte(state, 3, 0));
    aes_set_byte(state, 3, 0, t);
}

/// AES InvShiftRows: rotate rows right by 0/1/2/3.
fn aes_inv_shift_rows(state: &mut [u32; 4]) {
    // Row 1: shift right by 1
    let t = aes_get_byte(state, 1, 3);
    aes_set_byte(state, 1, 3, aes_get_byte(state, 1, 2));
    aes_set_byte(state, 1, 2, aes_get_byte(state, 1, 1));
    aes_set_byte(state, 1, 1, aes_get_byte(state, 1, 0));
    aes_set_byte(state, 1, 0, t);
    // Row 2: shift right by 2
    let t0 = aes_get_byte(state, 2, 0);
    let t1 = aes_get_byte(state, 2, 1);
    aes_set_byte(state, 2, 0, aes_get_byte(state, 2, 2));
    aes_set_byte(state, 2, 1, aes_get_byte(state, 2, 3));
    aes_set_byte(state, 2, 2, t0);
    aes_set_byte(state, 2, 3, t1);
    // Row 3: shift right by 3 (= left by 1)
    let t = aes_get_byte(state, 3, 0);
    aes_set_byte(state, 3, 0, aes_get_byte(state, 3, 1));
    aes_set_byte(state, 3, 1, aes_get_byte(state, 3, 2));
    aes_set_byte(state, 3, 2, aes_get_byte(state, 3, 3));
    aes_set_byte(state, 3, 3, t);
}

/// GF(2^8) multiply by 2 (xtime).
#[inline]
fn gf_mul2(x: u8) -> u8 {
    let r = (x as u16) << 1;
    if r & 0x100 != 0 {
        (r ^ 0x11b) as u8
    } else {
        r as u8
    }
}

/// AES MixColumns: mix each column independently.
fn aes_mix_columns(state: &mut [u32; 4]) {
    for col in 0..4 {
        let s0 = aes_get_byte(state, 0, col);
        let s1 = aes_get_byte(state, 1, col);
        let s2 = aes_get_byte(state, 2, col);
        let s3 = aes_get_byte(state, 3, col);
        let r0 = gf_mul2(s0) ^ gf_mul2(s1) ^ s1 ^ s2 ^ s3;
        let r1 = s0 ^ gf_mul2(s1) ^ gf_mul2(s2) ^ s2 ^ s3;
        let r2 = s0 ^ s1 ^ gf_mul2(s2) ^ gf_mul2(s3) ^ s3;
        let r3 = gf_mul2(s0) ^ s0 ^ s1 ^ s2 ^ gf_mul2(s3);
        aes_set_byte(state, 0, col, r0);
        aes_set_byte(state, 1, col, r1);
        aes_set_byte(state, 2, col, r2);
        aes_set_byte(state, 3, col, r3);
    }
}

/// GF(2^8) multiply.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// AES InvMixColumns.
fn aes_inv_mix_columns(state: &mut [u32; 4]) {
    for col in 0..4 {
        let s0 = aes_get_byte(state, 0, col);
        let s1 = aes_get_byte(state, 1, col);
        let s2 = aes_get_byte(state, 2, col);
        let s3 = aes_get_byte(state, 3, col);
        let r0 = gf_mul(s0, 0x0e) ^ gf_mul(s1, 0x0b) ^ gf_mul(s2, 0x0d) ^ gf_mul(s3, 0x09);
        let r1 = gf_mul(s0, 0x09) ^ gf_mul(s1, 0x0e) ^ gf_mul(s2, 0x0b) ^ gf_mul(s3, 0x0d);
        let r2 = gf_mul(s0, 0x0d) ^ gf_mul(s1, 0x09) ^ gf_mul(s2, 0x0e) ^ gf_mul(s3, 0x0b);
        let r3 = gf_mul(s0, 0x0b) ^ gf_mul(s1, 0x0d) ^ gf_mul(s2, 0x09) ^ gf_mul(s3, 0x0e);
        aes_set_byte(state, 0, col, r0);
        aes_set_byte(state, 1, col, r1);
        aes_set_byte(state, 2, col, r2);
        aes_set_byte(state, 3, col, r3);
    }
}

/// AES AddRoundKey: XOR state with round key.
fn aes_add_round_key(state: &mut [u32; 4], rk: &[u32; 4]) {
    for i in 0..4 {
        state[i] ^= rk[i];
    }
}

/// AES encrypt middle round: SubBytes → ShiftRows → MixColumns → AddRoundKey
fn aes_encrypt_middle(state: &mut [u32; 4], rk: &[u32; 4]) {
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_mix_columns(state);
    aes_add_round_key(state, rk);
}

/// AES encrypt final round: SubBytes → ShiftRows → AddRoundKey
fn aes_encrypt_final(state: &mut [u32; 4], rk: &[u32; 4]) {
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, rk);
}

/// AES decrypt middle round: InvShiftRows → InvSubBytes → AddRoundKey → InvMixColumns
fn aes_decrypt_middle(state: &mut [u32; 4], rk: &[u32; 4]) {
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, rk);
    aes_inv_mix_columns(state);
}

/// AES decrypt final round: InvShiftRows → InvSubBytes → AddRoundKey
fn aes_decrypt_final(state: &mut [u32; 4], rk: &[u32; 4]) {
    aes_inv_shift_rows(state);
    aes_inv_sub_bytes(state);
    aes_add_round_key(state, rk);
}

/// AES-128 key schedule: produce next round key from current.
fn aes_keyschedule_128(current: &[u32; 4], rnum: u32) -> [u32; 4] {
    let rcon = if (rnum as usize) < super::execute::AES_RCON.len() {
        super::execute::AES_RCON[rnum as usize] as u32
    } else {
        0
    };
    // RotWord + SubWord on last word
    let w3 = current[3];
    let rot = w3.rotate_right(8); // RotWord
    let sub = aes_sub_word(rot);
    let mut nk = [0u32; 4];
    nk[0] = current[0] ^ sub ^ rcon;
    nk[1] = current[1] ^ nk[0];
    nk[2] = current[2] ^ nk[1];
    nk[3] = current[3] ^ nk[2];
    nk
}

/// AES-256 key schedule: produce next round key.
/// prev_key = vs2 (previous 128-bit), current_key = vd (current 128-bit).
fn aes_keyschedule_256(prev_key: &[u32; 4], current_key: &[u32; 4], rnum: u32) -> [u32; 4] {
    let mut nk = [0u32; 4];
    if rnum & 1 == 1 {
        // Odd round: SubWord (no RotWord, no Rcon)
        let sub = aes_sub_word(current_key[3]);
        nk[0] = prev_key[0] ^ sub;
        nk[1] = prev_key[1] ^ nk[0];
        nk[2] = prev_key[2] ^ nk[1];
        nk[3] = prev_key[3] ^ nk[2];
    } else {
        // Even round: RotWord + SubWord + Rcon
        let rcon_idx = (rnum / 2) as usize;
        let rcon = if rcon_idx < super::execute::AES_RCON.len() {
            super::execute::AES_RCON[rcon_idx] as u32
        } else {
            0
        };
        let w3 = current_key[3];
        let rot = w3.rotate_right(8);
        let sub = aes_sub_word(rot);
        nk[0] = prev_key[0] ^ sub ^ rcon;
        nk[1] = prev_key[1] ^ nk[0];
        nk[2] = prev_key[2] ^ nk[1];
        nk[3] = prev_key[3] ^ nk[2];
    }
    nk
}

/// Apply AES S-box to each byte of a 32-bit word.
fn aes_sub_word(w: u32) -> u32 {
    let b0 = super::execute::AES_SBOX[(w & 0xFF) as usize] as u32;
    let b1 = super::execute::AES_SBOX[((w >> 8) & 0xFF) as usize] as u32;
    let b2 = super::execute::AES_SBOX[((w >> 16) & 0xFF) as usize] as u32;
    let b3 = super::execute::AES_SBOX[((w >> 24) & 0xFF) as usize] as u32;
    b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
}

// ============================================================================
// OPMVX (funct3=6): scalar-vector operations
// ============================================================================
fn execute_mvx(cpu: &mut Cpu, ctx: &VCtx, scalar: u64) {
    let VCtx {
        funct6,
        vd,
        vs2,
        vm,
        vl,
        sew,
        ..
    } = *ctx;

    match funct6 {
        0b010000 => {
            // vmv.s.x
            if vl > 0 {
                cpu.vregs.write_elem(vd, sew, 0, trunc_sew(scalar, sew));
            }
        }

        // --- Averaging add/sub (OPMVX) ---
        0b001000 => {
            // vaaddu.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i) as u128;
                let b = scalar as u128;
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(((a + b) >> 1) as u64, sew));
            }
        }
        0b001001 => {
            // vaadd.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = sext_sew(cpu.vregs.read_elem(vs2, sew, i), sew) as i128;
                let b = sext_sew(scalar, sew) as i128;
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(((a + b) >> 1) as u64, sew));
            }
        }
        0b001010 => {
            // vasubu.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i) as u128;
                let b = scalar as u128;
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew((a.wrapping_sub(b) >> 1) as u64, sew));
            }
        }
        0b001011 => {
            // vasub.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = sext_sew(cpu.vregs.read_elem(vs2, sew, i), sew) as i128;
                let b = sext_sew(scalar, sew) as i128;
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(((a - b) >> 1) as u64, sew));
            }
        }

        // vslide1up.vx: vd[0] = rs1, vd[i] = vs2[i-1]
        0b001110 => {
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let val = if i == 0 {
                    trunc_sew(scalar, sew)
                } else {
                    cpu.vregs.read_elem(vs2, sew, i - 1)
                };
                cpu.vregs.write_elem(vd, sew, i, val);
            }
        }

        // vslide1down.vx: vd[vl-1] = rs1, vd[i] = vs2[i+1]
        0b001111 => {
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let val = if i == (vl as usize - 1) {
                    trunc_sew(scalar, sew)
                } else {
                    cpu.vregs.read_elem(vs2, sew, i + 1)
                };
                cpu.vregs.write_elem(vd, sew, i, val);
            }
        }

        // --- Integer multiply ---
        0b100100 => {
            // vmulhu.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(mulhu_sew(a, scalar, sew), sew));
            }
        }
        0b100101 => {
            // vmul.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(a.wrapping_mul(scalar), sew));
            }
        }
        0b100110 => {
            // vmulhsu.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(mulhsu_sew(a, scalar, sew), sew));
            }
        }
        0b100111 => {
            // vmulh.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs
                    .write_elem(vd, sew, i, trunc_sew(mulh_sew(a, scalar, sew), sew));
            }
        }

        // --- Integer divide ---
        0b100000 => {
            // vdivu.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, sew, i, divu_sew(a, scalar, sew));
            }
        }
        0b100001 => {
            // vdiv.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, sew, i, div_sew(a, scalar, sew));
            }
        }
        0b100010 => {
            // vremu.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, sew, i, remu_sew(a, scalar, sew));
            }
        }
        0b100011 => {
            // vrem.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, sew, i, rem_sew(a, scalar, sew));
            }
        }

        // --- Multiply-add ---
        0b101101 => {
            // vmacc.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(scalar.wrapping_mul(b).wrapping_add(d), sew),
                );
            }
        }
        0b101111 => {
            // vnmsac.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(d.wrapping_sub(scalar.wrapping_mul(b)), sew),
                );
            }
        }
        0b101001 => {
            // vmadd.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(scalar.wrapping_mul(d).wrapping_add(b), sew),
                );
            }
        }
        0b101011 => {
            // vnmsub.vx
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, sew, i);
                cpu.vregs.write_elem(
                    vd,
                    sew,
                    i,
                    trunc_sew(b.wrapping_sub(scalar.wrapping_mul(d)), sew),
                );
            }
        }

        // --- Widening integer add/sub ---
        0b110000 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_addu(a, scalar, sew));
            }
        }
        0b110001 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_add(a, scalar, sew));
            }
        }
        0b110010 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_subu(a, scalar, sew));
            }
        }
        0b110011 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_sub(a, scalar, sew));
            }
        }
        0b110100 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_waddu(a, scalar, sew));
            }
        }
        0b110101 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_wadd(a, scalar, sew));
            }
        }
        0b110110 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_wsubu(a, scalar, sew));
            }
        }
        0b110111 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, dsew, i);
                cpu.vregs.write_elem(vd, dsew, i, wop_wsub(a, scalar, sew));
            }
        }

        // --- Widening multiply ---
        0b111000 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wmul_uu(a, scalar, sew));
            }
        }
        0b111010 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wmul_su(a, scalar, sew));
            }
        }
        0b111011 => {
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let a = cpu.vregs.read_elem(vs2, sew, i);
                cpu.vregs.write_elem(vd, dsew, i, wmul_ss(a, scalar, sew));
            }
        }

        // --- Widening multiply-accumulate ---
        0b111100 => {
            // vwmaccu.vx
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs.write_elem(
                    vd,
                    dsew,
                    i,
                    trunc_sew(d.wrapping_add(wmul_uu(scalar, b, sew)), dsew),
                );
            }
        }
        0b111101 => {
            // vwmacc.vx
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs.write_elem(
                    vd,
                    dsew,
                    i,
                    trunc_sew(d.wrapping_add(wmul_ss(scalar, b, sew)), dsew),
                );
            }
        }
        0b111110 => {
            // vwmaccsu.vx: vd += vs2(signed) * rs1(unsigned)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs.write_elem(
                    vd,
                    dsew,
                    i,
                    trunc_sew(d.wrapping_add(wmul_su(b, scalar, sew)), dsew),
                );
            }
        }
        0b111111 => {
            // vwmaccus.vx: vd += rs1(signed) * vs2(unsigned)
            let dsew = sew * 2;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let b = cpu.vregs.read_elem(vs2, sew, i);
                let d = cpu.vregs.read_elem(vd, dsew, i);
                cpu.vregs.write_elem(
                    vd,
                    dsew,
                    i,
                    trunc_sew(d.wrapping_add(wmul_su(scalar, b, sew)), dsew),
                );
            }
        }

        _ => {}
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

    let vtype = current_vtype(cpu);
    if mop == 0 && vtype.vill && lumop != 0b01000 {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }
    if mop != 0 && vtype.vill {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }

    set_vs_dirty(cpu);
    let base = cpu.regs[rs1];

    match mop {
        0 if lumop == 0b01000 => {
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
        }
        0 => {
            // Unit-stride load (with optional segment: nf+1 fields)
            let vl = current_vl(cpu);
            let eew_bytes = eew as u64 / 8;
            let nfields = nf + 1;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                for f in 0..nfields {
                    let addr = base + (i * nfields + f) as u64 * eew_bytes;
                    match v_load_elem(cpu, bus, addr, eew) {
                        Ok(val) => cpu.vregs.write_elem(vd + f, eew, i, val),
                        Err(e) => {
                            cpu.handle_exception(e, addr, bus);
                            return true;
                        }
                    }
                }
            }
        }
        2 => {
            // Strided load: rs2 = stride (with optional segment)
            let rs2 = ((raw >> 20) & 0x1F) as usize;
            let stride = cpu.regs[rs2] as i64;
            let vl = current_vl(cpu);
            let eew_bytes = eew as u64 / 8;
            let nfields = nf + 1;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let seg_base = (base as i64 + (i as i64) * stride) as u64;
                for f in 0..nfields {
                    let addr = seg_base + f as u64 * eew_bytes;
                    match v_load_elem(cpu, bus, addr, eew) {
                        Ok(val) => cpu.vregs.write_elem(vd + f, eew, i, val),
                        Err(e) => {
                            cpu.handle_exception(e, addr, bus);
                            return true;
                        }
                    }
                }
            }
        }
        1 | 3 => {
            // Indexed load: vs2 contains indices (with optional segment)
            let vs2_reg = ((raw >> 20) & 0x1F) as usize;
            let vl = current_vl(cpu);
            let idx_sew = eew;
            let data_sew = vtype.sew;
            let data_bytes = data_sew as u64 / 8;
            let nfields = nf + 1;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let offset = cpu.vregs.read_elem(vs2_reg, idx_sew, i);
                let seg_base = base.wrapping_add(offset);
                for f in 0..nfields {
                    let addr = seg_base + f as u64 * data_bytes;
                    match v_load_elem(cpu, bus, addr, data_sew) {
                        Ok(val) => cpu.vregs.write_elem(vd + f, data_sew, i, val),
                        Err(e) => {
                            cpu.handle_exception(e, addr, bus);
                            return true;
                        }
                    }
                }
            }
        }
        _ => {
            cpu.handle_exception(2, raw as u64, bus);
            return true;
        }
    }

    cpu.pc += inst_len;
    true
}

/// Helper: load a single element from memory
fn v_load_elem(cpu: &mut Cpu, bus: &mut Bus, addr: u64, eew: u32) -> Result<u64, u64> {
    let phys = cpu
        .mmu
        .translate(addr, AccessType::Read, cpu.mode, &cpu.csrs, bus)?;
    Ok(match eew {
        8 => bus.read8(phys) as u64,
        16 => bus.read16(phys) as u64,
        32 => bus.read32(phys) as u64,
        64 => bus.read64(phys),
        _ => 0,
    })
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

    let vtype = current_vtype(cpu);
    if mop == 0 && vtype.vill && sumop != 0b01000 {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }
    if mop != 0 && vtype.vill {
        cpu.handle_exception(2, raw as u64, bus);
        return true;
    }

    let base = cpu.regs[rs1];

    match mop {
        0 if sumop == 0b01000 => {
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
        }
        0 => {
            // Unit-stride store (with optional segment: nf+1 fields)
            let vl = current_vl(cpu);
            let eew_bytes = eew as u64 / 8;
            let nfields = nf + 1;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                for f in 0..nfields {
                    let addr = base + (i * nfields + f) as u64 * eew_bytes;
                    let val = cpu.vregs.read_elem(vs3 + f, eew, i);
                    if let Err(e) = v_store_elem(cpu, bus, addr, eew, val) {
                        cpu.handle_exception(e, addr, bus);
                        return true;
                    }
                }
            }
        }
        2 => {
            // Strided store (with optional segment)
            let rs2 = ((raw >> 20) & 0x1F) as usize;
            let stride = cpu.regs[rs2] as i64;
            let vl = current_vl(cpu);
            let eew_bytes = eew as u64 / 8;
            let nfields = nf + 1;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let seg_base = (base as i64 + (i as i64) * stride) as u64;
                for f in 0..nfields {
                    let addr = seg_base + f as u64 * eew_bytes;
                    let val = cpu.vregs.read_elem(vs3 + f, eew, i);
                    if let Err(e) = v_store_elem(cpu, bus, addr, eew, val) {
                        cpu.handle_exception(e, addr, bus);
                        return true;
                    }
                }
            }
        }
        1 | 3 => {
            // Indexed store (with optional segment)
            let vs2_reg = ((raw >> 20) & 0x1F) as usize;
            let vl = current_vl(cpu);
            let idx_sew = eew;
            let data_sew = vtype.sew;
            let data_bytes = data_sew as u64 / 8;
            let nfields = nf + 1;
            for i in 0..vl as usize {
                if !elem_active(cpu, vm, i) {
                    continue;
                }
                let offset = cpu.vregs.read_elem(vs2_reg, idx_sew, i);
                let seg_base = base.wrapping_add(offset);
                for f in 0..nfields {
                    let addr = seg_base + f as u64 * data_bytes;
                    let val = cpu.vregs.read_elem(vs3 + f, data_sew, i);
                    if let Err(e) = v_store_elem(cpu, bus, addr, data_sew, val) {
                        cpu.handle_exception(e, addr, bus);
                        return true;
                    }
                }
            }
        }
        _ => {
            cpu.handle_exception(2, raw as u64, bus);
            return true;
        }
    }

    cpu.pc += inst_len;
    true
}

/// Helper: store a single element to memory
fn v_store_elem(cpu: &mut Cpu, bus: &mut Bus, addr: u64, eew: u32, val: u64) -> Result<(), u64> {
    let phys = cpu
        .mmu
        .translate(addr, AccessType::Write, cpu.mode, &cpu.csrs, bus)?;
    match eew {
        8 => bus.write8(phys, val as u8),
        16 => bus.write16(phys, val as u16),
        32 => bus.write32(phys, val as u32),
        64 => bus.write64(phys, val),
        _ => {}
    }
    Ok(())
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

    // ===== Vector FP unit tests =====

    #[test]
    fn fp_add_f32() {
        let a = 2.0f32.to_bits() as u64;
        let b = 3.0f32.to_bits() as u64;
        let r = f32_add(a, b);
        assert_eq!(f32::from_bits(r as u32), 5.0);
    }

    #[test]
    fn fp_sub_f32() {
        let a = 5.0f32.to_bits() as u64;
        let b = 3.0f32.to_bits() as u64;
        let r = f32_sub(a, b);
        assert_eq!(f32::from_bits(r as u32), 2.0);
    }

    #[test]
    fn fp_mul_f32() {
        let a = 3.0f32.to_bits() as u64;
        let b = 4.0f32.to_bits() as u64;
        let r = f32_mul(a, b);
        assert_eq!(f32::from_bits(r as u32), 12.0);
    }

    #[test]
    fn fp_div_f32() {
        let a = 12.0f32.to_bits() as u64;
        let b = 4.0f32.to_bits() as u64;
        let r = f32_div(a, b);
        assert_eq!(f32::from_bits(r as u32), 3.0);
    }

    #[test]
    fn fp_min_nan_propagation() {
        let nan = f32::NAN.to_bits() as u64;
        let val = 1.0f32.to_bits() as u64;
        assert_eq!(f32_min(nan, val), val);
        assert_eq!(f32_min(val, nan), val);
        assert!(f32::from_bits(f32_min(nan, nan) as u32).is_nan());
    }

    #[test]
    fn fp_max_nan_propagation() {
        let nan = f32::NAN.to_bits() as u64;
        let val = 1.0f32.to_bits() as u64;
        assert_eq!(f32_max(nan, val), val);
        assert_eq!(f32_max(val, nan), val);
        assert!(f32::from_bits(f32_max(nan, nan) as u32).is_nan());
    }

    #[test]
    fn fp_fma_f32() {
        let a = 2.0f32.to_bits() as u64;
        let b = 3.0f32.to_bits() as u64;
        let c = 1.0f32.to_bits() as u64;
        let r = fp_fma(32, a, b, c);
        assert_eq!(f32::from_bits(r as u32), 7.0); // 2*3+1
    }

    #[test]
    fn fp_fma_f64() {
        let a = 2.0f64.to_bits();
        let b = 3.0f64.to_bits();
        let c = 1.0f64.to_bits();
        let r = fp_fma(64, a, b, c);
        assert_eq!(f64::from_bits(r), 7.0);
    }

    #[test]
    fn fp_sgnj_f32() {
        let pos = 1.0f32.to_bits() as u64;
        let neg = (-2.0f32).to_bits() as u64;
        let r = fp_sgnj(32, pos, neg);
        assert_eq!(f32::from_bits(r as u32), -1.0); // magnitude of pos, sign of neg
    }

    #[test]
    fn fp_classify_f32_values() {
        assert_eq!(classify_f32(f32::NEG_INFINITY.to_bits() as u64), 1 << 0);
        assert_eq!(classify_f32((-1.0f32).to_bits() as u64), 1 << 1);
        assert_eq!(
            classify_f32(f32::from_bits(0x80000000).to_bits() as u64),
            1 << 3
        ); // -0
        assert_eq!(classify_f32(0.0f32.to_bits() as u64), 1 << 4);
        assert_eq!(classify_f32(1.0f32.to_bits() as u64), 1 << 6);
        assert_eq!(classify_f32(f32::INFINITY.to_bits() as u64), 1 << 7);
    }

    #[test]
    fn fp_classify_f64_values() {
        assert_eq!(classify_f64(f64::NEG_INFINITY.to_bits()), 1 << 0);
        assert_eq!(classify_f64((-1.0f64).to_bits()), 1 << 1);
        assert_eq!(classify_f64(0.0f64.to_bits()), 1 << 4);
        assert_eq!(classify_f64(1.0f64.to_bits()), 1 << 6);
        assert_eq!(classify_f64(f64::INFINITY.to_bits()), 1 << 7);
    }

    #[test]
    fn fp_to_int_conversions() {
        assert_eq!(fp_to_int(32, 3.7f32.to_bits() as u64), 3u32 as u64);
        assert_eq!(
            fp_to_int(32, (-2.9f32).to_bits() as u64),
            trunc_sew(-2i32 as u64, 32)
        );
        assert_eq!(fp_to_uint(32, 3.7f32.to_bits() as u64), 3u64);
        assert_eq!(fp_to_uint(32, (-1.0f32).to_bits() as u64), 0); // negative → 0
    }

    #[test]
    fn int_to_fp_conversions() {
        let r = int_to_fp(32, trunc_sew(-5i32 as u64, 32));
        assert_eq!(f32::from_bits(r as u32), -5.0);
        let r = uint_to_fp(32, 42u64);
        assert_eq!(f32::from_bits(r as u32), 42.0);
    }

    #[test]
    fn fp_f64_ops() {
        let a = 10.0f64.to_bits();
        let b = 3.0f64.to_bits();
        assert_eq!(f64::from_bits(f64_add(a, b)), 13.0);
        assert_eq!(f64::from_bits(f64_sub(a, b)), 7.0);
        assert_eq!(f64::from_bits(f64_mul(a, b)), 30.0);
        let d = f64::from_bits(f64_div(a, b));
        assert!((d - 10.0 / 3.0).abs() < 1e-10);
        assert_eq!(f64::from_bits(f64_sqrt(4.0f64.to_bits())), 2.0);
    }

    // ========================================================================
    // Zvkned tests
    // ========================================================================

    #[test]
    fn test_aes_sub_bytes_roundtrip() {
        let mut state = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
        let original = state;
        aes_sub_bytes(&mut state);
        // SubBytes should change the state
        assert_ne!(state, original);
        aes_inv_sub_bytes(&mut state);
        // InvSubBytes should restore it
        assert_eq!(state, original);
    }

    #[test]
    fn test_aes_shift_rows_roundtrip() {
        let mut state = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f];
        let original = state;
        aes_shift_rows(&mut state);
        assert_ne!(state, original);
        aes_inv_shift_rows(&mut state);
        assert_eq!(state, original);
    }

    #[test]
    fn test_aes_mix_columns_roundtrip() {
        let mut state = [0x63637c63, 0x7c776b7c, 0xf26bc5f2, 0x6fc56f6f];
        let original = state;
        aes_mix_columns(&mut state);
        assert_ne!(state, original);
        aes_inv_mix_columns(&mut state);
        assert_eq!(state, original);
    }

    #[test]
    fn test_aes_encrypt_final_decrypt_final_roundtrip() {
        // Final round: encrypt then decrypt with same key is a valid roundtrip
        // because final round has no MixColumns
        let plaintext = [0x11223344, 0x55667788, 0x99aabbcc, 0xddeeff00];
        let key = [0xaabbccdd, 0xeeff0011, 0x22334455, 0x66778899];

        let mut state = plaintext;
        // Encrypt final: SubBytes → ShiftRows → XOR key
        aes_encrypt_final(&mut state, &key);
        assert_ne!(state, plaintext);
        // To reverse: XOR key → InvShiftRows → InvSubBytes
        // Which is: InvSubBytes(InvShiftRows(state XOR key))
        aes_add_round_key(&mut state, &key);
        aes_inv_shift_rows(&mut state);
        aes_inv_sub_bytes(&mut state);
        assert_eq!(state, plaintext);
    }

    #[test]
    fn test_aes_keyschedule_128() {
        // FIPS 197 Appendix A.1: AES-128 key expansion
        // Key: 2b7e1516 28aed2a6 abf71588 09cf4f3c
        let key = [0x16157e2b, 0xa6d2ae28, 0x8815f7ab, 0x3c4fcf09];
        let rk1 = aes_keyschedule_128(&key, 1);
        // Expected round key 1: a0fafe17 88542cb1 23a33939 2a6c7605
        assert_eq!(rk1[0], 0x17fefaa0);
        assert_eq!(rk1[1], 0xb12c5488);
        assert_eq!(rk1[2], 0x3939a323);
        assert_eq!(rk1[3], 0x05766c2a);
    }

    #[test]
    fn test_aes_sub_word() {
        // SubWord(0x00010203) = S[00] S[01] S[02] S[03] = 63 7c 77 7b
        assert_eq!(aes_sub_word(0x03020100), 0x7b777c63);
    }

    #[test]
    fn test_gf_mul() {
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x57, 0x02), 0xae);
        assert_eq!(gf_mul(0x01, 0x01), 0x01);
        assert_eq!(gf_mul(0x00, 0xff), 0x00);
    }
}
