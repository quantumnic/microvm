//! RV64F (single-precision), RV64D (double-precision), and Zfh (half-precision)
//! floating-point extensions.
//!
//! All f-register values are stored as u64 bits (NaN-boxed for single/half-precision).
//! NaN-boxing: single values have upper 32 bits = 1s; half values have upper 48 bits = 1s.

use super::Cpu;
use crate::memory::Bus;

/// NaN-box a 32-bit float value into 64 bits (upper 32 bits = 1s)
#[inline]
fn nan_box(val: u32) -> u64 {
    val as u64 | 0xFFFF_FFFF_0000_0000
}

/// NaN-box a 16-bit half-precision value into 64 bits (upper 48 bits = 1s)
#[inline]
fn nan_box_h(val: u16) -> u64 {
    val as u64 | 0xFFFF_FFFF_FFFF_0000
}

/// Unbox a NaN-boxed single. If not properly NaN-boxed, return canonical NaN.
#[inline]
fn unbox_f32(val: u64) -> f32 {
    if val & 0xFFFF_FFFF_0000_0000 == 0xFFFF_FFFF_0000_0000 {
        f32::from_bits(val as u32)
    } else {
        f32::from_bits(0x7FC0_0000) // canonical NaN
    }
}

/// Unbox a NaN-boxed half. If not properly NaN-boxed, return canonical NaN (0x7E00).
#[inline]
fn unbox_f16(val: u64) -> u16 {
    if val & 0xFFFF_FFFF_FFFF_0000 == 0xFFFF_FFFF_FFFF_0000 {
        val as u16
    } else {
        0x7E00 // canonical half NaN
    }
}

#[inline]
fn to_f64(val: u64) -> f64 {
    f64::from_bits(val)
}

// =====================================================================
// IEEE 754 half-precision (binary16) conversion helpers
// =====================================================================

/// Convert half-precision (u16 bits) to single-precision f32
fn f16_to_f32(h: u16) -> f32 {
    let sign = ((h >> 15) & 1) as u32;
    let exp = ((h >> 10) & 0x1F) as u32;
    let frac = (h & 0x3FF) as u32;

    let bits = if exp == 0 {
        if frac == 0 {
            // Zero
            sign << 31
        } else {
            // Subnormal: normalize
            let mut f = frac;
            let mut e: i32 = -14 + 127; // bias conversion
            while f & 0x400 == 0 {
                f <<= 1;
                e -= 1;
            }
            f &= 0x3FF; // remove implicit bit
            (sign << 31) | ((e as u32) << 23) | (f << 13)
        }
    } else if exp == 0x1F {
        // Inf or NaN
        if frac == 0 {
            (sign << 31) | (0xFF << 23)
        } else {
            // NaN: preserve quiet bit, shift mantissa
            (sign << 31) | (0xFF << 23) | (frac << 13)
        }
    } else {
        // Normal
        let new_exp = (exp as i32 - 15 + 127) as u32;
        (sign << 31) | (new_exp << 23) | (frac << 13)
    };
    f32::from_bits(bits)
}

/// Convert single-precision f32 to half-precision (u16 bits), with round-to-nearest-even
fn f32_to_f16(f: f32) -> u16 {
    let bits = f.to_bits();
    let sign = ((bits >> 31) & 1) as u16;
    let exp = ((bits >> 23) & 0xFF) as i32;
    let frac = bits & 0x007F_FFFF;

    if exp == 0xFF {
        // Inf or NaN
        if frac == 0 {
            (sign << 15) | (0x1F << 10)
        } else {
            // NaN: set quiet bit, preserve some mantissa
            (sign << 15) | (0x1F << 10) | ((frac >> 13) as u16).max(1)
        }
    } else if exp > 142 {
        // Overflow → infinity (bias diff: 127-15=112, max half exp=30 → 142)
        (sign << 15) | (0x1F << 10)
    } else if exp < 103 {
        // Too small for even subnormal
        sign << 15
    } else if exp < 113 {
        // Subnormal half
        let shift = 113 - exp;
        let full_frac = (1 << 23) | frac; // add implicit bit
        let shifted = full_frac >> (shift + 13);
        // Round
        let round_bit = (full_frac >> (shift + 12)) & 1;
        let sticky = if (full_frac & ((1 << (shift + 12)) - 1)) != 0 {
            1
        } else {
            0
        };
        let mut result = (sign << 15) | (shifted as u16);
        if round_bit != 0 && (sticky != 0 || (shifted & 1) != 0) {
            result += 1;
        }
        result
    } else {
        // Normal
        let new_exp = (exp - 112) as u16;
        let new_frac = (frac >> 13) as u16;
        // Round
        let round_bit = (frac >> 12) & 1;
        let sticky = frac & 0xFFF;
        let mut result = (sign << 15) | (new_exp << 10) | new_frac;
        if round_bit != 0 && (sticky != 0 || (new_frac & 1) != 0) {
            result += 1;
        }
        result
    }
}

/// Check if a half-precision value is a signaling NaN
fn is_snan_f16(h: u16) -> bool {
    let exp = (h >> 10) & 0x1F;
    let frac = h & 0x3FF;
    // sNaN: exponent all 1s, mantissa non-zero with bit 9 (quiet bit) = 0
    exp == 0x1F && frac != 0 && (frac & 0x200) == 0
}

/// FCLASS for half-precision
fn fclass_f16(h: u16) -> u32 {
    let sign = (h >> 15) & 1;
    let exp = (h >> 10) & 0x1F;
    let frac = h & 0x3FF;

    if exp == 0x1F {
        if frac == 0 {
            if sign == 1 {
                1 << 0
            } else {
                1 << 7
            } // -inf / +inf
        } else if frac & 0x200 != 0 {
            1 << 9 // quiet NaN
        } else {
            1 << 8 // signaling NaN
        }
    } else if exp == 0 {
        if frac == 0 {
            if sign == 1 {
                1 << 3
            } else {
                1 << 4
            } // -0 / +0
        } else if sign == 1 {
            1 << 2 // negative subnormal
        } else {
            1 << 5 // positive subnormal
        }
    } else if sign == 1 {
        1 << 1 // negative normal
    } else {
        1 << 6 // positive normal
    }
}

/// Accumulate FP exception flags for half-precision results
fn accumulate_f16_flags(cpu: &mut Cpu, h: u16) {
    let exp = (h >> 10) & 0x1F;
    let frac = h & 0x3FF;
    if exp == 0 && frac != 0 {
        set_flags(cpu, UF | NX);
    }
}

// Rounding mode constants (for future use with software rounding)
// 0=RNE, 1=RTZ, 2=RDN, 3=RUP, 4=RMM, 7=dynamic (use frm CSR)

// Exception flags
const NX: u64 = 1; // Inexact
const UF: u64 = 2; // Underflow
#[allow(dead_code)]
const OF: u64 = 4; // Overflow
const DZ: u64 = 8; // Divide by zero
const NV: u64 = 16; // Invalid operation

/// Accumulate FP exception flags into FCSR
fn set_flags(cpu: &mut Cpu, flags: u64) {
    if flags != 0 {
        let fcsr = cpu.csrs.read(super::csr::FCSR);
        cpu.csrs.write(super::csr::FCSR, fcsr | (flags & 0x1F));
    }
}

/// Execute a floating-point instruction. Returns true if handled.
/// Caller must check FS != Off before calling.
pub fn execute_fp(cpu: &mut Cpu, bus: &mut Bus, raw: u32, inst_len: u64) -> bool {
    let opcode = raw & 0x7F;
    match opcode {
        0x07 => exec_fp_load(cpu, bus, raw, inst_len),
        0x27 => exec_fp_store(cpu, bus, raw, inst_len),
        0x43 => exec_fmadd(cpu, raw, inst_len),
        0x47 => exec_fmsub(cpu, raw, inst_len),
        0x4B => exec_fnmsub(cpu, raw, inst_len),
        0x4F => exec_fnmadd(cpu, raw, inst_len),
        0x53 => exec_fp_op(cpu, bus, raw, inst_len),
        _ => return false,
    }
    true
}

/// FLW / FLD
fn exec_fp_load(cpu: &mut Cpu, bus: &mut Bus, raw: u32, len: u64) {
    let rd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let funct3 = (raw >> 12) & 0x7;
    let imm = ((raw as i32) >> 20) as i64;
    let addr = cpu.regs[rs1].wrapping_add(imm as u64);

    let phys = match cpu
        .mmu
        .translate(addr, super::mmu::AccessType::Read, cpu.mode, &cpu.csrs, bus)
    {
        Ok(a) => a,
        Err(e) => {
            cpu.handle_exception(e, addr, bus);
            return;
        }
    };

    match funct3 {
        1 => {
            // FLH (Zfh)
            let val = bus.read16(phys);
            cpu.fregs[rd] = nan_box_h(val);
        }
        2 => {
            // FLW
            let val = bus.read32(phys);
            cpu.fregs[rd] = nan_box(val);
        }
        3 => {
            // FLD
            cpu.fregs[rd] = bus.read64(phys);
        }
        _ => {
            cpu.handle_exception(2, raw as u64, bus);
            return;
        }
    }
    cpu.csrs.set_fs_dirty();
    cpu.pc += len;
}

/// FSW / FSD
fn exec_fp_store(cpu: &mut Cpu, bus: &mut Bus, raw: u32, len: u64) {
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let funct3 = (raw >> 12) & 0x7;
    let imm = ((((raw >> 25) & 0x7F) as i32) << 5 | ((raw >> 7) & 0x1F) as i32) as i64;
    let imm = ((imm << 20) as i32 >> 20) as i64;
    let addr = cpu.regs[rs1].wrapping_add(imm as u64);

    let phys = match cpu.mmu.translate(
        addr,
        super::mmu::AccessType::Write,
        cpu.mode,
        &cpu.csrs,
        bus,
    ) {
        Ok(a) => a,
        Err(e) => {
            cpu.handle_exception(e, addr, bus);
            return;
        }
    };

    match funct3 {
        1 => {
            // FSH (Zfh)
            bus.write16(phys, cpu.fregs[rs2] as u16);
        }
        2 => {
            // FSW
            bus.write32(phys, cpu.fregs[rs2] as u32);
        }
        3 => {
            // FSD
            bus.write64(phys, cpu.fregs[rs2]);
        }
        _ => {
            cpu.handle_exception(2, raw as u64, bus);
            return;
        }
    }
    cpu.pc += len;
}

/// FMADD.S / FMADD.D
fn exec_fmadd(cpu: &mut Cpu, raw: u32, len: u64) {
    let rd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let rs3 = ((raw >> 27) & 0x1F) as usize;
    let fmt = (raw >> 25) & 0x3;
    let _rm = (raw >> 12) & 0x7;

    cpu.csrs.set_fs_dirty();
    match fmt {
        0 => {
            // FMADD.S
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let c = unbox_f32(cpu.fregs[rs3]);
            let result = a.mul_add(b, c);
            cpu.fregs[rd] = nan_box(result.to_bits());
            accumulate_f32_flags(cpu, result);
        }
        1 => {
            // FMADD.D
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let c = to_f64(cpu.fregs[rs3]);
            let result = a.mul_add(b, c);
            cpu.fregs[rd] = result.to_bits();
            accumulate_f64_flags(cpu, result);
        }
        2 => {
            // FMADD.H (Zfh)
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let c = f16_to_f32(unbox_f16(cpu.fregs[rs3]));
            let result = f32_to_f16(a.mul_add(b, c));
            cpu.fregs[rd] = nan_box_h(result);
            accumulate_f16_flags(cpu, result);
        }
        _ => {}
    }
    cpu.pc += len;
}

/// FMSUB.S / FMSUB.D / FMSUB.H: rd = rs1*rs2 - rs3
fn exec_fmsub(cpu: &mut Cpu, raw: u32, len: u64) {
    let rd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let rs3 = ((raw >> 27) & 0x1F) as usize;
    let fmt = (raw >> 25) & 0x3;

    cpu.csrs.set_fs_dirty();
    match fmt {
        0 => {
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let c = unbox_f32(cpu.fregs[rs3]);
            let result = a.mul_add(b, -c);
            cpu.fregs[rd] = nan_box(result.to_bits());
            accumulate_f32_flags(cpu, result);
        }
        1 => {
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let c = to_f64(cpu.fregs[rs3]);
            let result = a.mul_add(b, -c);
            cpu.fregs[rd] = result.to_bits();
            accumulate_f64_flags(cpu, result);
        }
        2 => {
            // FMSUB.H (Zfh)
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let c = f16_to_f32(unbox_f16(cpu.fregs[rs3]));
            let result = f32_to_f16(a.mul_add(b, -c));
            cpu.fregs[rd] = nan_box_h(result);
            accumulate_f16_flags(cpu, result);
        }
        _ => {}
    }
    cpu.pc += len;
}

/// FNMSUB.S / FNMSUB.D / FNMSUB.H: rd = -(rs1*rs2) + rs3 = (-rs1)*rs2 + rs3
fn exec_fnmsub(cpu: &mut Cpu, raw: u32, len: u64) {
    let rd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let rs3 = ((raw >> 27) & 0x1F) as usize;
    let fmt = (raw >> 25) & 0x3;

    cpu.csrs.set_fs_dirty();
    match fmt {
        0 => {
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let c = unbox_f32(cpu.fregs[rs3]);
            let result = (-a).mul_add(b, c);
            cpu.fregs[rd] = nan_box(result.to_bits());
            accumulate_f32_flags(cpu, result);
        }
        1 => {
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let c = to_f64(cpu.fregs[rs3]);
            let result = (-a).mul_add(b, c);
            cpu.fregs[rd] = result.to_bits();
            accumulate_f64_flags(cpu, result);
        }
        2 => {
            // FNMSUB.H (Zfh)
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let c = f16_to_f32(unbox_f16(cpu.fregs[rs3]));
            let result = f32_to_f16((-a).mul_add(b, c));
            cpu.fregs[rd] = nan_box_h(result);
            accumulate_f16_flags(cpu, result);
        }
        _ => {}
    }
    cpu.pc += len;
}

/// FNMADD.S / FNMADD.D / FNMADD.H: rd = -(rs1*rs2) - rs3 = (-rs1)*rs2 - rs3
fn exec_fnmadd(cpu: &mut Cpu, raw: u32, len: u64) {
    let rd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let rs3 = ((raw >> 27) & 0x1F) as usize;
    let fmt = (raw >> 25) & 0x3;

    cpu.csrs.set_fs_dirty();
    match fmt {
        0 => {
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let c = unbox_f32(cpu.fregs[rs3]);
            let result = (-a).mul_add(b, -c);
            cpu.fregs[rd] = nan_box(result.to_bits());
            accumulate_f32_flags(cpu, result);
        }
        1 => {
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let c = to_f64(cpu.fregs[rs3]);
            let result = (-a).mul_add(b, -c);
            cpu.fregs[rd] = result.to_bits();
            accumulate_f64_flags(cpu, result);
        }
        2 => {
            // FNMADD.H (Zfh)
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let c = f16_to_f32(unbox_f16(cpu.fregs[rs3]));
            let result = f32_to_f16((-a).mul_add(b, -c));
            cpu.fregs[rd] = nan_box_h(result);
            accumulate_f16_flags(cpu, result);
        }
        _ => {}
    }
    cpu.pc += len;
}

/// OP-FP (opcode 0x53) — arithmetic, conversion, comparison, sign-injection, etc.
fn exec_fp_op(cpu: &mut Cpu, bus: &mut Bus, raw: u32, len: u64) {
    let rd = ((raw >> 7) & 0x1F) as usize;
    let rs1 = ((raw >> 15) & 0x1F) as usize;
    let rs2 = ((raw >> 20) & 0x1F) as usize;
    let funct7 = (raw >> 25) & 0x7F;
    let rm = (raw >> 12) & 0x7;
    let _frm = cpu.csrs.read(super::csr::FRM) as u32;

    match funct7 {
        // === Single-precision (F) ===
        0x00 => {
            // FADD.S
            cpu.csrs.set_fs_dirty();
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let r = a + b;
            cpu.fregs[rd] = nan_box(r.to_bits());
            accumulate_f32_flags(cpu, r);
        }
        0x04 => {
            // FSUB.S
            cpu.csrs.set_fs_dirty();
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let r = a - b;
            cpu.fregs[rd] = nan_box(r.to_bits());
            accumulate_f32_flags(cpu, r);
        }
        0x08 => {
            // FMUL.S
            cpu.csrs.set_fs_dirty();
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let r = a * b;
            cpu.fregs[rd] = nan_box(r.to_bits());
            accumulate_f32_flags(cpu, r);
        }
        0x0C => {
            // FDIV.S
            cpu.csrs.set_fs_dirty();
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            if b == 0.0 && !a.is_nan() {
                set_flags(cpu, DZ);
            }
            let r = a / b;
            cpu.fregs[rd] = nan_box(r.to_bits());
            accumulate_f32_flags(cpu, r);
        }
        0x2C => {
            // FSQRT.S
            cpu.csrs.set_fs_dirty();
            let a = unbox_f32(cpu.fregs[rs1]);
            if a < 0.0 && !a.is_nan() {
                set_flags(cpu, NV);
            }
            let r = a.sqrt();
            cpu.fregs[rd] = nan_box(r.to_bits());
            accumulate_f32_flags(cpu, r);
        }
        0x10 => {
            // FSGNJ.S / FSGNJN.S / FSGNJX.S
            cpu.csrs.set_fs_dirty();
            let a = cpu.fregs[rs1] as u32;
            let b = cpu.fregs[rs2] as u32;
            let result = match rm {
                0 => (a & 0x7FFF_FFFF) | (b & 0x8000_0000), // FSGNJ
                1 => (a & 0x7FFF_FFFF) | ((b ^ 0x8000_0000) & 0x8000_0000), // FSGNJN
                2 => (a & 0x7FFF_FFFF) | ((a ^ b) & 0x8000_0000), // FSGNJX
                _ => a,
            };
            cpu.fregs[rd] = nan_box(result);
        }
        0x14 => {
            // FMIN.S / FMAX.S / FMINM.S (Zfa) / FMAXM.S (Zfa)
            cpu.csrs.set_fs_dirty();
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let r = match rm {
                2 => {
                    // FMINM.S (Zfa) — IEEE 754-2019 minimum: NaN if either is NaN
                    if a.is_nan() || b.is_nan() {
                        if is_snan_f32(a) || is_snan_f32(b) {
                            set_flags(cpu, NV);
                        }
                        f32::from_bits(0x7FC0_0000)
                    } else if a == 0.0 && b == 0.0 {
                        if a.is_sign_negative() {
                            a
                        } else {
                            b
                        }
                    } else if a < b {
                        a
                    } else {
                        b
                    }
                }
                3 => {
                    // FMAXM.S (Zfa) — IEEE 754-2019 maximum: NaN if either is NaN
                    if a.is_nan() || b.is_nan() {
                        if is_snan_f32(a) || is_snan_f32(b) {
                            set_flags(cpu, NV);
                        }
                        f32::from_bits(0x7FC0_0000)
                    } else if a == 0.0 && b == 0.0 {
                        if a.is_sign_positive() {
                            a
                        } else {
                            b
                        }
                    } else if a > b {
                        a
                    } else {
                        b
                    }
                }
                _ => {
                    // FMIN.S (rm=0) / FMAX.S (rm=1)
                    if a.is_nan() && b.is_nan() {
                        set_flags(cpu, NV);
                        f32::from_bits(0x7FC0_0000)
                    } else if a.is_nan() {
                        if is_snan_f32(a) {
                            set_flags(cpu, NV);
                        }
                        b
                    } else if b.is_nan() {
                        if is_snan_f32(b) {
                            set_flags(cpu, NV);
                        }
                        a
                    } else {
                        match rm {
                            0 => {
                                if a == 0.0 && b == 0.0 {
                                    if a.is_sign_negative() {
                                        a
                                    } else {
                                        b
                                    }
                                } else if a < b {
                                    a
                                } else {
                                    b
                                }
                            }
                            1 => {
                                if a == 0.0 && b == 0.0 {
                                    if a.is_sign_positive() {
                                        a
                                    } else {
                                        b
                                    }
                                } else if a > b {
                                    a
                                } else {
                                    b
                                }
                            }
                            _ => a,
                        }
                    }
                }
            };
            cpu.fregs[rd] = nan_box(r.to_bits());
        }
        0x50 => {
            // FLE.S / FLT.S / FEQ.S / FLEQ.S (Zfa) / FLTQ.S (Zfa)
            let a = unbox_f32(cpu.fregs[rs1]);
            let b = unbox_f32(cpu.fregs[rs2]);
            let result = match rm {
                0 => {
                    // FLE.S
                    if a.is_nan() || b.is_nan() {
                        set_flags(cpu, NV);
                        0u64
                    } else {
                        (a <= b) as u64
                    }
                }
                1 => {
                    // FLT.S
                    if a.is_nan() || b.is_nan() {
                        set_flags(cpu, NV);
                        0u64
                    } else {
                        (a < b) as u64
                    }
                }
                2 => {
                    // FEQ.S
                    if is_snan_f32(a) || is_snan_f32(b) {
                        set_flags(cpu, NV);
                    }
                    if a.is_nan() || b.is_nan() {
                        0u64
                    } else {
                        (a == b) as u64
                    }
                }
                4 => {
                    // FLEQ.S (Zfa) — quiet: only sNaN raises NV
                    if is_snan_f32(a) || is_snan_f32(b) {
                        set_flags(cpu, NV);
                    }
                    if a.is_nan() || b.is_nan() {
                        0u64
                    } else {
                        (a <= b) as u64
                    }
                }
                5 => {
                    // FLTQ.S (Zfa) — quiet: only sNaN raises NV
                    if is_snan_f32(a) || is_snan_f32(b) {
                        set_flags(cpu, NV);
                    }
                    if a.is_nan() || b.is_nan() {
                        0u64
                    } else {
                        (a < b) as u64
                    }
                }
                _ => 0u64,
            };
            cpu.regs[rd] = result;
            cpu.pc += len;
            return;
        }
        0x60 => {
            // FCVT.W.S / FCVT.WU.S / FCVT.L.S / FCVT.LU.S
            let a = unbox_f32(cpu.fregs[rs1]);
            let result = match rs2 {
                0 => fcvt_to_i32(cpu, a as f64) as u64, // FCVT.W.S
                1 => fcvt_to_u32(cpu, a as f64) as u64, // FCVT.WU.S
                2 => fcvt_to_i64(cpu, a as f64),        // FCVT.L.S
                3 => fcvt_to_u64(cpu, a as f64),        // FCVT.LU.S
                _ => 0,
            };
            cpu.regs[rd] = result;
            cpu.pc += len;
            return;
        }
        0x68 => {
            // FCVT.S.W / FCVT.S.WU / FCVT.S.L / FCVT.S.LU
            cpu.csrs.set_fs_dirty();
            let r = match rs2 {
                0 => (cpu.regs[rs1] as i32 as f32).to_bits(), // FCVT.S.W
                1 => (cpu.regs[rs1] as u32 as f32).to_bits(), // FCVT.S.WU
                2 => (cpu.regs[rs1] as i64 as f32).to_bits(), // FCVT.S.L
                3 => (cpu.regs[rs1] as f32).to_bits(),        // FCVT.S.LU
                _ => 0,
            };
            cpu.fregs[rd] = nan_box(r);
        }
        0x70 => {
            match rm {
                0 => {
                    // FMV.X.W (move fp bits to integer reg)
                    cpu.regs[rd] = cpu.fregs[rs1] as u32 as i32 as i64 as u64;
                    cpu.pc += len;
                    return;
                }
                1 => {
                    // FCLASS.S
                    let f = unbox_f32(cpu.fregs[rs1]);
                    cpu.regs[rd] = fclass_f32(f) as u64;
                    cpu.pc += len;
                    return;
                }
                _ => {
                    cpu.handle_exception(2, raw as u64, bus);
                    return;
                }
            }
        }
        0x78 => {
            cpu.csrs.set_fs_dirty();
            if rs2 == 1 {
                // FLI.S (Zfa) — load immediate single-precision constant
                cpu.fregs[rd] = nan_box(fli_s_table(rs1));
            } else {
                // FMV.W.X (move integer bits to fp reg)
                cpu.fregs[rd] = nan_box(cpu.regs[rs1] as u32);
            }
        }

        // === Double-precision (D) ===
        0x01 => {
            // FADD.D
            cpu.csrs.set_fs_dirty();
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let r = a + b;
            cpu.fregs[rd] = r.to_bits();
            accumulate_f64_flags(cpu, r);
        }
        0x05 => {
            // FSUB.D
            cpu.csrs.set_fs_dirty();
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let r = a - b;
            cpu.fregs[rd] = r.to_bits();
            accumulate_f64_flags(cpu, r);
        }
        0x09 => {
            // FMUL.D
            cpu.csrs.set_fs_dirty();
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let r = a * b;
            cpu.fregs[rd] = r.to_bits();
            accumulate_f64_flags(cpu, r);
        }
        0x0D => {
            // FDIV.D
            cpu.csrs.set_fs_dirty();
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            if b == 0.0 && !a.is_nan() {
                set_flags(cpu, DZ);
            }
            let r = a / b;
            cpu.fregs[rd] = r.to_bits();
            accumulate_f64_flags(cpu, r);
        }
        0x2D => {
            // FSQRT.D
            cpu.csrs.set_fs_dirty();
            let a = to_f64(cpu.fregs[rs1]);
            if a < 0.0 && !a.is_nan() {
                set_flags(cpu, NV);
            }
            let r = a.sqrt();
            cpu.fregs[rd] = r.to_bits();
            accumulate_f64_flags(cpu, r);
        }
        0x11 => {
            // FSGNJ.D / FSGNJN.D / FSGNJX.D
            cpu.csrs.set_fs_dirty();
            let a = cpu.fregs[rs1];
            let b = cpu.fregs[rs2];
            let result = match rm {
                0 => (a & 0x7FFF_FFFF_FFFF_FFFF) | (b & 0x8000_0000_0000_0000),
                1 => {
                    (a & 0x7FFF_FFFF_FFFF_FFFF)
                        | ((b ^ 0x8000_0000_0000_0000) & 0x8000_0000_0000_0000)
                }
                2 => (a & 0x7FFF_FFFF_FFFF_FFFF) | ((a ^ b) & 0x8000_0000_0000_0000),
                _ => a,
            };
            cpu.fregs[rd] = result;
        }
        0x15 => {
            // FMIN.D / FMAX.D / FMINM.D (Zfa) / FMAXM.D (Zfa)
            cpu.csrs.set_fs_dirty();
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let r = match rm {
                2 => {
                    // FMINM.D (Zfa)
                    if a.is_nan() || b.is_nan() {
                        if is_snan_f64(a) || is_snan_f64(b) {
                            set_flags(cpu, NV);
                        }
                        f64::from_bits(0x7FF8_0000_0000_0000)
                    } else if a == 0.0 && b == 0.0 {
                        if a.is_sign_negative() {
                            a
                        } else {
                            b
                        }
                    } else if a < b {
                        a
                    } else {
                        b
                    }
                }
                3 => {
                    // FMAXM.D (Zfa)
                    if a.is_nan() || b.is_nan() {
                        if is_snan_f64(a) || is_snan_f64(b) {
                            set_flags(cpu, NV);
                        }
                        f64::from_bits(0x7FF8_0000_0000_0000)
                    } else if a == 0.0 && b == 0.0 {
                        if a.is_sign_positive() {
                            a
                        } else {
                            b
                        }
                    } else if a > b {
                        a
                    } else {
                        b
                    }
                }
                _ => {
                    if a.is_nan() && b.is_nan() {
                        set_flags(cpu, NV);
                        f64::from_bits(0x7FF8_0000_0000_0000)
                    } else if a.is_nan() {
                        if is_snan_f64(a) {
                            set_flags(cpu, NV);
                        }
                        b
                    } else if b.is_nan() {
                        if is_snan_f64(b) {
                            set_flags(cpu, NV);
                        }
                        a
                    } else {
                        match rm {
                            0 => {
                                if a == 0.0 && b == 0.0 {
                                    if a.is_sign_negative() {
                                        a
                                    } else {
                                        b
                                    }
                                } else if a < b {
                                    a
                                } else {
                                    b
                                }
                            }
                            1 => {
                                if a == 0.0 && b == 0.0 {
                                    if a.is_sign_positive() {
                                        a
                                    } else {
                                        b
                                    }
                                } else if a > b {
                                    a
                                } else {
                                    b
                                }
                            }
                            _ => a,
                        }
                    }
                }
            };
            cpu.fregs[rd] = r.to_bits();
        }
        0x51 => {
            // FLE.D / FLT.D / FEQ.D / FLEQ.D (Zfa) / FLTQ.D (Zfa)
            let a = to_f64(cpu.fregs[rs1]);
            let b = to_f64(cpu.fregs[rs2]);
            let result = match rm {
                0 => {
                    if a.is_nan() || b.is_nan() {
                        set_flags(cpu, NV);
                        0u64
                    } else {
                        (a <= b) as u64
                    }
                }
                1 => {
                    if a.is_nan() || b.is_nan() {
                        set_flags(cpu, NV);
                        0u64
                    } else {
                        (a < b) as u64
                    }
                }
                2 => {
                    if is_snan_f64(a) || is_snan_f64(b) {
                        set_flags(cpu, NV);
                    }
                    if a.is_nan() || b.is_nan() {
                        0u64
                    } else {
                        (a == b) as u64
                    }
                }
                4 => {
                    // FLEQ.D (Zfa) — quiet
                    if is_snan_f64(a) || is_snan_f64(b) {
                        set_flags(cpu, NV);
                    }
                    if a.is_nan() || b.is_nan() {
                        0u64
                    } else {
                        (a <= b) as u64
                    }
                }
                5 => {
                    // FLTQ.D (Zfa) — quiet
                    if is_snan_f64(a) || is_snan_f64(b) {
                        set_flags(cpu, NV);
                    }
                    if a.is_nan() || b.is_nan() {
                        0u64
                    } else {
                        (a < b) as u64
                    }
                }
                _ => 0u64,
            };
            cpu.regs[rd] = result;
            cpu.pc += len;
            return;
        }
        0x61 => {
            // FCVT.W.D / FCVT.WU.D / FCVT.L.D / FCVT.LU.D / FCVTMOD.W.D (Zfa)
            let a = to_f64(cpu.fregs[rs1]);
            let result = match rs2 {
                0 => fcvt_to_i32(cpu, a) as u64,
                1 => fcvt_to_u32(cpu, a) as u64,
                2 => fcvt_to_i64(cpu, a),
                3 => fcvt_to_u64(cpu, a),
                8 => {
                    // FCVTMOD.W.D (Zfa) — modular convert, always RTZ
                    fcvtmod_w_d(cpu, a)
                }
                _ => 0,
            };
            cpu.regs[rd] = result;
            cpu.pc += len;
            return;
        }
        0x69 => {
            // FCVT.D.W / FCVT.D.WU / FCVT.D.L / FCVT.D.LU
            cpu.csrs.set_fs_dirty();
            let r = match rs2 {
                0 => (cpu.regs[rs1] as i32 as f64).to_bits(),
                1 => (cpu.regs[rs1] as u32 as f64).to_bits(),
                2 => (cpu.regs[rs1] as i64 as f64).to_bits(),
                3 => (cpu.regs[rs1] as f64).to_bits(),
                _ => 0,
            };
            cpu.fregs[rd] = r;
        }
        0x71 => {
            match rm {
                0 => {
                    // FMV.X.D
                    cpu.regs[rd] = cpu.fregs[rs1];
                    cpu.pc += len;
                    return;
                }
                1 => {
                    // FCLASS.D
                    let f = to_f64(cpu.fregs[rs1]);
                    cpu.regs[rd] = fclass_f64(f) as u64;
                    cpu.pc += len;
                    return;
                }
                _ => {
                    cpu.handle_exception(2, raw as u64, bus);
                    return;
                }
            }
        }
        0x79 => {
            cpu.csrs.set_fs_dirty();
            if rs2 == 1 {
                // FLI.D (Zfa) — load immediate double-precision constant
                cpu.fregs[rd] = fli_d_table(rs1);
            } else {
                // FMV.D.X
                cpu.fregs[rd] = cpu.regs[rs1];
            }
        }
        // === Half-precision (H) — Zfh ===
        0x02 => {
            // FADD.H
            cpu.csrs.set_fs_dirty();
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let r = f32_to_f16(a + b);
            cpu.fregs[rd] = nan_box_h(r);
            accumulate_f16_flags(cpu, r);
        }
        0x06 => {
            // FSUB.H
            cpu.csrs.set_fs_dirty();
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let r = f32_to_f16(a - b);
            cpu.fregs[rd] = nan_box_h(r);
            accumulate_f16_flags(cpu, r);
        }
        0x0A => {
            // FMUL.H
            cpu.csrs.set_fs_dirty();
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let r = f32_to_f16(a * b);
            cpu.fregs[rd] = nan_box_h(r);
            accumulate_f16_flags(cpu, r);
        }
        0x0E => {
            // FDIV.H
            cpu.csrs.set_fs_dirty();
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            if b == 0.0 && !a.is_nan() {
                set_flags(cpu, DZ);
            }
            let r = f32_to_f16(a / b);
            cpu.fregs[rd] = nan_box_h(r);
            accumulate_f16_flags(cpu, r);
        }
        0x2E => {
            // FSQRT.H
            cpu.csrs.set_fs_dirty();
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            if a < 0.0 && !a.is_nan() {
                set_flags(cpu, NV);
            }
            let r = f32_to_f16(a.sqrt());
            cpu.fregs[rd] = nan_box_h(r);
            accumulate_f16_flags(cpu, r);
        }
        0x12 => {
            // FSGNJ.H / FSGNJN.H / FSGNJX.H
            cpu.csrs.set_fs_dirty();
            let a = unbox_f16(cpu.fregs[rs1]);
            let b = unbox_f16(cpu.fregs[rs2]);
            let result = match rm {
                0 => (a & 0x7FFF) | (b & 0x8000),
                1 => (a & 0x7FFF) | ((b ^ 0x8000) & 0x8000),
                2 => (a & 0x7FFF) | ((a ^ b) & 0x8000),
                _ => a,
            };
            cpu.fregs[rd] = nan_box_h(result);
        }
        0x16 => {
            // FMIN.H / FMAX.H
            cpu.csrs.set_fs_dirty();
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let r = match rm {
                0 => {
                    // FMIN.H
                    if a.is_nan() && b.is_nan() {
                        set_flags(cpu, NV);
                        f32::from_bits(0x7FC0_0000)
                    } else if a.is_nan() {
                        if is_snan_f32(a) {
                            set_flags(cpu, NV);
                        }
                        b
                    } else if b.is_nan() {
                        if is_snan_f32(b) {
                            set_flags(cpu, NV);
                        }
                        a
                    } else if a == 0.0 && b == 0.0 {
                        if a.is_sign_negative() {
                            a
                        } else {
                            b
                        }
                    } else if a < b {
                        a
                    } else {
                        b
                    }
                }
                1 => {
                    // FMAX.H
                    if a.is_nan() && b.is_nan() {
                        set_flags(cpu, NV);
                        f32::from_bits(0x7FC0_0000)
                    } else if a.is_nan() {
                        if is_snan_f32(a) {
                            set_flags(cpu, NV);
                        }
                        b
                    } else if b.is_nan() {
                        if is_snan_f32(b) {
                            set_flags(cpu, NV);
                        }
                        a
                    } else if a == 0.0 && b == 0.0 {
                        if a.is_sign_positive() {
                            a
                        } else {
                            b
                        }
                    } else if a > b {
                        a
                    } else {
                        b
                    }
                }
                _ => a,
            };
            cpu.fregs[rd] = nan_box_h(f32_to_f16(r));
        }
        0x52 => {
            // FLE.H / FLT.H / FEQ.H
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1]));
            let b = f16_to_f32(unbox_f16(cpu.fregs[rs2]));
            let result = match rm {
                0 => {
                    if a.is_nan() || b.is_nan() {
                        set_flags(cpu, NV);
                        0u64
                    } else {
                        (a <= b) as u64
                    }
                }
                1 => {
                    if a.is_nan() || b.is_nan() {
                        set_flags(cpu, NV);
                        0u64
                    } else {
                        (a < b) as u64
                    }
                }
                2 => {
                    let ah = unbox_f16(cpu.fregs[rs1]);
                    let bh = unbox_f16(cpu.fregs[rs2]);
                    if is_snan_f16(ah) || is_snan_f16(bh) {
                        set_flags(cpu, NV);
                    }
                    if a.is_nan() || b.is_nan() {
                        0u64
                    } else {
                        (a == b) as u64
                    }
                }
                _ => 0u64,
            };
            cpu.regs[rd] = result;
            cpu.pc += len;
            return;
        }
        0x62 => {
            // FCVT.W.H / FCVT.WU.H / FCVT.L.H / FCVT.LU.H
            let a = f16_to_f32(unbox_f16(cpu.fregs[rs1])) as f64;
            let result = match rs2 {
                0 => fcvt_to_i32(cpu, a) as u64,
                1 => fcvt_to_u32(cpu, a) as u64,
                2 => fcvt_to_i64(cpu, a),
                3 => fcvt_to_u64(cpu, a),
                _ => 0,
            };
            cpu.regs[rd] = result;
            cpu.pc += len;
            return;
        }
        0x6A => {
            // FCVT.H.W / FCVT.H.WU / FCVT.H.L / FCVT.H.LU
            cpu.csrs.set_fs_dirty();
            let r = match rs2 {
                0 => f32_to_f16(cpu.regs[rs1] as i32 as f32),
                1 => f32_to_f16(cpu.regs[rs1] as u32 as f32),
                2 => f32_to_f16(cpu.regs[rs1] as i64 as f32),
                3 => f32_to_f16(cpu.regs[rs1] as f32),
                _ => 0,
            };
            cpu.fregs[rd] = nan_box_h(r);
        }
        0x72 => {
            // FMV.X.H / FCLASS.H
            match rm {
                0 => {
                    // FMV.X.H: move half bits to integer, sign-extended
                    cpu.regs[rd] = cpu.fregs[rs1] as u16 as i16 as i64 as u64;
                    cpu.pc += len;
                    return;
                }
                1 => {
                    // FCLASS.H
                    cpu.regs[rd] = fclass_f16(unbox_f16(cpu.fregs[rs1])) as u64;
                    cpu.pc += len;
                    return;
                }
                _ => {
                    cpu.handle_exception(2, raw as u64, bus);
                    return;
                }
            }
        }
        0x7A => {
            // FMV.H.X
            cpu.csrs.set_fs_dirty();
            cpu.fregs[rd] = nan_box_h(cpu.regs[rs1] as u16);
        }

        // Conversions between S and D
        0x20 => {
            match rs2 {
                1 => {
                    // FCVT.S.D
                    cpu.csrs.set_fs_dirty();
                    let d = to_f64(cpu.fregs[rs1]);
                    let s = d as f32;
                    cpu.fregs[rd] = nan_box(s.to_bits());
                    accumulate_f32_flags(cpu, s);
                }
                2 => {
                    // FCVT.S.H (Zfh)
                    cpu.csrs.set_fs_dirty();
                    let h = unbox_f16(cpu.fregs[rs1]);
                    let s = f16_to_f32(h);
                    cpu.fregs[rd] = nan_box(s.to_bits());
                }
                4 => {
                    // FROUND.S (Zfa)
                    cpu.csrs.set_fs_dirty();
                    let a = unbox_f32(cpu.fregs[rs1]);
                    let r = fround_f32(cpu, a, rm, false);
                    cpu.fregs[rd] = nan_box(r.to_bits());
                }
                5 => {
                    // FROUNDNX.S (Zfa)
                    cpu.csrs.set_fs_dirty();
                    let a = unbox_f32(cpu.fregs[rs1]);
                    let r = fround_f32(cpu, a, rm, true);
                    cpu.fregs[rd] = nan_box(r.to_bits());
                }
                _ => {
                    cpu.handle_exception(2, raw as u64, bus);
                    return;
                }
            }
        }
        0x21 => {
            match rs2 {
                0 => {
                    // FCVT.D.S
                    cpu.csrs.set_fs_dirty();
                    let s = unbox_f32(cpu.fregs[rs1]);
                    let d = s as f64;
                    cpu.fregs[rd] = d.to_bits();
                }
                2 => {
                    // FCVT.D.H (Zfh)
                    cpu.csrs.set_fs_dirty();
                    let h = unbox_f16(cpu.fregs[rs1]);
                    let d = f16_to_f32(h) as f64;
                    cpu.fregs[rd] = d.to_bits();
                }
                4 => {
                    // FROUND.D (Zfa)
                    cpu.csrs.set_fs_dirty();
                    let a = to_f64(cpu.fregs[rs1]);
                    let r = fround_f64(cpu, a, rm, false);
                    cpu.fregs[rd] = r.to_bits();
                }
                5 => {
                    // FROUNDNX.D (Zfa)
                    cpu.csrs.set_fs_dirty();
                    let a = to_f64(cpu.fregs[rs1]);
                    let r = fround_f64(cpu, a, rm, true);
                    cpu.fregs[rd] = r.to_bits();
                }
                _ => {
                    cpu.handle_exception(2, raw as u64, bus);
                    return;
                }
            }
        }
        0x22 => {
            // FCVT.H.S (rs2=0) / FCVT.H.D (rs2=1)
            cpu.csrs.set_fs_dirty();
            match rs2 {
                0 => {
                    // FCVT.H.S
                    let s = unbox_f32(cpu.fregs[rs1]);
                    let h = f32_to_f16(s);
                    cpu.fregs[rd] = nan_box_h(h);
                    accumulate_f16_flags(cpu, h);
                }
                1 => {
                    // FCVT.H.D
                    let d = to_f64(cpu.fregs[rs1]);
                    let h = f32_to_f16(d as f32);
                    cpu.fregs[rd] = nan_box_h(h);
                    accumulate_f16_flags(cpu, h);
                }
                _ => {
                    cpu.handle_exception(2, raw as u64, bus);
                    return;
                }
            }
        }
        _ => {
            log::warn!("Unknown FP op funct7={:#x} at PC={:#x}", funct7, cpu.pc);
            cpu.handle_exception(2, raw as u64, bus);
            return;
        }
    }
    cpu.pc += len;
}

// === Helper functions ===

fn is_snan_f32(f: f32) -> bool {
    let bits = f.to_bits();
    // sNaN: exponent all 1s, mantissa non-zero with bit 22 = 0
    f.is_nan() && (bits & 0x0040_0000) == 0
}

fn is_snan_f64(f: f64) -> bool {
    let bits = f.to_bits();
    f.is_nan() && (bits & 0x0008_0000_0000_0000) == 0
}

fn accumulate_f32_flags(cpu: &mut Cpu, r: f32) {
    let mut flags = 0u64;
    if r.is_nan() {
        // Could be from invalid op (already set by caller for specific cases)
    }
    if r.is_infinite() {
        // overflow may have been set
    }
    // Use a simple heuristic: check if result is subnormal (underflow + inexact)
    let bits = r.to_bits();
    let exp = (bits >> 23) & 0xFF;
    if exp == 0 && (bits & 0x007F_FFFF) != 0 {
        flags |= UF | NX;
    }
    if flags != 0 {
        set_flags(cpu, flags);
    }
}

fn accumulate_f64_flags(cpu: &mut Cpu, r: f64) {
    let bits = r.to_bits();
    let exp = (bits >> 52) & 0x7FF;
    if exp == 0 && (bits & 0x000F_FFFF_FFFF_FFFF) != 0 {
        set_flags(cpu, UF | NX);
    }
}

fn fclass_f32(f: f32) -> u32 {
    let bits = f.to_bits();
    let sign = (bits >> 31) & 1;
    let exp = (bits >> 23) & 0xFF;
    let frac = bits & 0x007F_FFFF;

    if exp == 0xFF {
        if frac == 0 {
            if sign == 1 {
                1 << 0
            } else {
                1 << 7
            } // -inf / +inf  — wait, reversed
              // bit 0 = -inf, bit 7 = +inf
        } else if frac & 0x0040_0000 != 0 {
            1 << 9 // quiet NaN
        } else {
            1 << 8 // signaling NaN
        }
    } else if exp == 0 {
        if frac == 0 {
            if sign == 1 {
                1 << 3
            } else {
                1 << 4
            } // -0 / +0
        } else if sign == 1 {
            1 << 2 // negative subnormal
        } else {
            1 << 5 // positive subnormal
        }
    } else if sign == 1 {
        1 << 1 // negative normal
    } else {
        1 << 6 // positive normal
    }
}

fn fclass_f64(f: f64) -> u32 {
    let bits = f.to_bits();
    let sign = (bits >> 63) & 1;
    let exp = (bits >> 52) & 0x7FF;
    let frac = bits & 0x000F_FFFF_FFFF_FFFF;

    if exp == 0x7FF {
        if frac == 0 {
            if sign == 1 {
                1 << 0
            } else {
                1 << 7
            }
        } else if frac & 0x0008_0000_0000_0000 != 0 {
            1 << 9
        } else {
            1 << 8
        }
    } else if exp == 0 {
        if frac == 0 {
            if sign == 1 {
                1 << 3
            } else {
                1 << 4
            }
        } else if sign == 1 {
            1 << 2
        } else {
            1 << 5
        }
    } else if sign == 1 {
        1 << 1
    } else {
        1 << 6
    }
}

/// Convert f64 to i32, clamping out-of-range values (RISC-V saturation semantics)
fn fcvt_to_i32(cpu: &mut Cpu, f: f64) -> i64 {
    if f.is_nan() {
        set_flags(cpu, NV);
        return i32::MAX as i64;
    }
    let v = f as i64;
    if f >= i32::MAX as f64 {
        set_flags(cpu, NV);
        i32::MAX as i64
    } else if f < i32::MIN as f64 {
        set_flags(cpu, NV);
        i32::MIN as i64
    } else {
        // Sign-extend to 64 bits
        v as i32 as i64
    }
}

fn fcvt_to_u32(cpu: &mut Cpu, f: f64) -> i64 {
    if f.is_nan() {
        set_flags(cpu, NV);
        return u32::MAX as i32 as i64; // sign-extended
    }
    if f >= (u32::MAX as f64 + 1.0) {
        set_flags(cpu, NV);
        return u32::MAX as i32 as i64;
    }
    if f < 0.0 {
        if f > -1.0 {
            // Rounds to 0
            return 0;
        }
        set_flags(cpu, NV);
        return 0;
    }
    let v = f as u32;
    v as i32 as i64
}

fn fcvt_to_i64(cpu: &mut Cpu, f: f64) -> u64 {
    if f.is_nan() {
        set_flags(cpu, NV);
        return i64::MAX as u64;
    }
    if f >= i64::MAX as f64 {
        set_flags(cpu, NV);
        return i64::MAX as u64;
    }
    if f < i64::MIN as f64 {
        set_flags(cpu, NV);
        return i64::MIN as u64;
    }
    f as i64 as u64
}

fn fcvt_to_u64(cpu: &mut Cpu, f: f64) -> u64 {
    if f.is_nan() {
        set_flags(cpu, NV);
        return u64::MAX;
    }
    if f >= u64::MAX as f64 {
        set_flags(cpu, NV);
        return u64::MAX;
    }
    if f < 0.0 {
        if f > -1.0 {
            return 0;
        }
        set_flags(cpu, NV);
        return 0;
    }
    f as u64
}

// =====================================================================
// Zfa extension helpers
// =====================================================================

/// FLI.S constant table — 32 single-precision values indexed by rs1
fn fli_s_table(idx: usize) -> u32 {
    const TABLE: [u32; 32] = [
        0xBF80_0000, // 0: -1.0
        0x0080_0000, // 1: minimum positive normal
        0x3780_0000, // 2: 2^-16
        0x3800_0000, // 3: 2^-15
        0x3B80_0000, // 4: 2^-8
        0x3C00_0000, // 5: 2^-7
        0x3D80_0000, // 6: 2^-4 (0.0625)
        0x3E00_0000, // 7: 2^-3 (0.125)
        0x3E80_0000, // 8: 0.25
        0x3EA0_0000, // 9: 0.3125
        0x3EC0_0000, // 10: 0.375
        0x3EE0_0000, // 11: 0.4375
        0x3F00_0000, // 12: 0.5
        0x3F20_0000, // 13: 0.625
        0x3F40_0000, // 14: 0.75
        0x3F60_0000, // 15: 0.875
        0x3F80_0000, // 16: 1.0
        0x3FA0_0000, // 17: 1.25
        0x3FC0_0000, // 18: 1.5
        0x3FE0_0000, // 19: 1.75
        0x4000_0000, // 20: 2.0
        0x4020_0000, // 21: 2.5
        0x4040_0000, // 22: 3.0
        0x4080_0000, // 23: 4.0
        0x4100_0000, // 24: 8.0
        0x4180_0000, // 25: 16.0
        0x4300_0000, // 26: 128.0 (2^7)
        0x4380_0000, // 27: 256.0 (2^8)
        0x4700_0000, // 28: 2^15
        0x4780_0000, // 29: 2^16
        0x7F80_0000, // 30: +inf
        0x7FC0_0000, // 31: canonical NaN
    ];
    TABLE[idx & 0x1F]
}

/// FLI.D constant table — 32 double-precision values indexed by rs1
fn fli_d_table(idx: usize) -> u64 {
    const TABLE: [u64; 32] = [
        0xBFF0_0000_0000_0000, // 0: -1.0
        0x0010_0000_0000_0000, // 1: minimum positive normal (double)
        0x3EF0_0000_0000_0000, // 2: 2^-16
        0x3F00_0000_0000_0000, // 3: 2^-15
        0x3F70_0000_0000_0000, // 4: 2^-8
        0x3F80_0000_0000_0000, // 5: 2^-7
        0x3FB0_0000_0000_0000, // 6: 2^-4 (0.0625)
        0x3FC0_0000_0000_0000, // 7: 2^-3 (0.125)
        0x3FD0_0000_0000_0000, // 8: 0.25
        0x3FD4_0000_0000_0000, // 9: 0.3125
        0x3FD8_0000_0000_0000, // 10: 0.375
        0x3FDC_0000_0000_0000, // 11: 0.4375
        0x3FE0_0000_0000_0000, // 12: 0.5
        0x3FE4_0000_0000_0000, // 13: 0.625
        0x3FE8_0000_0000_0000, // 14: 0.75
        0x3FEC_0000_0000_0000, // 15: 0.875
        0x3FF0_0000_0000_0000, // 16: 1.0
        0x3FF4_0000_0000_0000, // 17: 1.25
        0x3FF8_0000_0000_0000, // 18: 1.5
        0x3FFC_0000_0000_0000, // 19: 1.75
        0x4000_0000_0000_0000, // 20: 2.0
        0x4004_0000_0000_0000, // 21: 2.5
        0x4008_0000_0000_0000, // 22: 3.0
        0x4010_0000_0000_0000, // 23: 4.0
        0x4020_0000_0000_0000, // 24: 8.0
        0x4030_0000_0000_0000, // 25: 16.0
        0x4060_0000_0000_0000, // 26: 128.0 (2^7)
        0x4070_0000_0000_0000, // 27: 256.0 (2^8)
        0x40E0_0000_0000_0000, // 28: 2^15
        0x40F0_0000_0000_0000, // 29: 2^16
        0x7FF0_0000_0000_0000, // 30: +inf
        0x7FF8_0000_0000_0000, // 31: canonical NaN
    ];
    TABLE[idx & 0x1F]
}

/// Resolve rounding mode: if rm==7 (dynamic), use FRM CSR
fn resolve_rm(cpu: &Cpu, rm: u32) -> u32 {
    if rm == 7 {
        cpu.csrs.read(super::csr::FRM) as u32 & 0x7
    } else {
        rm
    }
}

/// FROUND.S / FROUNDNX.S helper
fn fround_f32(cpu: &mut Cpu, a: f32, rm: u32, set_inexact: bool) -> f32 {
    if a.is_nan() {
        if is_snan_f32(a) {
            set_flags(cpu, NV);
        }
        return f32::from_bits(0x7FC0_0000); // canonical NaN
    }
    if a.is_infinite() || a == 0.0 {
        return a;
    }
    let mode = resolve_rm(cpu, rm);
    let rounded = round_f64_to_int(a as f64, mode);
    let result = rounded as f32;
    if set_inexact && result != a {
        set_flags(cpu, NX);
    }
    result
}

/// FROUND.D / FROUNDNX.D helper
fn fround_f64(cpu: &mut Cpu, a: f64, rm: u32, set_inexact: bool) -> f64 {
    if a.is_nan() {
        if is_snan_f64(a) {
            set_flags(cpu, NV);
        }
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    if a.is_infinite() || a == 0.0 {
        return a;
    }
    let mode = resolve_rm(cpu, rm);
    let result = round_f64_to_int(a, mode);
    if set_inexact && result != a {
        set_flags(cpu, NX);
    }
    result
}

/// Round f64 to integer using specified rounding mode
fn round_f64_to_int(val: f64, mode: u32) -> f64 {
    match mode {
        0 => {
            // RNE — round to nearest, ties to even
            let r = val.round();
            // Check for tie: if exactly halfway, round to even
            let frac = (val - val.floor()).abs();
            if (frac - 0.5).abs() < f64::EPSILON {
                let floored = val.floor();
                let ceiled = val.ceil();
                if (floored as i64) % 2 == 0 {
                    floored
                } else {
                    ceiled
                }
            } else {
                r
            }
        }
        1 => {
            // RTZ — round towards zero
            val.trunc()
        }
        2 => {
            // RDN — round down (towards -inf)
            val.floor()
        }
        3 => {
            // RUP — round up (towards +inf)
            val.ceil()
        }
        4 => {
            // RMM — round to nearest, ties to max magnitude
            val.round()
        }
        _ => val.round(),
    }
}

/// FCVTMOD.W.D (Zfa) — modular convert double to i32, always RTZ
fn fcvtmod_w_d(cpu: &mut Cpu, f: f64) -> u64 {
    if f.is_nan() || f.is_infinite() {
        set_flags(cpu, NV);
        return 0u64;
    }
    // Truncate to integer, then take low 32 bits, sign-extend
    let truncated = f.trunc();
    if truncated != f {
        set_flags(cpu, NX);
    }
    // Convert to large integer, take low 32 bits
    // For very large values, we need modular arithmetic
    let as_i128 = truncated as i128;
    let low32 = (as_i128 & 0xFFFF_FFFF) as u32;
    // Sign-extend to 64 bits
    low32 as i32 as i64 as u64
}
