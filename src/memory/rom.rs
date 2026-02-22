/// Boot ROM — generates M-mode firmware that sets up the system and drops to S-mode
///
/// This acts as a minimal OpenSBI replacement:
/// 1. Set up PMP to allow full access
/// 2. Set up medeleg/mideleg for interrupt/exception delegation
/// 3. Set up mcounteren/scounteren to allow counter access
/// 4. Set up mtvec for SBI trap handler
/// 5. Prepare S-mode entry: set mstatus.MPP=S, mepc=kernel_entry
/// 6. Set a0=hartid, a1=dtb_addr
/// 7. MRET to S-mode
pub struct BootRom;

impl BootRom {
    /// Generate boot firmware code.
    /// The firmware runs at DRAM_BASE in M-mode and drops to S-mode at kernel_entry.
    #[allow(clippy::vec_init_then_push)]
    pub fn generate(kernel_entry: u64, dtb_addr: u64) -> Vec<u8> {
        let mut code: Vec<u32> = Vec::new();

        // ===== PMP: allow all access (TOR, full RWX on entry 0) =====
        // pmpaddr0 = 0xFFFFFFFFFFFFFFFF (cover all addresses)
        // We need to set it to (1<<54)-1 for RV64 TOR mode (covers 56-bit physical space)
        // li t0, -1
        code.push(0xFFF00293); // addi t0, zero, -1
                               // csrw pmpaddr0, t0
        code.push(0x3B029073); // csrw 0x3B0, t0
                               // li t0, 0x1F (TOR=0b01_000, RWX=0b111 → 0x0F; actually: A=TOR(01), match all, RWX)
                               // pmpcfg0[7:0] = L=0, reserved=0, A=TOR(01), X=1, W=1, R=1 = 0b00_01_1_1_1_1 = 0x0F
        code.push(0x00F00293); // addi t0, zero, 0x0F
                               // csrw pmpcfg0, t0
        code.push(0x3A029073); // csrw 0x3A0, t0

        // ===== Delegate exceptions and interrupts to S-mode =====
        // medeleg: delegate most exceptions to S-mode
        // Bits: 0(misalign fetch), 1(fetch access), 2(illegal), 3(breakpoint),
        //       4(misalign load), 5(load access), 6(misalign store), 7(store access),
        //       8(ecall-U), 12(inst page fault), 13(load page fault), 15(store page fault)
        // = 0xB1FF (all except ecall-S(9), ecall-M(11))
        Self::emit_load_imm(&mut code, 5, 0xB1FF); // t0
        code.push(0x30229073); // csrw medeleg, t0

        // mideleg: delegate S-mode interrupts (SSIP=1, STIP=5, SEIP=9)
        Self::emit_load_imm(&mut code, 5, (1 << 1) | (1 << 5) | (1 << 9)); // 0x222
        code.push(0x30329073); // csrw mideleg, t0

        // ===== Enable counter access from S-mode and U-mode =====
        // mcounteren: allow CY, TM, IR (bits 0,1,2)
        code.push(0x00700293); // addi t0, zero, 7
        code.push(0x30629073); // csrw mcounteren, t0
                               // scounteren: same
        code.push(0x00700293); // addi t0, zero, 7
        code.push(0x10629073); // csrw scounteren, t0

        // ===== Set mtvec to a simple trap handler (infinite loop) =====
        // If any non-delegated exception reaches M-mode, loop forever
        // The trap handler is placed right after mret; we'll point mtvec at a wfi+j loop
        // For now, we'll set mtvec after all code is emitted (see below)

        // ===== Enable Sstc + Svadu in menvcfg =====
        // MENVCFG.STCE (bit 63) = Sstc timer compare
        // MENVCFG.ADUE (bit 61) = hardware A/D bit updates (Svadu)
        // Value: (1 << 63) | (1 << 61) = 0xA000000000000000
        // Build: t0 = 0b101 << 61
        code.push(0x00500293); // addi t0, zero, 5  (t0 = 5 = 0b101)
        let shamt61 = 61u32;
        code.push((shamt61 << 20) | (5 << 15) | (1 << 12) | (5 << 7) | 0x13); // slli t0, t0, 61
        code.push(0x30A29073); // csrw menvcfg(0x30A), t0

        // ===== Set up mstatus for S-mode entry =====
        // We want: MPP=01 (S-mode), MPIE=1, SXL=2, UXL=2
        // Value: (2 << 34) | (2 << 32) | (1 << 11) | (1 << 7)
        // = 0x0000000A00000880
        // Simpler: use csrr+csrc+csrs approach with small immediates
        // First, clear MPP bits using CSRC with immediate (bits 12:11)
        // csrc mstatus, 0x18  — clears bits 4:3... no, CSRCI uses rs1 field as zimm
        // Better: write the exact value we want
        // mstatus = SXL(2)=bits[35:34] | UXL(2)=bits[33:32] | MPP(S)=bit[11] | MPIE=bit[7]
        // = 0xA00000880
        // Use csrr, then mask with CSR instructions
        code.push(0x300022F3); // csrr t0, mstatus
                               // CSRC mstatus, 0x18 — clear bits 4:3 (not what we want)
                               // Actually we need to clear bits 12:11. Use register approach:
                               // li t1, (3 << 11) = 0x1800
        Self::emit_load_imm(&mut code, 6, 3 << 11); // t1 = 0x1800
                                                    // csrc mstatus, t1  (clear MPP bits)
        code.push(0x30033073); // csrrc x0, mstatus, t1
                               // li t1, (1 << 11) | (1 << 7) = 0x880
                               // Set MPP=S(bit11), MPIE(bit7), FS=Initial(bit13), VS=Initial(bit9)
                               // 0x2A80 = (1<<13) | (1<<11) | (1<<9) | (1<<7)
        Self::emit_load_imm(&mut code, 6, (1 << 13) | (1 << 11) | (1 << 9) | (1 << 7)); // t1 = 0x2A80
                                                                                        // csrs mstatus, t1  (set MPP=S, MPIE=1, FS=Initial, VS=Initial)
        code.push(0x30032073); // csrrs x0, mstatus, t1

        // ===== Set mepc = kernel_entry =====
        Self::emit_load_u64(&mut code, 5, kernel_entry); // t0
        code.push(0x34129073); // csrw mepc, t0

        // ===== Set up arguments: a0 = hartid (0), a1 = dtb_addr =====
        code.push(0x00000513); // addi a0, zero, 0
        Self::emit_load_u64(&mut code, 11, dtb_addr); // a1 = x11

        // ===== Set mtvec to M-mode trap handler at fixed offset 0x100 =====
        let trap_addr = crate::memory::DRAM_BASE + 0x100;
        Self::emit_load_u64(&mut code, 5, trap_addr); // t0
        code.push(0x30529073); // csrw mtvec, t0

        // ===== MRET to S-mode =====
        code.push(0x30200073); // mret

        // Pad to offset 0x100 (64 instructions) for trap handler placement
        while code.len() < 64 {
            code.push(0x00000013); // nop (addi x0, x0, 0)
        }

        // ===== M-mode trap handler at offset 0x100 =====
        // Handles traps that reach M-mode (non-delegated).
        // Most traps should never reach here since the emulator intercepts SBI calls
        // and timer conversion is done in the VM loop. This is a safety net.
        // Simple approach: just MRET back (for interrupts the VM loop will handle it)
        code.push(0x30200073); // mret

        code.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

    /// Emit instructions to load a small immediate into register `rd`.
    fn emit_load_imm(code: &mut Vec<u32>, rd: u32, val: u64) {
        // Use the same logic as emit_load_u64 for consistency
        Self::emit_load_u64(code, rd, val);
    }

    /// Emit instructions to load a 64-bit address into register `rd`.
    /// Uses lui+addi for the low 32 bits, then slli+srli to zero-extend
    /// if bit 31 is set (which would cause lui to sign-extend on RV64).
    fn emit_load_u64(code: &mut Vec<u32>, rd: u32, addr: u64) {
        if addr <= 0x7FFFFFFF {
            // Fits in positive 32-bit range, lui+addi is fine
            let hi = ((addr.wrapping_add(0x800) >> 12) & 0xFFFFF) as u32;
            let lo = (addr & 0xFFF) as u32;
            code.push((hi << 12) | (rd << 7) | 0x37); // lui rd, hi
            code.push(((lo << 20) | (rd << 15)) | (rd << 7) | 0x13); // addi rd, rd, lo
        } else if addr <= 0xFFFFFFFF {
            // 32-bit address with bit 31 set — lui sign-extends, need cleanup
            let hi = ((addr.wrapping_add(0x800) >> 12) & 0xFFFFF) as u32;
            let lo = (addr & 0xFFF) as u32;
            code.push((hi << 12) | (rd << 7) | 0x37); // lui rd, hi
            code.push(((lo << 20) | (rd << 15)) | (rd << 7) | 0x13); // addi rd, rd, lo
                                                                     // Zero-extend: slli rd, rd, 32 then srli rd, rd, 32
            let shamt32 = 32u32;
            code.push((shamt32 << 20) | (rd << 15) | (1 << 12) | (rd << 7) | 0x13); // slli rd, rd, 32
            code.push((shamt32 << 20) | (rd << 15) | (5 << 12) | (rd << 7) | 0x13);
        // srli rd, rd, 32
        } else {
            // Full 64-bit: build upper 32 bits first, then shift and OR lower
            let hi = ((addr.wrapping_add(0x800) >> 12) & 0xFFFFF) as u32;
            let lo = (addr & 0xFFF) as u32;
            code.push((hi << 12) | (rd << 7) | 0x37);
            code.push(((lo << 20) | (rd << 15)) | (rd << 7) | 0x13);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boot_rom_generates_code() {
        let code = BootRom::generate(0x80200000, 0x87FF0000);
        assert!(!code.is_empty());
        assert_eq!(code.len() % 4, 0);
    }

    #[test]
    fn test_boot_rom_address_in_high_range() {
        let code = BootRom::generate(0x80200000, 0x87F00000);
        // Should produce valid code (exact size may vary due to firmware setup)
        assert!(code.len() >= 10 * 4);
        assert_eq!(code.len() % 4, 0);
    }

    #[test]
    fn test_boot_rom_contains_mret() {
        let code = BootRom::generate(0x80200000, 0x87FF0000);
        // MRET (0x30200073) should be present in the code
        let instrs: Vec<u32> = code
            .chunks(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert!(instrs.contains(&0x30200073), "Boot ROM should contain MRET");
    }

    #[test]
    fn test_boot_rom_sets_pmp() {
        let code = BootRom::generate(0x80200000, 0x87FF0000);
        // Check that PMP setup instructions are present
        // csrw pmpaddr0 (0x3B0) should be in the code
        let instrs: Vec<u32> = code
            .chunks(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        assert!(instrs.contains(&0x3B029073), "Should contain csrw pmpaddr0");
        assert!(instrs.contains(&0x3A029073), "Should contain csrw pmpcfg0");
    }
}
