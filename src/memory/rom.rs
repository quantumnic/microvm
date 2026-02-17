/// Boot ROM — generates a minimal trampoline to jump to kernel entry
pub struct BootRom;

impl BootRom {
    /// Generate boot code that:
    /// 1. Sets a0 = hartid (0)
    /// 2. Sets a1 = DTB address
    /// 3. Jumps to kernel entry point
    pub fn generate(kernel_entry: u64, dtb_addr: u64) -> Vec<u8> {
        let mut code: Vec<u32> = Vec::new();

        // li a0, 0 (hartid)
        code.push(0x00000513); // addi a0, zero, 0

        // Load DTB address into a1
        // lui a1, hi20(dtb_addr)
        // addi a1, a1, lo12(dtb_addr)
        let dtb_hi = ((dtb_addr.wrapping_add(0x800) >> 12) & 0xFFFFF) as u32;
        let dtb_lo = (dtb_addr & 0xFFF) as u32;
        code.push((dtb_hi << 12) | 0x5B7); // lui a1, dtb_hi
        code.push((dtb_lo << 20) | 0x58593); // addi a1, a1, dtb_lo

        // Jump to kernel
        // lui t0, hi20(kernel_entry)
        // addi t0, t0, lo12(kernel_entry)
        // jr t0
        let kern_hi = ((kernel_entry.wrapping_add(0x800) >> 12) & 0xFFFFF) as u32;
        let kern_lo = (kernel_entry & 0xFFF) as u32;
        code.push((kern_hi << 12) | 0x2B7); // lui t0, kern_hi
        code.push((kern_lo << 20) | 0x28293); // addi t0, t0, kern_lo
        code.push(0x00028067); // jalr zero, t0, 0 (jr t0)

        code.iter().flat_map(|w| w.to_le_bytes()).collect()
    }
}
