//! Kernel image loader — supports ELF64 and RISC-V Linux Image format.
//!
//! Detects the format automatically:
//! - ELF64: Parses program headers, loads LOAD segments into memory
//! - RISC-V Image: Detects the magic, extracts entry offset and load size
//! - Raw binary: Fallback — loads the entire file at the specified address

/// Result of loading a kernel image.
pub struct LoadedKernel {
    /// Entry point (physical address)
    pub entry: u64,
    /// Where the kernel was loaded (lowest physical address)
    pub load_base: u64,
    /// Total size in memory
    pub load_size: u64,
}

/// RISC-V Linux Image header (64 bytes)
/// See: https://www.kernel.org/doc/html/latest/arch/riscv/boot-image-header.html
const RISCV_IMAGE_MAGIC_OLD: u32 = 0x5643534f; // Legacy magic (pre-6.x kernels)
const RISCV_IMAGE_MAGIC_NEW: [u8; 5] = *b"RISCV"; // Modern magic (Linux 6.x+ EFI stub)

/// ELF magic
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Detect format and load kernel into memory
pub fn load_kernel(data: &[u8], load_addr: u64, ram: &mut [u8], dram_base: u64) -> LoadedKernel {
    if data.len() >= 4 && data[0..4] == ELF_MAGIC {
        load_elf(data, ram, dram_base)
    } else if data.len() >= 64 && detect_riscv_image(data) {
        load_riscv_image(data, ram, dram_base)
    } else {
        load_raw(data, load_addr, ram, dram_base)
    }
}

/// Detect RISC-V Linux Image format
/// Header layout (all little-endian):
///   offset 0:  u32 code0 (jump instruction)
///   offset 4:  u32 code1
///   offset 8:  u64 text_offset (offset from load address)
///   offset 16: u64 image_size (0 = unknown)
///   offset 24: u64 flags
///   offset 32: u32 version
///   offset 36: u32 res1
///   offset 40: u64 res2
///   offset 48: u64 magic ("RSCV\x00\x00\x00\x00" → 0x5643534f at offset 48)
///   offset 56: u32 magic2 (PE header for EFI, or 0)
///   offset 60: u32 res3
fn detect_riscv_image(data: &[u8]) -> bool {
    if data.len() < 64 {
        return false;
    }
    // Check legacy magic (u32 at offset 48)
    let magic = u32::from_le_bytes([data[48], data[49], data[50], data[51]]);
    if magic == RISCV_IMAGE_MAGIC_OLD {
        return true;
    }
    // Check modern magic: "RISCV" at offset 48 (Linux 6.x+ with EFI stub)
    if data[48..53] == RISCV_IMAGE_MAGIC_NEW {
        return true;
    }
    false
}

fn load_riscv_image(data: &[u8], ram: &mut [u8], dram_base: u64) -> LoadedKernel {
    let text_offset = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let image_size = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let size = if image_size == 0 {
        data.len() as u64
    } else {
        image_size
    };

    // Load at DRAM_BASE + text_offset (typically 0x200000 = 2MiB)
    let load_addr = dram_base + text_offset;
    let ram_offset = (load_addr - dram_base) as usize;
    let copy_len = std::cmp::min(data.len(), size as usize);

    if ram_offset + copy_len <= ram.len() {
        ram[ram_offset..ram_offset + copy_len].copy_from_slice(&data[..copy_len]);
    }

    log::info!(
        "RISC-V Image: text_offset={:#x}, size={:#x}, loaded at {:#x}",
        text_offset,
        size,
        load_addr
    );

    LoadedKernel {
        entry: load_addr,
        load_base: load_addr,
        load_size: size,
    }
}

fn load_elf(data: &[u8], ram: &mut [u8], dram_base: u64) -> LoadedKernel {
    // Parse ELF64 header
    if data.len() < 64 {
        log::warn!("ELF file too small");
        return LoadedKernel {
            entry: dram_base,
            load_base: dram_base,
            load_size: 0,
        };
    }

    let class = data[4];
    if class != 2 {
        log::warn!("Not an ELF64 file (class={})", class);
        return load_raw(data, dram_base + 0x200000, ram, dram_base);
    }

    let endian = data[5]; // 1=LE, 2=BE
    if endian != 1 {
        log::warn!("ELF is not little-endian");
        return load_raw(data, dram_base + 0x200000, ram, dram_base);
    }

    let machine = u16::from_le_bytes([data[18], data[19]]);
    if machine != 243 {
        // EM_RISCV = 243
        log::warn!("ELF machine type {} is not RISC-V (243)", machine);
    }

    let entry = u64::from_le_bytes(data[24..32].try_into().unwrap());
    let phoff = u64::from_le_bytes(data[32..40].try_into().unwrap());
    let phentsize = u16::from_le_bytes([data[54], data[55]]) as u64;
    let phnum = u16::from_le_bytes([data[56], data[57]]) as u64;

    log::info!(
        "ELF64: entry={:#x}, phoff={:#x}, phnum={}, phentsize={}",
        entry,
        phoff,
        phnum,
        phentsize
    );

    let mut load_base = u64::MAX;
    let mut load_end = 0u64;

    // Load PT_LOAD segments
    for i in 0..phnum {
        let off = (phoff + i * phentsize) as usize;
        if off + phentsize as usize > data.len() {
            break;
        }
        let phdr = &data[off..off + phentsize as usize];

        let p_type = u32::from_le_bytes(phdr[0..4].try_into().unwrap());
        if p_type != 1 {
            // PT_LOAD = 1
            continue;
        }

        let p_offset = u64::from_le_bytes(phdr[8..16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(phdr[16..24].try_into().unwrap());
        let p_paddr = u64::from_le_bytes(phdr[24..32].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(phdr[32..40].try_into().unwrap());
        let p_memsz = u64::from_le_bytes(phdr[40..48].try_into().unwrap());

        // Use physical address for loading
        let addr = if p_paddr != 0 { p_paddr } else { p_vaddr };

        log::info!(
            "  PT_LOAD: paddr={:#x} filesz={:#x} memsz={:#x}",
            addr,
            p_filesz,
            p_memsz
        );

        if addr < dram_base {
            log::warn!("  Segment below DRAM_BASE, skipping");
            continue;
        }

        let ram_offset = (addr - dram_base) as usize;
        let file_offset = p_offset as usize;
        let copy_len = p_filesz as usize;

        // Copy file data
        if ram_offset + copy_len <= ram.len() && file_offset + copy_len <= data.len() {
            ram[ram_offset..ram_offset + copy_len]
                .copy_from_slice(&data[file_offset..file_offset + copy_len]);
        }

        // Zero BSS (memsz > filesz)
        if p_memsz > p_filesz {
            let bss_start = ram_offset + copy_len;
            let bss_len = (p_memsz - p_filesz) as usize;
            if bss_start + bss_len <= ram.len() {
                ram[bss_start..bss_start + bss_len].fill(0);
            }
        }

        load_base = load_base.min(addr);
        load_end = load_end.max(addr + p_memsz);
    }

    if load_base == u64::MAX {
        load_base = dram_base;
    }

    LoadedKernel {
        entry,
        load_base,
        load_size: load_end.saturating_sub(load_base),
    }
}

fn load_raw(data: &[u8], load_addr: u64, ram: &mut [u8], dram_base: u64) -> LoadedKernel {
    let ram_offset = (load_addr - dram_base) as usize;
    if ram_offset + data.len() <= ram.len() {
        ram[ram_offset..ram_offset + data.len()].copy_from_slice(data);
    }
    LoadedKernel {
        entry: load_addr,
        load_base: load_addr,
        load_size: data.len() as u64,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_riscv_image() {
        let mut data = vec![0u8; 64];
        // Set legacy magic at offset 48
        data[48..52].copy_from_slice(&RISCV_IMAGE_MAGIC_OLD.to_le_bytes());
        assert!(detect_riscv_image(&data));

        // Wrong magic
        data[48] = 0;
        assert!(!detect_riscv_image(&data));

        // Modern magic "RISCV" at offset 48
        data[48..53].copy_from_slice(&RISCV_IMAGE_MAGIC_NEW);
        assert!(detect_riscv_image(&data));
    }

    #[test]
    fn test_load_raw_fallback() {
        let data = vec![0xAA; 256];
        let dram_base = 0x8000_0000u64;
        let load_addr = dram_base + 0x200000;
        let mut ram = vec![0u8; 0x400000];

        let result = load_kernel(&data, load_addr, &mut ram, dram_base);
        assert_eq!(result.entry, load_addr);
        assert_eq!(result.load_size, 256);
        assert_eq!(ram[0x200000], 0xAA);
    }

    #[test]
    fn test_load_riscv_image() {
        let mut data = vec![0u8; 256];
        // Set RISC-V Image header
        data[48..52].copy_from_slice(&RISCV_IMAGE_MAGIC_OLD.to_le_bytes());
        // text_offset = 0x200000
        data[8..16].copy_from_slice(&0x200000u64.to_le_bytes());
        // image_size = 256
        data[16..24].copy_from_slice(&256u64.to_le_bytes());
        // Put recognizable data
        data[64] = 0xBB;

        let dram_base = 0x8000_0000u64;
        let mut ram = vec![0u8; 0x400000];

        let result = load_kernel(&data, 0, &mut ram, dram_base);
        assert_eq!(result.entry, dram_base + 0x200000);
        assert_eq!(ram[0x200000 + 64], 0xBB);
    }

    #[test]
    fn test_load_elf64_minimal() {
        // Build a minimal ELF64 with one PT_LOAD segment
        let dram_base = 0x8000_0000u64;
        let entry = dram_base + 0x200000;
        let mut elf = vec![0u8; 256];

        // ELF header
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']); // magic
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // ELFDATA2LSB
        elf[6] = 1; // EV_CURRENT
        elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        elf[18..20].copy_from_slice(&243u16.to_le_bytes()); // EM_RISCV
        elf[24..32].copy_from_slice(&entry.to_le_bytes()); // e_entry
        elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff = 64
        elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1

        // Program header at offset 64
        let ph = &mut elf[64..120];
        ph[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        ph[8..16].copy_from_slice(&128u64.to_le_bytes()); // p_offset (file offset of data)
        ph[16..24].copy_from_slice(&entry.to_le_bytes()); // p_vaddr
        ph[24..32].copy_from_slice(&entry.to_le_bytes()); // p_paddr
        ph[32..40].copy_from_slice(&64u64.to_le_bytes()); // p_filesz
        ph[40..48].copy_from_slice(&128u64.to_le_bytes()); // p_memsz (includes BSS)

        // Payload at offset 128
        for i in 128..192 {
            elf[i] = 0xCC;
        }

        let mut ram = vec![0u8; 0x400000];
        let result = load_kernel(&elf, 0, &mut ram, dram_base);

        assert_eq!(result.entry, entry);
        assert_eq!(result.load_base, entry);
        assert_eq!(result.load_size, 128); // memsz
                                           // Check data was loaded
        assert_eq!(ram[0x200000], 0xCC);
        // Check BSS was zeroed
        assert_eq!(ram[0x200000 + 64], 0);
    }

    #[test]
    fn test_elf_non_riscv_warns() {
        // ELF64 with wrong machine type — still parses but warns, entry=0 with no segments
        let mut elf = vec![0u8; 128];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2; // ELFCLASS64
        elf[5] = 1; // LE
        elf[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        elf[24..32].copy_from_slice(&0x1000u64.to_le_bytes()); // e_entry
                                                               // No program headers → empty load

        let dram_base = 0x8000_0000u64;
        let mut ram = vec![0u8; 0x400000];
        let result = load_kernel(&elf, dram_base + 0x200000, &mut ram, dram_base);
        // Entry comes from ELF header
        assert_eq!(result.entry, 0x1000);
    }

    #[test]
    fn test_elf32_falls_back_to_raw() {
        // ELF32 is not supported → falls back to raw via load_raw inside load_elf
        let mut data = vec![0xDD; 128];
        data[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        data[4] = 1; // ELFCLASS32 — not supported

        let dram_base = 0x8000_0000u64;
        let load_addr = dram_base + 0x200000;
        let mut ram = vec![0u8; 0x400000];
        let result = load_kernel(&data, load_addr, &mut ram, dram_base);
        // Falls back to raw load at dram_base + 0x200000
        assert_eq!(result.entry, load_addr);
        // First byte: 0x7f (ELF magic), not 0xDD
        assert_eq!(ram[0x200000], 0x7f);
    }
}
