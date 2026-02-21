//! VM snapshot/restore — save and load complete machine state.
//!
//! Binary format (little-endian):
//!   Magic:    8 bytes  "MVSN0001"
//!   CPU:      32×8B regs + 32×8B fregs + 8B pc + 8B cycle + 1B mode
//!   CSRs:     4096×8B array + 4×8B pmpcfg + 16×8B pmpaddr + 8B mtime
//!   FP:       (included in fregs above)
//!   Devices:  CLINT(24B) + PLIC(variable) + UART(small) + Syscon(1B)
//!   RAM size: 8B
//!   RAM data: compressed with zlib (length-prefixed)

use std::io::{self, Write};
use std::path::Path;

pub const MAGIC: &[u8; 8] = b"MVSN0001";

/// Snapshot writer — collects state into a byte buffer
struct SnapshotWriter {
    buf: Vec<u8>,
}

impl SnapshotWriter {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(1024 * 1024),
        }
    }

    fn write_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    fn write_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    fn write_bytes(&mut self, data: &[u8]) {
        self.write_u64(data.len() as u64);
        self.buf.extend_from_slice(data);
    }
}

/// Snapshot reader — reads state from a byte buffer
struct SnapshotReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SnapshotReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        if self.pos >= self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated snapshot",
            ));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        if self.pos + 4 > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated snapshot",
            ));
        }
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        if self.pos + 8 > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated snapshot",
            ));
        }
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    fn read_bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.read_u64()? as usize;
        if self.pos + len > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated snapshot",
            ));
        }
        let data = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(data)
    }

    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        if self.pos + buf.len() > self.data.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated snapshot",
            ));
        }
        buf.copy_from_slice(&self.data[self.pos..self.pos + buf.len()]);
        self.pos += buf.len();
        Ok(())
    }
}

use crate::cpu::Cpu;
use crate::memory::Bus;

/// Save complete VM state to a file.
pub fn save_snapshot(path: &Path, cpu: &Cpu, bus: &mut Bus) -> io::Result<()> {
    let mut w = SnapshotWriter::new();

    // Magic
    w.buf.extend_from_slice(MAGIC);

    // CPU registers
    for &r in &cpu.regs {
        w.write_u64(r);
    }
    for &f in &cpu.fregs {
        w.write_u64(f);
    }
    w.write_u64(cpu.pc);
    w.write_u64(cpu.cycle);
    w.write_u8(cpu.mode as u8);
    w.write_u8(if cpu.wfi { 1 } else { 0 });
    // Reservation
    match cpu.reservation {
        Some(addr) => {
            w.write_u8(1);
            w.write_u64(addr);
        }
        None => {
            w.write_u8(0);
        }
    }

    // CSR file: dump all 4096 entries
    for addr in 0..4096u16 {
        w.write_u64(cpu.csrs.read_raw(addr));
    }
    // PMP state
    for &cfg in &cpu.csrs.pmpcfg {
        w.write_u64(cfg);
    }
    for &addr in &cpu.csrs.pmpaddr {
        w.write_u64(addr);
    }
    w.write_u64(cpu.csrs.mtime);

    // CLINT state
    w.write_u64(bus.clint.mtime());
    w.write_u64(bus.clint.mtimecmp());
    w.write_u32(if bus.clint.software_interrupt() { 1 } else { 0 });

    // PLIC state (priority + pending + enable + threshold + claim)
    let plic_state = bus.plic.save_state();
    w.write_bytes(&plic_state);

    // UART state
    let uart_state = bus.uart.save_state();
    w.write_bytes(&uart_state);

    // Syscon — no meaningful state to save

    // RAM
    let ram_data = bus.ram.as_slice();
    w.write_u64(ram_data.len() as u64);

    // Compress RAM with simple RLE for zero pages (most RAM is zeroed)
    let compressed = compress_ram(ram_data);
    w.write_bytes(&compressed);

    // Write to file
    let mut file = std::fs::File::create(path)?;
    file.write_all(&w.buf)?;

    log::info!(
        "Snapshot saved to {} ({:.1} MiB, RAM {:.1} MiB → {:.1} MiB compressed)",
        path.display(),
        w.buf.len() as f64 / 1024.0 / 1024.0,
        ram_data.len() as f64 / 1024.0 / 1024.0,
        compressed.len() as f64 / 1024.0 / 1024.0,
    );

    Ok(())
}

/// Load VM state from a snapshot file.
/// Returns the required RAM size so the caller can verify it matches.
pub fn load_snapshot(path: &Path, cpu: &mut Cpu, bus: &mut Bus) -> io::Result<()> {
    let data = std::fs::read(path)?;
    let mut r = SnapshotReader::new(&data);

    // Magic
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "invalid snapshot magic: expected {:?}, got {:?}",
                MAGIC,
                std::str::from_utf8(&magic).unwrap_or("???")
            ),
        ));
    }

    // CPU registers
    for i in 0..32 {
        cpu.regs[i] = r.read_u64()?;
    }
    for i in 0..32 {
        cpu.fregs[i] = r.read_u64()?;
    }
    cpu.pc = r.read_u64()?;
    cpu.cycle = r.read_u64()?;
    cpu.mode = crate::cpu::PrivilegeMode::from_u64(r.read_u8()? as u64);
    cpu.wfi = r.read_u8()? != 0;
    // Reservation
    let has_reservation = r.read_u8()?;
    cpu.reservation = if has_reservation != 0 {
        Some(r.read_u64()?)
    } else {
        None
    };

    // CSR file
    for addr in 0..4096u16 {
        let val = r.read_u64()?;
        cpu.csrs.write_raw(addr, val);
    }
    for i in 0..4 {
        cpu.csrs.pmpcfg[i] = r.read_u64()?;
    }
    for i in 0..16 {
        cpu.csrs.pmpaddr[i] = r.read_u64()?;
    }
    cpu.csrs.mtime = r.read_u64()?;

    // Flush TLB after restoring CSRs (SATP may have changed)
    cpu.mmu.flush_tlb();

    // CLINT state
    let mtime = r.read_u64()?;
    let mtimecmp = r.read_u64()?;
    let msip = r.read_u32()?;
    bus.clint.restore_state(mtime, mtimecmp, msip != 0);

    // PLIC state
    let plic_data = r.read_bytes()?;
    bus.plic.restore_state(&plic_data)?;

    // UART state
    let uart_data = r.read_bytes()?;
    bus.uart.restore_state(&uart_data)?;

    // RAM
    let ram_size = r.read_u64()? as usize;
    if ram_size != bus.ram.as_slice().len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "RAM size mismatch: snapshot has {} MiB, VM has {} MiB",
                ram_size / 1024 / 1024,
                bus.ram.as_slice().len() / 1024 / 1024,
            ),
        ));
    }

    let compressed = r.read_bytes()?;
    let decompressed = decompress_ram(&compressed, ram_size)?;
    bus.ram.as_mut_slice().copy_from_slice(&decompressed);

    log::info!(
        "Snapshot restored from {} (PC={:#x}, mode={:?}, cycle={})",
        path.display(),
        cpu.pc,
        cpu.mode,
        cpu.cycle,
    );

    Ok(())
}

/// Simple RAM compression: page-level RLE for zero pages.
/// Format: for each 4KiB page:
///   0x00 = zero page (no data follows)
///   0x01 = non-zero page (4096 bytes follow)
fn compress_ram(data: &[u8]) -> Vec<u8> {
    const PAGE_SIZE: usize = 4096;
    let num_pages = data.len().div_ceil(PAGE_SIZE);
    // Estimate: worst case = data.len() + num_pages
    let mut out = Vec::with_capacity(data.len() / 4); // Assume mostly zero

    for i in 0..num_pages {
        let start = i * PAGE_SIZE;
        let end = std::cmp::min(start + PAGE_SIZE, data.len());
        let page = &data[start..end];

        if page.iter().all(|&b| b == 0) {
            out.push(0x00);
        } else {
            out.push(0x01);
            out.extend_from_slice(page);
        }
    }

    out
}

/// Decompress RAM from page-level RLE format.
fn decompress_ram(compressed: &[u8], expected_size: usize) -> io::Result<Vec<u8>> {
    const PAGE_SIZE: usize = 4096;
    let mut out = vec![0u8; expected_size];
    let mut pos = 0;
    let mut page_idx = 0;

    while pos < compressed.len() && page_idx * PAGE_SIZE < expected_size {
        let tag = compressed[pos];
        pos += 1;
        let page_start = page_idx * PAGE_SIZE;

        match tag {
            0x00 => {
                // Zero page — already zeroed in output
            }
            0x01 => {
                let page_end = std::cmp::min(page_start + PAGE_SIZE, expected_size);
                let page_len = page_end - page_start;
                if pos + page_len > compressed.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated compressed RAM data",
                    ));
                }
                out[page_start..page_end].copy_from_slice(&compressed[pos..pos + page_len]);
                pos += page_len;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid page tag: {:#x}", tag),
                ));
            }
        }

        page_idx += 1;
    }

    Ok(out)
}

/// ABI register names for RISC-V
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

/// Named CSRs worth displaying
const NAMED_CSRS: &[(u16, &str)] = &[
    (0x300, "mstatus"),
    (0x301, "misa"),
    (0x302, "medeleg"),
    (0x303, "mideleg"),
    (0x304, "mie"),
    (0x305, "mtvec"),
    (0x306, "mcounteren"),
    (0x320, "mcountinhibit"),
    (0x340, "mscratch"),
    (0x341, "mepc"),
    (0x342, "mcause"),
    (0x343, "mtval"),
    (0x344, "mip"),
    (0x30A, "menvcfg"),
    (0x3A0, "pmpcfg0"),
    (0x3A2, "pmpcfg2"),
    (0xF11, "mvendorid"),
    (0xF12, "marchid"),
    (0xF13, "mimpid"),
    (0xF14, "mhartid"),
    (0x100, "sstatus"),
    (0x104, "sie"),
    (0x105, "stvec"),
    (0x106, "scounteren"),
    (0x140, "sscratch"),
    (0x141, "sepc"),
    (0x142, "scause"),
    (0x143, "stval"),
    (0x144, "sip"),
    (0x180, "satp"),
    (0x10A, "senvcfg"),
    (0x14D, "stimecmp"),
    (0xB00, "mcycle"),
    (0xB02, "minstret"),
];

/// Inspect a snapshot file and print human-readable state.
pub fn inspect_snapshot(
    path: &Path,
    all_regs: bool,
    show_fpregs: bool,
    show_all_csrs: bool,
    disasm_count: Option<u64>,
) {
    let data = match std::fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read snapshot: {}", e);
            std::process::exit(1);
        }
    };

    let mut r = SnapshotReader::new(&data);

    // Magic
    let mut magic = [0u8; 8];
    if r.read_exact(&mut magic).is_err() || &magic != MAGIC {
        eprintln!(
            "Invalid snapshot file (bad magic: {:?})",
            std::str::from_utf8(&magic).unwrap_or("???")
        );
        std::process::exit(1);
    }

    // CPU registers
    let mut regs = [0u64; 32];
    for reg in &mut regs {
        *reg = r.read_u64().unwrap();
    }
    let mut fregs = [0u64; 32];
    for freg in &mut fregs {
        *freg = r.read_u64().unwrap();
    }
    let pc = r.read_u64().unwrap();
    let cycle = r.read_u64().unwrap();
    let mode_byte = r.read_u8().unwrap();
    let wfi = r.read_u8().unwrap() != 0;
    let has_reservation = r.read_u8().unwrap();
    let reservation = if has_reservation != 0 {
        Some(r.read_u64().unwrap())
    } else {
        None
    };

    // CSR file
    let mut csr_values = [0u64; 4096];
    for val in &mut csr_values {
        *val = r.read_u64().unwrap();
    }
    let mut pmpcfg = [0u64; 4];
    for cfg in &mut pmpcfg {
        *cfg = r.read_u64().unwrap();
    }
    let mut pmpaddr = [0u64; 16];
    for addr in &mut pmpaddr {
        *addr = r.read_u64().unwrap();
    }
    let mtime = r.read_u64().unwrap();

    // CLINT
    let clint_mtime = r.read_u64().unwrap();
    let clint_mtimecmp = r.read_u64().unwrap();
    let clint_msip = r.read_u32().unwrap();

    // PLIC
    let plic_data = r.read_bytes().unwrap();

    // UART
    let uart_data = r.read_bytes().unwrap();

    // RAM
    let ram_size = r.read_u64().unwrap() as usize;
    let compressed = r.read_bytes().unwrap();

    let mode_name = match mode_byte {
        0 => "User",
        1 => "Supervisor",
        3 => "Machine",
        _ => "Unknown",
    };

    // File info
    println!("╔══════════════════════════════════════════════════════════╗");
    println!(
        "║  microvm snapshot: {}",
        path.file_name().unwrap_or_default().to_string_lossy()
    );
    println!("╚══════════════════════════════════════════════════════════╝");
    println!();
    println!(
        "  File size:    {:.1} KiB ({} bytes)",
        data.len() as f64 / 1024.0,
        data.len()
    );
    println!(
        "  RAM:          {} MiB (compressed: {:.1} KiB, ratio: {:.1}x)",
        ram_size / 1024 / 1024,
        compressed.len() as f64 / 1024.0,
        ram_size as f64 / compressed.len().max(1) as f64,
    );
    println!();

    // CPU state
    println!("── CPU ──────────────────────────────────────────────────");
    println!("  PC:           {:#018x}", pc);
    println!("  Mode:         {} ({})", mode_name, mode_byte);
    println!("  Cycle:        {} ({:.1}M)", cycle, cycle as f64 / 1e6);
    println!("  WFI:          {}", wfi);
    if let Some(addr) = reservation {
        println!("  LR/SC rsv:    {:#018x}", addr);
    }
    println!();

    // General-purpose registers
    println!("── Registers ───────────────────────────────────────────");
    for i in 0..32 {
        if all_regs || regs[i] != 0 {
            println!(
                "  x{:<2} ({:<4}) = {:#018x}  ({})",
                i, REG_NAMES[i], regs[i], regs[i] as i64
            );
        }
    }
    println!();

    // Floating-point registers
    if show_fpregs {
        println!("── FP Registers ────────────────────────────────────────");
        for i in 0..32 {
            if all_regs || fregs[i] != 0 {
                let f = f64::from_bits(fregs[i]);
                println!(
                    "  f{:<2} ({:<5}) = {:#018x}  ({})",
                    i, FREG_NAMES[i], fregs[i], f
                );
            }
        }
        println!();
    }

    // CSRs
    println!("── Key CSRs ────────────────────────────────────────────");
    for &(addr, name) in NAMED_CSRS {
        let val = csr_values[addr as usize];
        if val != 0 || show_all_csrs {
            println!("  {:<16} ({:#05x}) = {:#018x}", name, addr, val);
        }
    }

    // SATP decoding
    let satp = csr_values[0x180];
    if satp != 0 {
        let satp_mode = satp >> 60;
        let asid = (satp >> 44) & 0xFFFF;
        let ppn = satp & ((1u64 << 44) - 1);
        let mode_str = match satp_mode {
            0 => "Bare",
            8 => "Sv39",
            9 => "Sv48",
            10 => "Sv57",
            _ => "Unknown",
        };
        println!(
            "    → {} (ASID={}, PPN={:#x}, root={:#x})",
            mode_str,
            asid,
            ppn,
            ppn << 12
        );
    }

    // mstatus decoding
    let mstatus = csr_values[0x300];
    if mstatus != 0 {
        let sie = (mstatus >> 1) & 1;
        let mie = (mstatus >> 3) & 1;
        let spie = (mstatus >> 5) & 1;
        let mpie = (mstatus >> 7) & 1;
        let spp = (mstatus >> 8) & 1;
        let mpp = (mstatus >> 11) & 3;
        let fs = (mstatus >> 13) & 3;
        let sum = (mstatus >> 18) & 1;
        let mxr = (mstatus >> 19) & 1;
        let fs_str = match fs {
            0 => "Off",
            1 => "Initial",
            2 => "Clean",
            3 => "Dirty",
            _ => "?",
        };
        println!(
            "    → SIE={} MIE={} SPIE={} MPIE={} SPP={} MPP={} FS={} ({}) SUM={} MXR={}",
            sie, mie, spie, mpie, spp, mpp, fs, fs_str, sum, mxr
        );
    }

    if show_all_csrs {
        println!();
        println!("── All Non-Zero CSRs ───────────────────────────────────");
        for addr in 0..4096u16 {
            let val = csr_values[addr as usize];
            if val != 0 {
                // Skip already-shown named CSRs
                if NAMED_CSRS.iter().any(|&(a, _)| a == addr) {
                    continue;
                }
                println!("  CSR {:#05x} = {:#018x}", addr, val);
            }
        }
    }
    println!();

    // PMP
    let any_pmp = pmpcfg.iter().any(|&v| v != 0) || pmpaddr.iter().any(|&v| v != 0);
    if any_pmp {
        println!("── PMP ─────────────────────────────────────────────────");
        for (i, &addr_val) in pmpaddr.iter().enumerate() {
            let cfg_reg = i / 8;
            let cfg_byte = (pmpcfg[cfg_reg] >> ((i % 8) * 8)) as u8;
            let a_field = (cfg_byte >> 3) & 3;
            if a_field != 0 || addr_val != 0 {
                let locked = if cfg_byte & 0x80 != 0 { "L" } else { " " };
                let r = if cfg_byte & 0x01 != 0 { "R" } else { "-" };
                let w = if cfg_byte & 0x02 != 0 { "W" } else { "-" };
                let x = if cfg_byte & 0x04 != 0 { "X" } else { "-" };
                let a_str = match a_field {
                    0 => "OFF  ",
                    1 => "TOR  ",
                    2 => "NA4  ",
                    3 => "NAPOT",
                    _ => "?    ",
                };
                println!(
                    "  pmp{:<2}: {} {}{}{} {} addr={:#018x}",
                    i, a_str, r, w, x, locked, addr_val
                );
            }
        }
        println!();
    }

    // Devices
    println!("── Devices ─────────────────────────────────────────────");
    println!(
        "  CLINT: mtime={} mtimecmp={} msip={}",
        clint_mtime, clint_mtimecmp, clint_msip
    );
    let timer_pending = clint_mtime >= clint_mtimecmp;
    println!(
        "    → timer {}",
        if timer_pending { "PENDING" } else { "idle" }
    );
    println!("  PLIC:  {} bytes state", plic_data.len());
    println!("  UART:  {} bytes state", uart_data.len());
    println!();

    // RAM analysis
    println!("── RAM Analysis ────────────────────────────────────────");
    let decompressed = decompress_ram(&compressed, ram_size).unwrap();
    let page_size = 4096usize;
    let total_pages = ram_size / page_size;
    let zero_pages = decompressed
        .chunks(page_size)
        .filter(|p| p.iter().all(|&b| b == 0))
        .count();
    let used_pages = total_pages - zero_pages;
    println!(
        "  Total:    {} pages ({} MiB)",
        total_pages,
        ram_size / 1024 / 1024
    );
    println!(
        "  Used:     {} pages ({:.1} MiB, {:.1}%)",
        used_pages,
        used_pages as f64 * 4.0 / 1024.0,
        used_pages as f64 / total_pages as f64 * 100.0
    );
    println!(
        "  Free:     {} pages ({:.1} MiB)",
        zero_pages,
        zero_pages as f64 * 4.0 / 1024.0
    );

    // Disassemble at PC
    if let Some(count) = disasm_count {
        let count = count.min(100); // Cap at 100
        println!();
        println!(
            "── Disassembly at PC={:#x} ─────────────────────────────",
            pc
        );

        // Translate PC through page table if SATP is set
        let phys_pc = if satp >> 60 != 0 {
            // We'd need full MMU translation — for now just try direct mapping
            // Check if PC is in the DRAM range
            pc // Simplified: user should use physical addresses in snapshot
        } else {
            pc
        };

        let dram_base = crate::memory::DRAM_BASE;
        if phys_pc >= dram_base && phys_pc < dram_base + ram_size as u64 {
            let mut addr = phys_pc;
            for _ in 0..count {
                let offset = (addr - dram_base) as usize;
                if offset + 4 > ram_size {
                    break;
                }
                let raw16 = u16::from_le_bytes([decompressed[offset], decompressed[offset + 1]]);
                let (inst, size) = if raw16 & 0x03 != 0x03 {
                    // Compressed
                    let expanded = crate::cpu::decode::expand_compressed(raw16 as u32);
                    (expanded, 2u64)
                } else {
                    let raw32 = u32::from_le_bytes([
                        decompressed[offset],
                        decompressed[offset + 1],
                        decompressed[offset + 2],
                        decompressed[offset + 3],
                    ]);
                    (raw32, 4u64)
                };
                let disasm_str = crate::cpu::disasm::disassemble(inst, addr);
                if size == 2 {
                    println!("  {:#010x}:  {:04x}       {}", addr, raw16, disasm_str);
                } else {
                    println!("  {:#010x}:  {:08x}   {}", addr, inst, disasm_str);
                }
                addr += size;
            }
        } else {
            println!(
                "  PC {:#x} is outside DRAM range ({:#x}..)",
                phys_pc, dram_base
            );
        }
    }

    println!();
    println!("  mtime: {}", mtime);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compress_decompress_zeros() {
        let data = vec![0u8; 8192]; // 2 zero pages
        let compressed = compress_ram(&data);
        assert_eq!(compressed.len(), 2); // Just 2 tags
        let decompressed = decompress_ram(&compressed, 8192).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compress_decompress_mixed() {
        let mut data = vec![0u8; 8192]; // 2 pages
        data[0] = 0x42; // First page non-zero
        let compressed = compress_ram(&data);
        assert_eq!(compressed.len(), 1 + 4096 + 1); // tag+data + tag
        let decompressed = decompress_ram(&compressed, 8192).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_snapshot_roundtrip_and_inspect() {
        // Create a VM, save snapshot, then verify inspect can parse it
        use crate::cpu::Cpu;
        use crate::memory::Bus;
        let mut cpu = Cpu::new();
        cpu.pc = 0x8020_0000;
        cpu.regs[1] = 0xDEAD_BEEF; // ra
        cpu.regs[2] = 0x8080_0000; // sp
        cpu.cycle = 42_000;
        let mut bus = Bus::new(4 * 1024 * 1024); // 4 MiB
                                                 // Write some data to RAM
        bus.write32(crate::memory::DRAM_BASE, 0x0000_0013); // nop (addi x0,x0,0)

        let tmp = std::env::temp_dir().join("microvm_test_inspect.snap");
        save_snapshot(&tmp, &cpu, &mut bus).unwrap();

        // Verify we can load it back
        let mut cpu2 = Cpu::new();
        let mut bus2 = Bus::new(4 * 1024 * 1024);
        load_snapshot(&tmp, &mut cpu2, &mut bus2).unwrap();
        assert_eq!(cpu2.pc, 0x8020_0000);
        assert_eq!(cpu2.regs[1], 0xDEAD_BEEF);
        assert_eq!(cpu2.regs[2], 0x8080_0000);
        assert_eq!(cpu2.cycle, 42_000);

        // Verify inspect doesn't panic (just exercise the code path)
        inspect_snapshot(&tmp, true, true, true, Some(4));

        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_compress_decompress_all_nonzero() {
        let data: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
        let compressed = compress_ram(&data);
        let decompressed = decompress_ram(&compressed, 4096).unwrap();
        assert_eq!(decompressed, data);
    }
}
