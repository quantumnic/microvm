//! Execution profiler — collects instruction and runtime statistics.
//!
//! Enable with `--profile` to get a detailed summary at the end of execution:
//! - Instruction opcode distribution (top instructions by frequency)
//! - Hottest PCs (where the CPU spends the most time)
//! - Privilege mode distribution (M/S/U time)
//! - Exception and interrupt counters
//! - SBI call statistics

use std::collections::HashMap;

/// Profiling data collected during execution.
pub struct Profile {
    /// Instruction mnemonic → count
    opcodes: HashMap<&'static str, u64>,
    /// PC → count (only tracks top entries via sampling)
    hot_pcs: HashMap<u64, u64>,
    /// Instructions per privilege mode: [M, S, U]
    mode_counts: [u64; 3],
    /// Exception cause → count (trap handler entries)
    exceptions: HashMap<u64, u64>,
    /// Interrupt cause → count
    interrupts: HashMap<u64, u64>,
    /// SBI extension ID → (call count, HashMap<fid, count>)
    sbi_calls: HashMap<u64, (u64, HashMap<u64, u64>)>,
    /// Total instructions profiled
    total: u64,
    /// Memory access counts: [loads, stores]
    mem_accesses: [u64; 2],
    /// Branch/jump counts: [taken, not_taken]
    branches: [u64; 2],
}

impl Default for Profile {
    fn default() -> Self {
        Self::new()
    }
}

impl Profile {
    pub fn new() -> Self {
        Self {
            opcodes: HashMap::new(),
            hot_pcs: HashMap::new(),
            mode_counts: [0; 3],
            exceptions: HashMap::new(),
            interrupts: HashMap::new(),
            sbi_calls: HashMap::new(),
            total: 0,
            mem_accesses: [0; 2],
            branches: [0; 2],
        }
    }

    /// Record an instruction execution.
    #[inline]
    pub fn record_insn(&mut self, pc: u64, mnemonic: &'static str, mode: u8) {
        self.total += 1;
        *self.opcodes.entry(mnemonic).or_insert(0) += 1;
        *self.hot_pcs.entry(pc).or_insert(0) += 1;
        if (mode as usize) < 3 {
            self.mode_counts[mode as usize] += 1;
        }

        // Prune hot_pcs if too large (keep memory bounded)
        if self.hot_pcs.len() > 100_000 {
            self.prune_hot_pcs();
        }
    }

    /// Record a memory load.
    #[inline]
    pub fn record_load(&mut self) {
        self.mem_accesses[0] += 1;
    }

    /// Record a memory store.
    #[inline]
    pub fn record_store(&mut self) {
        self.mem_accesses[1] += 1;
    }

    /// Record a branch (taken or not taken).
    #[inline]
    pub fn record_branch(&mut self, taken: bool) {
        if taken {
            self.branches[0] += 1;
        } else {
            self.branches[1] += 1;
        }
    }

    /// Record a trap (exception or interrupt).
    pub fn record_trap(&mut self, cause: u64, is_interrupt: bool) {
        if is_interrupt {
            *self
                .interrupts
                .entry(cause & 0x7FFF_FFFF_FFFF_FFFF)
                .or_insert(0) += 1;
        } else {
            *self.exceptions.entry(cause).or_insert(0) += 1;
        }
    }

    /// Record an SBI call.
    pub fn record_sbi(&mut self, eid: u64, fid: u64) {
        let entry = self
            .sbi_calls
            .entry(eid)
            .or_insert_with(|| (0, HashMap::new()));
        entry.0 += 1;
        *entry.1.entry(fid).or_insert(0) += 1;
    }

    fn prune_hot_pcs(&mut self) {
        // Keep only the top 10000 entries by count
        let mut entries: Vec<_> = self.hot_pcs.drain().collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1));
        entries.truncate(10_000);
        self.hot_pcs = entries.into_iter().collect();
    }

    /// Print the profiling summary to stderr.
    pub fn print_summary(&self) {
        eprintln!();
        eprintln!("╔══════════════════════════════════════════════════════════════╗");
        eprintln!("║                    EXECUTION PROFILE                        ║");
        eprintln!("╚══════════════════════════════════════════════════════════════╝");
        eprintln!();

        // Total instructions
        eprintln!("Total instructions: {}", format_count(self.total));
        eprintln!();

        // Privilege mode distribution
        eprintln!("── Privilege Mode Distribution ──────────────────────────────");
        let mode_names = ["Machine (M)", "Supervisor (S)", "User (U)"];
        for (i, name) in mode_names.iter().enumerate() {
            let count = self.mode_counts[i];
            if count > 0 {
                let pct = count as f64 / self.total as f64 * 100.0;
                eprintln!(
                    "  {:16} {:>12}  ({:5.1}%)  {}",
                    name,
                    format_count(count),
                    pct,
                    bar(pct)
                );
            }
        }
        eprintln!();

        // Memory access stats
        let loads = self.mem_accesses[0];
        let stores = self.mem_accesses[1];
        if loads > 0 || stores > 0 {
            eprintln!("── Memory Accesses ─────────────────────────────────────────");
            eprintln!(
                "  Loads:  {:>12}  ({:.1}% of insns)",
                format_count(loads),
                loads as f64 / self.total as f64 * 100.0
            );
            eprintln!(
                "  Stores: {:>12}  ({:.1}% of insns)",
                format_count(stores),
                stores as f64 / self.total as f64 * 100.0
            );
            eprintln!();
        }

        // Branch stats
        let taken = self.branches[0];
        let not_taken = self.branches[1];
        if taken > 0 || not_taken > 0 {
            let total_br = taken + not_taken;
            eprintln!("── Branches ────────────────────────────────────────────────");
            eprintln!("  Total:     {:>12}", format_count(total_br));
            eprintln!(
                "  Taken:     {:>12}  ({:.1}%)",
                format_count(taken),
                taken as f64 / total_br as f64 * 100.0
            );
            eprintln!(
                "  Not taken: {:>12}  ({:.1}%)",
                format_count(not_taken),
                not_taken as f64 / total_br as f64 * 100.0
            );
            eprintln!();
        }

        // Top instructions
        eprintln!("── Top 20 Instructions ─────────────────────────────────────");
        let mut sorted_ops: Vec<_> = self.opcodes.iter().collect();
        sorted_ops.sort_by(|a, b| b.1.cmp(a.1));
        for (i, (name, count)) in sorted_ops.iter().take(20).enumerate() {
            let pct = **count as f64 / self.total as f64 * 100.0;
            eprintln!(
                "  {:2}. {:<12} {:>12}  ({:5.1}%)  {}",
                i + 1,
                name,
                format_count(**count),
                pct,
                bar(pct)
            );
        }
        if sorted_ops.len() > 20 {
            let rest: u64 = sorted_ops[20..].iter().map(|(_, c)| **c).sum();
            eprintln!(
                "      ... +{} more  {:>12}",
                sorted_ops.len() - 20,
                format_count(rest)
            );
        }
        eprintln!();

        // Hottest PCs
        eprintln!("── Hottest 15 PCs ──────────────────────────────────────────");
        let mut sorted_pcs: Vec<_> = self.hot_pcs.iter().collect();
        sorted_pcs.sort_by(|a, b| b.1.cmp(a.1));
        for (i, (pc, count)) in sorted_pcs.iter().take(15).enumerate() {
            let pct = **count as f64 / self.total as f64 * 100.0;
            eprintln!(
                "  {:2}. {:#014x}  {:>12}  ({:5.1}%)",
                i + 1,
                pc,
                format_count(**count),
                pct
            );
        }
        eprintln!();

        // Exceptions
        if !self.exceptions.is_empty() {
            eprintln!("── Exceptions ──────────────────────────────────────────────");
            let mut sorted: Vec<_> = self.exceptions.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (cause, count) in &sorted {
                eprintln!(
                    "  cause {:2} ({:<24}) {:>10}",
                    cause,
                    exception_name(**cause),
                    format_count(**count)
                );
            }
            eprintln!();
        }

        // Interrupts
        if !self.interrupts.is_empty() {
            eprintln!("── Interrupts ──────────────────────────────────────────────");
            let mut sorted: Vec<_> = self.interrupts.iter().collect();
            sorted.sort_by(|a, b| b.1.cmp(a.1));
            for (cause, count) in &sorted {
                eprintln!(
                    "  cause {:2} ({:<24}) {:>10}",
                    cause,
                    interrupt_name(**cause),
                    format_count(**count)
                );
            }
            eprintln!();
        }

        // SBI calls
        if !self.sbi_calls.is_empty() {
            eprintln!("── SBI Calls ───────────────────────────────────────────────");
            let mut sorted: Vec<_> = self.sbi_calls.iter().collect();
            sorted.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
            for (eid, (total, fids)) in &sorted {
                eprintln!(
                    "  EID {:#x} ({:<12}) {:>8} calls",
                    eid,
                    sbi_ext_name(**eid),
                    format_count(*total)
                );
                let mut sorted_fids: Vec<_> = fids.iter().collect();
                sorted_fids.sort_by(|a, b| b.1.cmp(a.1));
                for (fid, count) in sorted_fids.iter().take(5) {
                    eprintln!("    fid {:2}: {:>8}", fid, format_count(**count));
                }
            }
            eprintln!();
        }
    }
}

fn format_count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.1}G", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 10_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{}", n)
    }
}

fn bar(pct: f64) -> String {
    let blocks = (pct / 2.0).round() as usize;
    "█".repeat(blocks.min(40))
}

fn exception_name(cause: u64) -> &'static str {
    match cause {
        0 => "misaligned fetch",
        1 => "fetch access fault",
        2 => "illegal instruction",
        3 => "breakpoint",
        4 => "misaligned load",
        5 => "load access fault",
        6 => "misaligned store",
        7 => "store access fault",
        8 => "ecall from U-mode",
        9 => "ecall from S-mode",
        11 => "ecall from M-mode",
        12 => "instruction page fault",
        13 => "load page fault",
        15 => "store page fault",
        _ => "unknown",
    }
}

fn interrupt_name(cause: u64) -> &'static str {
    match cause {
        1 => "S-mode software",
        3 => "M-mode software",
        5 => "S-mode timer",
        7 => "M-mode timer",
        9 => "S-mode external",
        11 => "M-mode external",
        _ => "unknown",
    }
}

fn sbi_ext_name(eid: u64) -> &'static str {
    match eid {
        0x00..=0x0F => "legacy",
        0x10 => "BASE",
        0x48534D => "HSM",
        0x535253 => "SRST",
        0x504D55 => "PMU",
        0x54494D45 => "TIME",
        0x735049 => "sPI",
        0x52464E43 => "RFENCE",
        0x4442434E => "DBCN",
        0x535553 => "SUSP",
        0x4E41434C => "NACL",
        0x535441 => "STA",
        0x43505043 => "CPPC",
        0x46574654 => "FWFT",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_record_and_counts() {
        let mut p = Profile::new();
        p.record_insn(0x8000_0000, "addi", 1); // S-mode
        p.record_insn(0x8000_0000, "addi", 1);
        p.record_insn(0x8000_0004, "sd", 1);
        p.record_insn(0x8000_0008, "beq", 0); // M-mode

        assert_eq!(p.total, 4);
        assert_eq!(p.opcodes["addi"], 2);
        assert_eq!(p.opcodes["sd"], 1);
        assert_eq!(p.opcodes["beq"], 1);
        assert_eq!(p.hot_pcs[&0x8000_0000], 2);
        assert_eq!(p.mode_counts[0], 1); // M
        assert_eq!(p.mode_counts[1], 3); // S
    }

    #[test]
    fn test_profile_memory_stats() {
        let mut p = Profile::new();
        p.record_load();
        p.record_load();
        p.record_store();
        assert_eq!(p.mem_accesses[0], 2);
        assert_eq!(p.mem_accesses[1], 1);
    }

    #[test]
    fn test_profile_branch_stats() {
        let mut p = Profile::new();
        p.record_branch(true);
        p.record_branch(true);
        p.record_branch(false);
        assert_eq!(p.branches[0], 2); // taken
        assert_eq!(p.branches[1], 1); // not taken
    }

    #[test]
    fn test_profile_traps() {
        let mut p = Profile::new();
        p.record_trap(8, false); // ecall from U
        p.record_trap(8, false);
        p.record_trap(5 | (1u64 << 63), true); // S-mode timer interrupt
        assert_eq!(p.exceptions[&8], 2);
        assert_eq!(p.interrupts[&5], 1);
    }

    #[test]
    fn test_profile_sbi() {
        let mut p = Profile::new();
        p.record_sbi(0x10, 0); // BASE, get_spec_version
        p.record_sbi(0x10, 3); // BASE, probe_extension
        p.record_sbi(0x10, 3);
        p.record_sbi(0x54494D45, 0); // TIME, set_timer

        assert_eq!(p.sbi_calls[&0x10].0, 3);
        assert_eq!(p.sbi_calls[&0x10].1[&3], 2);
        assert_eq!(p.sbi_calls[&0x54494D45].0, 1);
    }

    #[test]
    fn test_profile_prune() {
        let mut p = Profile::new();
        // Add many unique PCs
        for i in 0..200_000u64 {
            p.record_insn(i, "nop", 0);
        }
        // After pruning, should have at most 100_001 (100k + buffer before next prune)
        // The prune threshold is 100_000
        assert!(p.hot_pcs.len() <= 110_001);
    }

    #[test]
    fn test_format_count() {
        assert_eq!(format_count(42), "42");
        assert_eq!(format_count(12345), "12.3K");
        assert_eq!(format_count(1_500_000), "1.5M");
        assert_eq!(format_count(2_300_000_000), "2.3G");
    }

    #[test]
    fn test_bar() {
        assert_eq!(bar(0.0), "");
        assert_eq!(bar(10.0), "█████");
        assert_eq!(bar(100.0), "████████████████████████████████████████");
    }

    #[test]
    fn test_exception_names() {
        assert_eq!(exception_name(2), "illegal instruction");
        assert_eq!(exception_name(13), "load page fault");
        assert_eq!(exception_name(99), "unknown");
    }

    #[test]
    fn test_interrupt_names() {
        assert_eq!(interrupt_name(5), "S-mode timer");
        assert_eq!(interrupt_name(9), "S-mode external");
        assert_eq!(interrupt_name(99), "unknown");
    }
}
