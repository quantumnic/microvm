/// Interactive debug monitor (QEMU-style Ctrl-A escape sequences)
///
/// Ctrl-A h — help
/// Ctrl-A x — quit emulator
/// Ctrl-A c — toggle monitor console
/// Ctrl-A a — send literal Ctrl-A to guest
///
/// Monitor commands:
///   info regs      — show general-purpose registers
///   info fregs     — show floating-point registers
///   info csrs      — show key CSRs
///   info mem       — show memory map summary
///   x <addr> [n]   — examine N words at physical address (hex)
///   disasm [n]     — disassemble N instructions at PC (physical)
///   pc             — show program counter
///   help           — list commands
///   quit / q       — exit emulator
use crate::cpu::Cpu;
use crate::cpu::PrivilegeMode;
use crate::memory::{Bus, DRAM_BASE};

/// Monitor state tracks Ctrl-A escape handling and console mode.
pub struct Monitor {
    /// True when we're in monitor console mode (not forwarding to guest)
    pub in_monitor: bool,
    /// True when we saw a Ctrl-A and are waiting for the next char
    escape_pending: bool,
    /// Line buffer for monitor commands
    line_buf: String,
    /// If set, the VM should exit
    pub quit_requested: bool,
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Monitor {
    pub fn new() -> Self {
        Self {
            in_monitor: false,
            escape_pending: false,
            line_buf: String::new(),
            quit_requested: false,
        }
    }

    /// Process a byte from stdin. Returns Some(byte) if it should be forwarded to the guest UART.
    pub fn process_byte(&mut self, byte: u8, cpu: &Cpu, bus: &mut Bus) -> Option<u8> {
        if self.escape_pending {
            self.escape_pending = false;
            match byte {
                b'h' | b'H' | b'?' => {
                    self.print_escape_help();
                    return None;
                }
                b'x' | b'X' => {
                    eprintln!("\r\n[monitor] Quit");
                    self.quit_requested = true;
                    return None;
                }
                b'c' | b'C' => {
                    self.in_monitor = !self.in_monitor;
                    if self.in_monitor {
                        eprintln!("\r\n[monitor] Entering monitor console (Ctrl-A c to return)");
                        eprint!("(monitor) ");
                    } else {
                        eprintln!("\r\n[monitor] Returning to guest console");
                    }
                    return None;
                }
                b'a' | b'A' => {
                    // Send literal Ctrl-A to guest
                    return Some(0x01);
                }
                _ => {
                    // Unknown escape — ignore
                    return None;
                }
            }
        }

        // Ctrl-A starts escape sequence
        if byte == 0x01 {
            self.escape_pending = true;
            return None;
        }

        // If in monitor mode, handle as command input
        if self.in_monitor {
            self.handle_monitor_input(byte, cpu, bus);
            return None;
        }

        // Otherwise forward to guest
        Some(byte)
    }

    fn handle_monitor_input(&mut self, byte: u8, cpu: &Cpu, bus: &mut Bus) {
        match byte {
            b'\r' | b'\n' => {
                eprintln!();
                let cmd = self.line_buf.trim().to_string();
                self.line_buf.clear();
                if !cmd.is_empty() {
                    self.execute_command(&cmd, cpu, bus);
                }
                if self.in_monitor && !self.quit_requested {
                    eprint!("(monitor) ");
                }
            }
            0x7F | 0x08 => {
                // Backspace
                if self.line_buf.pop().is_some() {
                    eprint!("\x08 \x08");
                }
            }
            0x03 => {
                // Ctrl-C — clear line
                self.line_buf.clear();
                eprintln!("^C");
                eprint!("(monitor) ");
            }
            b if b >= 0x20 => {
                self.line_buf.push(b as char);
                eprint!("{}", b as char);
            }
            _ => {}
        }
    }

    fn execute_command(&mut self, cmd: &str, cpu: &Cpu, bus: &mut Bus) {
        let parts: Vec<&str> = cmd.split_whitespace().collect();
        match parts.first().copied() {
            Some("help") | Some("h") => self.cmd_help(),
            Some("quit") | Some("q") => {
                eprintln!("[monitor] Quit");
                self.quit_requested = true;
            }
            Some("info") => match parts.get(1).copied() {
                Some("regs") | Some("registers") | Some("reg") => self.cmd_info_regs(cpu),
                Some("fregs") | Some("fpu") => self.cmd_info_fregs(cpu),
                Some("csrs") | Some("csr") => self.cmd_info_csrs(cpu),
                Some("mem") | Some("memory") => self.cmd_info_mem(bus),
                Some("tlb") => self.cmd_info_tlb(cpu),
                _ => eprintln!("Usage: info <regs|fregs|csrs|mem|tlb>"),
            },
            Some("x") => self.cmd_examine(&parts, bus),
            Some("disasm") | Some("dis") => self.cmd_disasm(&parts, cpu, bus),
            Some("pc") => {
                let mode = match cpu.mode {
                    PrivilegeMode::Machine => "M",
                    PrivilegeMode::Supervisor => "S",
                    PrivilegeMode::User => "U",
                };
                eprintln!("PC = {:#018x}  ({})", cpu.pc, mode);
            }
            _ => eprintln!("Unknown command: {}  (type 'help' for commands)", cmd),
        }
    }

    fn print_escape_help(&self) {
        eprintln!("\r\n[monitor] Escape sequences:");
        eprintln!("  Ctrl-A h  — this help");
        eprintln!("  Ctrl-A x  — quit emulator");
        eprintln!("  Ctrl-A c  — toggle monitor console");
        eprintln!("  Ctrl-A a  — send Ctrl-A to guest");
    }

    fn cmd_help(&self) {
        eprintln!("Monitor commands:");
        eprintln!("  info regs       — general-purpose registers");
        eprintln!("  info fregs      — floating-point registers");
        eprintln!("  info csrs       — key CSRs");
        eprintln!("  info mem        — memory map");
        eprintln!("  info tlb        — TLB statistics");
        eprintln!("  x <addr> [n]    — examine N words at physical address (hex)");
        eprintln!("  disasm [n]      — disassemble N instructions at PC");
        eprintln!("  pc              — show program counter");
        eprintln!("  quit / q        — exit emulator");
    }

    fn cmd_info_regs(&self, cpu: &Cpu) {
        let names = [
            "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3",
            "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11",
            "t3", "t4", "t5", "t6",
        ];
        let mode = match cpu.mode {
            PrivilegeMode::Machine => "Machine",
            PrivilegeMode::Supervisor => "Supervisor",
            PrivilegeMode::User => "User",
        };
        eprintln!("PC = {:#018x}  Mode = {}", cpu.pc, mode);
        for (i, name) in names.iter().enumerate() {
            let val = cpu.regs[i];
            if i % 4 == 0 {
                eprint!("  ");
            }
            eprint!("{:>4} = {:#018x}", name, val);
            if i % 4 == 3 {
                eprintln!();
            } else {
                eprint!("  ");
            }
        }
    }

    fn cmd_info_fregs(&self, cpu: &Cpu) {
        let names = [
            "ft0", "ft1", "ft2", "ft3", "ft4", "ft5", "ft6", "ft7", "fs0", "fs1", "fa0", "fa1",
            "fa2", "fa3", "fa4", "fa5", "fa6", "fa7", "fs2", "fs3", "fs4", "fs5", "fs6", "fs7",
            "fs8", "fs9", "fs10", "fs11", "ft8", "ft9", "ft10", "ft11",
        ];
        for (i, name) in names.iter().enumerate() {
            let val = cpu.fregs[i];
            if i % 2 == 0 {
                eprint!("  ");
            }
            eprint!(
                "{:>5} = {:#018x} ({:>20.8e})",
                name,
                val,
                f64::from_bits(val)
            );
            if i % 2 == 1 {
                eprintln!();
            } else {
                eprint!("  ");
            }
        }
    }

    fn cmd_info_csrs(&self, cpu: &Cpu) {
        use crate::cpu::csr;
        let pairs: &[(u16, &str)] = &[
            (csr::MSTATUS, "mstatus"),
            (csr::MISA, "misa"),
            (csr::MEDELEG, "medeleg"),
            (csr::MIDELEG, "mideleg"),
            (csr::MIE, "mie"),
            (csr::MIP, "mip"),
            (csr::MTVEC, "mtvec"),
            (csr::MEPC, "mepc"),
            (csr::MCAUSE, "mcause"),
            (csr::MTVAL, "mtval"),
            (csr::SSTATUS, "sstatus"),
            (csr::SIE, "sie"),
            (csr::SIP, "sip"),
            (csr::STVEC, "stvec"),
            (csr::SEPC, "sepc"),
            (csr::SCAUSE, "scause"),
            (csr::STVAL, "stval"),
            (csr::SATP, "satp"),
            (csr::MCYCLE, "mcycle"),
            (csr::MINSTRET, "minstret"),
        ];
        for (addr, name) in pairs {
            let val = cpu.csrs.read(*addr);
            eprintln!("  {:>10} ({:#05x}) = {:#018x}", name, addr, val);
        }
    }

    fn cmd_info_mem(&self, bus: &Bus) {
        let ram_size = bus.ram.size();
        eprintln!("Memory map:");
        eprintln!(
            "  RAM      : {:#010x} - {:#010x} ({} MiB)",
            DRAM_BASE,
            DRAM_BASE + ram_size,
            ram_size / (1024 * 1024)
        );
        eprintln!(
            "  CLINT    : {:#010x} - {:#010x}",
            0x0200_0000u64, 0x0201_0000u64
        );
        eprintln!(
            "  PLIC     : {:#010x} - {:#010x}",
            0x0C00_0000u64, 0x1000_0000u64
        );
        eprintln!(
            "  UART     : {:#010x} - {:#010x}",
            0x1000_0000u64, 0x1000_0100u64
        );
        eprintln!(
            "  SYSCON   : {:#010x} - {:#010x}",
            0x0010_0000u64, 0x0010_0010u64
        );
        eprintln!(
            "  RTC      : {:#010x} - {:#010x}",
            0x0010_1000u64, 0x0010_2000u64
        );
        eprintln!(
            "  VirtIO   : {:#010x} - {:#010x}",
            0x1000_1000u64, 0x1000_5000u64
        );
    }

    fn cmd_info_tlb(&self, cpu: &Cpu) {
        let total = cpu.mmu.tlb_hits + cpu.mmu.tlb_misses;
        let hit_rate = if total > 0 {
            cpu.mmu.tlb_hits as f64 / total as f64 * 100.0
        } else {
            0.0
        };
        eprintln!(
            "TLB: hits={} misses={} hit_rate={:.1}%",
            cpu.mmu.tlb_hits, cpu.mmu.tlb_misses, hit_rate
        );
    }

    fn cmd_examine(&self, parts: &[&str], bus: &mut Bus) {
        if parts.len() < 2 {
            eprintln!("Usage: x <addr> [count]");
            return;
        }
        let addr_str = parts[1].trim_start_matches("0x").trim_start_matches("0X");
        let addr = match u64::from_str_radix(addr_str, 16) {
            Ok(a) => a,
            Err(_) => {
                eprintln!("Invalid address: {}", parts[1]);
                return;
            }
        };
        let count: u64 = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(4);
        let count = count.min(64); // Cap at 64 words

        for i in 0..count {
            let a = addr + i * 4;
            if i % 4 == 0 {
                eprint!("  {:#010x}:", a);
            }
            let val = bus.read32(a);
            eprint!(" {:08x}", val);
            if i % 4 == 3 || i == count - 1 {
                eprintln!();
            }
        }
    }

    fn cmd_disasm(&self, parts: &[&str], cpu: &Cpu, bus: &mut Bus) {
        let count: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
        let count = count.min(100);

        // Use physical PC (best-effort: try translate via MMU, fall back to raw PC)
        let mut pc = cpu.pc;
        for _ in 0..count {
            let raw16 = bus.read16(pc);
            let (inst, is_c) = if raw16 & 0x03 != 0x03 {
                (crate::cpu::decode::expand_compressed(raw16 as u32), true)
            } else {
                (bus.read32(pc), false)
            };
            let disasm = crate::cpu::disasm::disassemble(inst, pc);
            if is_c {
                eprintln!("  {:#010x}:  {:04x}       {}", pc, raw16, disasm);
                pc += 2;
            } else {
                eprintln!("  {:#010x}:  {:08x}   {}", pc, inst, disasm);
                pc += 4;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_monitor_new() {
        let mon = Monitor::new();
        assert!(!mon.in_monitor);
        assert!(!mon.quit_requested);
    }

    #[test]
    fn test_monitor_escape_sequence() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        // Regular byte passes through
        assert_eq!(mon.process_byte(b'A', &cpu, &mut bus), Some(b'A'));

        // Ctrl-A starts escape
        assert_eq!(mon.process_byte(0x01, &cpu, &mut bus), None);

        // 'a' after Ctrl-A sends literal Ctrl-A
        assert_eq!(mon.process_byte(b'a', &cpu, &mut bus), Some(0x01));

        // Ctrl-A x quits
        assert_eq!(mon.process_byte(0x01, &cpu, &mut bus), None);
        assert_eq!(mon.process_byte(b'x', &cpu, &mut bus), None);
        assert!(mon.quit_requested);
    }

    #[test]
    fn test_monitor_toggle() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        assert!(!mon.in_monitor);

        // Ctrl-A c toggles monitor
        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);
        assert!(mon.in_monitor);

        // In monitor mode, bytes don't pass through
        assert_eq!(mon.process_byte(b'A', &cpu, &mut bus), None);

        // Ctrl-A c toggles back
        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);
        assert!(!mon.in_monitor);

        // Now bytes pass through again
        assert_eq!(mon.process_byte(b'B', &cpu, &mut bus), Some(b'B'));
    }

    #[test]
    fn test_monitor_help_no_crash() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        // Enter monitor
        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);
        assert!(mon.in_monitor);

        // Type "help" + enter
        for b in b"help" {
            mon.process_byte(*b, &cpu, &mut bus);
        }
        mon.process_byte(b'\r', &cpu, &mut bus);
        assert!(!mon.quit_requested);
    }

    #[test]
    fn test_monitor_quit_command() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        // Enter monitor
        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);

        // Type "quit" + enter
        for b in b"quit" {
            mon.process_byte(*b, &cpu, &mut bus);
        }
        mon.process_byte(b'\r', &cpu, &mut bus);
        assert!(mon.quit_requested);
    }

    #[test]
    fn test_monitor_info_regs() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        // Enter monitor and run info regs
        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);
        for b in b"info regs" {
            mon.process_byte(*b, &cpu, &mut bus);
        }
        mon.process_byte(b'\r', &cpu, &mut bus);
        assert!(!mon.quit_requested);
    }

    #[test]
    fn test_monitor_examine_memory() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        // Enter monitor and examine memory at DRAM_BASE
        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);
        for b in b"x 0x80000000 2" {
            mon.process_byte(*b, &cpu, &mut bus);
        }
        mon.process_byte(b'\r', &cpu, &mut bus);
        assert!(!mon.quit_requested);
    }

    #[test]
    fn test_monitor_pc_command() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);
        for b in b"pc" {
            mon.process_byte(*b, &cpu, &mut bus);
        }
        mon.process_byte(b'\r', &cpu, &mut bus);
        assert!(!mon.quit_requested);
    }

    #[test]
    fn test_monitor_backspace() {
        let mut mon = Monitor::new();
        let cpu = Cpu::new();
        let mut bus = Bus::new(64 * 1024 * 1024);

        // Enter monitor
        mon.process_byte(0x01, &cpu, &mut bus);
        mon.process_byte(b'c', &cpu, &mut bus);

        // Type "qx", backspace, "uit", enter
        mon.process_byte(b'q', &cpu, &mut bus);
        mon.process_byte(b'x', &cpu, &mut bus);
        mon.process_byte(0x7F, &cpu, &mut bus); // backspace
        for b in b"uit" {
            mon.process_byte(*b, &cpu, &mut bus);
        }
        mon.process_byte(b'\r', &cpu, &mut bus);
        assert!(mon.quit_requested);
    }
}
