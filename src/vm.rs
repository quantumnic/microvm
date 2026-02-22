use std::path::PathBuf;

use crate::cpu::csr;
use crate::cpu::Cpu;
use crate::devices::syscon::SysconAction;
use crate::dtb;
use crate::gdb::{GdbAction, GdbServer};
use crate::loader;
use crate::memory::rom::BootRom;
use crate::memory::{Bus, DRAM_BASE};
use crate::monitor::Monitor;
use crate::profile::Profile;
use crate::snapshot;

pub struct VmConfig {
    pub kernel_path: PathBuf,
    pub disk_path: Option<PathBuf>,
    pub initrd_path: Option<PathBuf>,
    pub ram_size_mib: u64,
    pub kernel_cmdline: String,
    pub load_addr: u64,
    pub trace: bool,
    pub max_insns: Option<u64>,
    pub gdb_port: Option<u16>,
    pub timeout_secs: Option<u64>,
    pub save_snapshot: Option<PathBuf>,
    pub load_snapshot: Option<PathBuf>,
    pub profile: bool,
    pub num_harts: usize,
}

pub struct Vm {
    cpus: Vec<Cpu>,
    bus: Bus,
    config: VmConfig,
}

impl Vm {
    pub fn new(config: VmConfig) -> Self {
        let ram_bytes = config.ram_size_mib * 1024 * 1024;
        let num_harts = config.num_harts.clamp(1, 8);
        let mut bus = Bus::new(ram_bytes);
        bus.clint = crate::devices::clint::Clint::with_harts(num_harts);
        bus.plic = crate::devices::plic::Plic::with_harts(num_harts);
        bus.num_harts = num_harts;

        let mut cpus = Vec::with_capacity(num_harts);
        for i in 0..num_harts {
            let mut cpu = Cpu::with_hart_id(i as u64);
            if i > 0 {
                // Secondary harts start in Stopped state (SBI HSM)
                cpu.hart_state = crate::cpu::HartState::Stopped;
            }
            cpus.push(cpu);
        }
        Self { cpus, bus, config }
    }

    pub fn run(&mut self) {
        let ram_bytes = self.config.ram_size_mib * 1024 * 1024;
        let num_harts = self.cpus.len();

        // Load kernel (auto-detects ELF, RISC-V Image, or raw binary)
        let kernel_data = std::fs::read(&self.config.kernel_path).unwrap_or_else(|e| {
            eprintln!("Failed to read kernel: {}", e);
            std::process::exit(1);
        });

        let loaded = loader::load_kernel(
            &kernel_data,
            self.config.load_addr,
            self.bus.ram.as_mut_slice(),
            DRAM_BASE,
        );
        let kernel_entry = loaded.entry;

        log::info!(
            "Loaded kernel: {} ({} bytes) entry={:#x} base={:#x} size={:#x}",
            self.config.kernel_path.display(),
            kernel_data.len(),
            loaded.entry,
            loaded.load_base,
            loaded.load_size
        );

        // Attach disk image if provided
        if let Some(ref disk_path) = self.config.disk_path {
            if let Err(e) = self.bus.virtio_blk.attach_disk(disk_path) {
                eprintln!(
                    "Warning: Failed to attach disk {}: {}",
                    disk_path.display(),
                    e
                );
            }
        }

        // Load initrd if provided
        let initrd_info = if let Some(ref initrd_path) = self.config.initrd_path {
            let initrd_data = std::fs::read(initrd_path).unwrap_or_else(|e| {
                eprintln!("Failed to read initrd: {}", e);
                std::process::exit(1);
            });
            let initrd_size = initrd_data.len() as u64;
            let initrd_end_region = DRAM_BASE + ram_bytes - 0x200000;
            let initrd_start = (initrd_end_region - initrd_size) & !0xFFF;
            self.bus.load_binary(&initrd_data, initrd_start - DRAM_BASE);
            log::info!(
                "Loaded initrd: {} ({} bytes) at {:#x}-{:#x}",
                initrd_path.display(),
                initrd_data.len(),
                initrd_start,
                initrd_start + initrd_size
            );
            Some((initrd_start, initrd_start + initrd_size))
        } else {
            None
        };

        // Generate and load DTB (SMP-aware)
        let has_disk = self.config.disk_path.is_some();
        let dtb_data = dtb::generate_dtb_smp(
            ram_bytes,
            &self.config.kernel_cmdline,
            has_disk,
            initrd_info,
            num_harts,
        );
        let dtb_addr = DRAM_BASE + ram_bytes - ((dtb_data.len() as u64 + 0xFFF) & !0xFFF);
        let dtb_offset = dtb_addr - DRAM_BASE;
        self.bus.load_binary(&dtb_data, dtb_offset);

        log::info!("DTB at {:#x} ({} bytes)", dtb_addr, dtb_data.len());

        // Generate boot ROM and load at DRAM_BASE
        let boot_code = BootRom::generate(kernel_entry, dtb_addr);
        self.bus.load_binary(&boot_code, 0);

        // Reset hart 0 — start at DRAM_BASE (boot ROM)
        self.cpus[0].reset(DRAM_BASE);
        self.cpus[0].hart_state = crate::cpu::HartState::Started;

        // Secondary harts stay stopped (will be started via SBI HSM hart_start)

        // Set up terminal for raw mode
        let _raw_guard = setup_terminal();

        let trace = self.config.trace;
        let max_insns = self.config.max_insns;

        // Set up GDB server if requested (attached to hart 0)
        let mut gdb: Option<GdbServer> = if let Some(port) = self.config.gdb_port {
            match GdbServer::new(port) {
                Ok(mut server) => {
                    if let Err(e) = server.wait_for_client() {
                        eprintln!("GDB client connection failed: {}", e);
                        None
                    } else {
                        match server.report_stop(&mut self.cpus[0], &mut self.bus, 5) {
                            GdbAction::Continue | GdbAction::Step => {}
                            GdbAction::Disconnect => {
                                log::info!("GDB disconnected before start");
                                return;
                            }
                        }
                        Some(server)
                    }
                }
                Err(e) => {
                    eprintln!("Failed to start GDB server: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Load snapshot if provided (restores hart 0 CPU, CSRs, RAM, devices)
        if let Some(ref snap_path) = self.config.load_snapshot {
            if let Err(e) = snapshot::load_snapshot(snap_path, &mut self.cpus[0], &mut self.bus) {
                eprintln!("Failed to load snapshot: {}", e);
                std::process::exit(1);
            }
        }

        log::info!(
            "Starting emulation ({} hart{})... (Ctrl-A h for monitor help)",
            num_harts,
            if num_harts > 1 { "s" } else { "" }
        );

        let start_time = std::time::Instant::now();
        let timeout = self.config.timeout_secs.map(std::time::Duration::from_secs);

        let mut profiler = if self.config.profile {
            Some(Profile::new())
        } else {
            None
        };

        let mut monitor = Monitor::new();

        // Main execution loop — round-robin across harts
        let mut insn_count: u64 = 0;
        'outer: loop {
            if let Some(max) = max_insns {
                if insn_count >= max {
                    log::info!("Reached max instruction count ({})", max);
                    break;
                }
            }

            // Check wall-clock timeout (every 65536 instructions)
            if insn_count & 0xFFFF == 0 {
                if let Some(dur) = timeout {
                    if start_time.elapsed() >= dur {
                        log::info!("Timeout after {} seconds", dur.as_secs());
                        break;
                    }
                }
            }

            // Update device interrupts (shared across all harts)
            if self.bus.uart.has_interrupt() {
                self.bus.plic.set_pending(10);
            }
            if self.bus.virtio_blk.has_interrupt() {
                self.bus.plic.set_pending(8);
            }
            if self.bus.virtio_console.has_interrupt() {
                self.bus.plic.set_pending(9);
            }
            if self.bus.virtio_rng.has_interrupt() {
                self.bus.plic.set_pending(11);
            }
            if self.bus.virtio_net.has_interrupt() {
                self.bus.plic.set_pending(12);
            }
            self.bus.rtc.tick();
            if self.bus.rtc.has_interrupt() {
                self.bus.plic.set_pending(13);
            }

            // Step each hart
            for hart_id in 0..num_harts {
                use crate::cpu::HartState;

                let cpu = &mut self.cpus[hart_id];

                // Handle StartPending: begin execution at the configured address
                if cpu.hart_state == HartState::StartPending {
                    cpu.hart_state = HartState::Started;
                    log::info!("Hart {} started at PC={:#x}", hart_id, cpu.pc);
                }

                // Only step Started harts
                if cpu.hart_state != HartState::Started {
                    continue;
                }

                // Update mtime in CSR file
                cpu.csrs.mtime = self.bus.clint.mtime();

                // Timer interrupt — STIP (bit 5)
                let clint_timer = self.bus.clint.timer_interrupt_hart(hart_id);
                let sstc_timer = cpu.csrs.stimecmp_pending();
                let mip = cpu.csrs.read(csr::MIP);
                if clint_timer || sstc_timer {
                    cpu.csrs.write(csr::MIP, mip | (1 << 5));
                } else {
                    cpu.csrs.write(csr::MIP, mip & !(1 << 5));
                }

                // Software interrupt — MSIP (bit 3)
                if self.bus.clint.software_interrupt_hart(hart_id) {
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip | (1 << 3));
                } else {
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip & !(1 << 3));
                }

                // External interrupts via PLIC → SEIP (S-mode context = 2*hart+1)
                let s_context = hart_id * 2 + 1;
                if self.bus.plic.has_interrupt(s_context) {
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip | (1 << 9));
                } else {
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip & !(1 << 9));
                }

                if trace && hart_id == 0 {
                    let trace_pc = cpu.pc;
                    let phys_pc = cpu
                        .mmu
                        .translate(
                            trace_pc,
                            crate::cpu::mmu::AccessType::Execute,
                            cpu.mode,
                            &cpu.csrs,
                            &mut self.bus,
                        )
                        .unwrap_or(trace_pc);
                    let raw16 = self.bus.read16(phys_pc);
                    let (inst_raw, is_compressed) = if raw16 & 0x03 != 0x03 {
                        (crate::cpu::decode::expand_compressed(raw16 as u32), true)
                    } else {
                        (self.bus.read32(phys_pc), false)
                    };
                    let disasm = crate::cpu::disasm::disassemble(inst_raw, trace_pc);
                    let mode_ch = match cpu.mode {
                        crate::cpu::PrivilegeMode::Machine => 'M',
                        crate::cpu::PrivilegeMode::Supervisor => 'S',
                        crate::cpu::PrivilegeMode::User => 'U',
                    };
                    if is_compressed {
                        eprintln!(
                            "[{:>10}] {:#010x} ({:04x})     {}: {}",
                            insn_count, trace_pc, raw16, mode_ch, disasm
                        );
                    } else {
                        eprintln!(
                            "[{:>10}] {:#010x} {:08x}  {}: {}",
                            insn_count, trace_pc, inst_raw, mode_ch, disasm
                        );
                    }
                }

                // Profile: record instruction before execution (hart 0 only)
                let mut prof_opcode: u8 = 0;
                if hart_id == 0 {
                    if let Some(ref mut prof) = profiler {
                        let prof_pc = cpu.pc;
                        let phys = cpu
                            .mmu
                            .translate(
                                prof_pc,
                                crate::cpu::mmu::AccessType::Execute,
                                cpu.mode,
                                &cpu.csrs,
                                &mut self.bus,
                            )
                            .unwrap_or(prof_pc);
                        let raw16 = self.bus.read16(phys);
                        let inst = if raw16 & 0x03 != 0x03 {
                            crate::cpu::decode::expand_compressed(raw16 as u32)
                        } else {
                            self.bus.read32(phys)
                        };
                        let mode = cpu.mode as u8;
                        let mn = crate::cpu::disasm::mnemonic(inst);
                        prof.record_insn(prof_pc, mn, mode);

                        prof_opcode = (inst & 0x7F) as u8;
                        match prof_opcode {
                            0x03 | 0x07 => prof.record_load(),
                            0x23 | 0x27 => prof.record_store(),
                            _ => {}
                        }
                    }
                }

                let pre_step_pc = if profiler.is_some() && hart_id == 0 {
                    cpu.pc
                } else {
                    0
                };

                if !cpu.step(&mut self.bus) {
                    if let Some(ref mut gdb_server) = gdb {
                        gdb_server.report_stop(&mut self.cpus[0], &mut self.bus, 5);
                    }
                    break 'outer;
                }

                insn_count += 1;

                // Profile: post-step (hart 0 only)
                if hart_id == 0 {
                    if let Some(ref mut prof) = profiler {
                        if prof_opcode == 0x63 {
                            let diff = cpu.pc.wrapping_sub(pre_step_pc);
                            prof.record_branch(diff != 4 && diff != 2);
                        }
                        if let Some((cause, is_int)) = cpu.last_trap.take() {
                            prof.record_trap(cause, is_int);
                        }
                        if let Some((eid, fid)) = cpu.last_sbi.take() {
                            prof.record_sbi(eid, fid);
                        }
                    }
                }
            }

            // Process hart start requests from SBI HSM
            while let Some(req) = self.bus.hart_start_queue.pop() {
                if req.hart_id < num_harts {
                    let target = &mut self.cpus[req.hart_id];
                    if target.hart_state == crate::cpu::HartState::Stopped {
                        target.reset(req.start_addr);
                        // Set up CSRs same as boot ROM firmware
                        // PMP: allow all access
                        target.csrs.write(csr::PMPADDR0, u64::MAX);
                        target.csrs.write(csr::PMPCFG0, 0x0F); // TOR, RWX
                                                               // Delegate exceptions/interrupts to S-mode
                        target.csrs.write(csr::MEDELEG, 0xB1FF);
                        target
                            .csrs
                            .write(csr::MIDELEG, (1 << 1) | (1 << 5) | (1 << 9));
                        // Counter access
                        target.csrs.write(csr::MCOUNTEREN, 7);
                        target.csrs.write(csr::SCOUNTEREN, 7);
                        // Enable Sstc + Svadu
                        target.csrs.write(csr::MENVCFG, (1u64 << 63) | (1u64 << 61));
                        // mtvec: point to boot ROM trap handler (MRET at DRAM_BASE+0x100)
                        target
                            .csrs
                            .write(csr::MTVEC, crate::memory::DRAM_BASE + 0x100);
                        // Set up mstatus: SXL=2, UXL=2, MPP=S(01), MPIE=1, FS/VS=Initial
                        // Must use write_raw to set SXL/UXL since write() treats them as readonly
                        let mstatus = (2u64 << 34)   // SXL=2 (64-bit)
                            | (2u64 << 32)            // UXL=2 (64-bit)
                            | (1u64 << 13)            // FS=Initial
                            | (1u64 << 11)            // MPP=S
                            | (1u64 << 9)             // VS=Initial
                            | (1u64 << 7); // MPIE
                        target.csrs.write_raw(csr::MSTATUS, mstatus);
                        // Enter S-mode
                        target.mode = crate::cpu::PrivilegeMode::Supervisor;
                        target.regs[10] = req.hart_id as u64; // a0 = hart_id
                        target.regs[11] = req.opaque; // a1 = opaque
                        target.hart_state = crate::cpu::HartState::StartPending;
                        log::info!(
                            "Hart {} queued for start at {:#x} (opaque={:#x})",
                            req.hart_id,
                            req.start_addr,
                            req.opaque
                        );
                    }
                }
            }

            // Handle IPI: CLINT MSIP sets SSIP for S-mode software interrupts
            // Linux uses SBI send_ipi which writes CLINT msip, and expects SSIP
            for hart_id in 0..num_harts {
                if self.bus.clint.msip[hart_id] & 1 != 0 {
                    let cpu = &mut self.cpus[hart_id];
                    // Set SSIP (bit 1) — S-mode software interrupt pending
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip | (1 << 1));
                    // Wake from WFI if suspended
                    if cpu.hart_state == crate::cpu::HartState::Suspended {
                        cpu.hart_state = crate::cpu::HartState::Started;
                        cpu.wfi = false;
                    }
                } else {
                    // Clear SSIP when MSIP is cleared
                    let cpu = &mut self.cpus[hart_id];
                    let mip = cpu.csrs.read(csr::MIP);
                    cpu.csrs.write(csr::MIP, mip & !(1 << 1));
                }
            }

            // GDB: check for breakpoints (hart 0)
            if let Some(ref mut gdb_server) = gdb {
                if gdb_server.should_halt(self.cpus[0].pc) {
                    match gdb_server.report_stop(&mut self.cpus[0], &mut self.bus, 5) {
                        GdbAction::Continue | GdbAction::Step => {}
                        GdbAction::Disconnect => {
                            log::info!("GDB disconnected");
                            gdb = None;
                        }
                    }
                }
            }

            // Check for syscon poweroff/reboot
            match self.bus.syscon.take_action() {
                SysconAction::Poweroff => {
                    log::info!("System poweroff after {} instructions", insn_count);
                    std::process::exit(0);
                }
                SysconAction::Reboot => {
                    log::info!("System reboot after {} instructions", insn_count);
                    std::process::exit(0);
                }
                SysconAction::None => {}
            }

            // Periodic tasks (every 1024 instructions)
            if insn_count & 0x3FF == 0 {
                poll_stdin_monitor(&mut self.bus, &self.cpus[0], &mut monitor);

                if monitor.quit_requested {
                    log::info!("Monitor quit after {} instructions", insn_count);
                    break;
                }

                if self.bus.virtio_blk.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_blk.process_queue(ram, dram_base);
                }
                if self.bus.virtio_console.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_console.process_queues(ram, dram_base);
                }
                if self.bus.virtio_rng.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_rng.process_queue(ram, dram_base);
                }
                if self.bus.virtio_net.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_net.process_queues(ram, dram_base);
                }
            }
        }

        // Save snapshot (hart 0)
        if let Some(ref snap_path) = self.config.save_snapshot {
            if let Err(e) = snapshot::save_snapshot(snap_path, &self.cpus[0], &mut self.bus) {
                eprintln!("Failed to save snapshot: {}", e);
            }
        }

        if let Some(ref prof) = profiler {
            prof.print_summary();
        }

        let elapsed = start_time.elapsed();
        let mips = if elapsed.as_micros() > 0 {
            insn_count as f64 / elapsed.as_secs_f64() / 1_000_000.0
        } else {
            0.0
        };
        log::info!(
            "Emulation ended after {} instructions in {:.2}s ({:.1} MIPS)",
            insn_count,
            elapsed.as_secs_f64(),
            mips
        );
    }
}

fn poll_stdin_monitor(bus: &mut Bus, cpu: &Cpu, monitor: &mut Monitor) {
    use std::io::Read;
    let mut buf = [0u8; 1];
    unsafe {
        let mut fds = libc::pollfd {
            fd: 0, // stdin
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = libc::poll(&mut fds, 1, 0);
        if ret > 0
            && fds.revents & libc::POLLIN != 0
            && std::io::stdin().read(&mut buf).unwrap_or(0) == 1
        {
            if let Some(byte) = monitor.process_byte(buf[0], cpu, bus) {
                bus.uart.push_byte(byte);
            }
        }
    }
}

/// Put terminal into raw mode and restore on drop
struct RawTermGuard {
    orig: libc::termios,
}

impl Drop for RawTermGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(0, libc::TCSANOW, &self.orig);
        }
        println!(); // Clean newline on exit
    }
}

fn setup_terminal() -> Option<RawTermGuard> {
    unsafe {
        let mut orig: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(0, &mut orig) != 0 {
            return None;
        }
        let guard = RawTermGuard { orig };
        let mut raw = orig;
        libc::cfmakeraw(&mut raw);
        libc::tcsetattr(0, libc::TCSANOW, &raw);
        Some(guard)
    }
}
