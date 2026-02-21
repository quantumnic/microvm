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
}

pub struct Vm {
    cpu: Cpu,
    bus: Bus,
    config: VmConfig,
}

impl Vm {
    pub fn new(config: VmConfig) -> Self {
        let ram_bytes = config.ram_size_mib * 1024 * 1024;
        let bus = Bus::new(ram_bytes);
        let cpu = Cpu::new();
        Self { cpu, bus, config }
    }

    pub fn run(&mut self) {
        let ram_bytes = self.config.ram_size_mib * 1024 * 1024;

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
            // Place initrd near end of RAM, page-aligned, leaving room for DTB after it
            let initrd_size = initrd_data.len() as u64;
            let initrd_end_region = DRAM_BASE + ram_bytes - 0x200000; // Leave 2 MiB for DTB
            let initrd_start = (initrd_end_region - initrd_size) & !0xFFF; // Page-align
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

        // Generate and load DTB
        let has_disk = self.config.disk_path.is_some();
        let dtb_data = dtb::generate_dtb(
            ram_bytes,
            &self.config.kernel_cmdline,
            has_disk,
            initrd_info,
        );
        // Place DTB at end of RAM (aligned)
        let dtb_addr = DRAM_BASE + ram_bytes - ((dtb_data.len() as u64 + 0xFFF) & !0xFFF);
        let dtb_offset = dtb_addr - DRAM_BASE;
        self.bus.load_binary(&dtb_data, dtb_offset);

        log::info!("DTB at {:#x} ({} bytes)", dtb_addr, dtb_data.len());

        // Generate boot ROM and load at DRAM_BASE
        let boot_code = BootRom::generate(kernel_entry, dtb_addr);
        self.bus.load_binary(&boot_code, 0);

        // Reset CPU — start at DRAM_BASE (boot ROM)
        self.cpu.reset(DRAM_BASE);

        // Set up terminal for raw mode
        let _raw_guard = setup_terminal();

        let trace = self.config.trace;
        let max_insns = self.config.max_insns;

        // Set up GDB server if requested
        let mut gdb: Option<GdbServer> = if let Some(port) = self.config.gdb_port {
            match GdbServer::new(port) {
                Ok(mut server) => {
                    if let Err(e) = server.wait_for_client() {
                        eprintln!("GDB client connection failed: {}", e);
                        None
                    } else {
                        // Initial halt — wait for GDB commands before running
                        match server.report_stop(&mut self.cpu, &mut self.bus, 5) {
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

        // Load snapshot if provided (restores CPU, CSRs, RAM, devices)
        if let Some(ref snap_path) = self.config.load_snapshot {
            if let Err(e) = snapshot::load_snapshot(snap_path, &mut self.cpu, &mut self.bus) {
                eprintln!("Failed to load snapshot: {}", e);
                std::process::exit(1);
            }
        }

        log::info!("Starting emulation... (Ctrl-A h for monitor help)");

        // Wall-clock timeout support
        let start_time = std::time::Instant::now();
        let timeout = self.config.timeout_secs.map(std::time::Duration::from_secs);

        // Execution profiler
        let mut profiler = if self.config.profile {
            Some(Profile::new())
        } else {
            None
        };

        // Interactive debug monitor
        let mut monitor = Monitor::new();

        // Main execution loop
        let mut insn_count: u64 = 0;
        loop {
            if let Some(max) = max_insns {
                if insn_count >= max {
                    log::info!("Reached max instruction count ({})", max);
                    break;
                }
            }
            // Check wall-clock timeout (every 65536 instructions to avoid syscall overhead)
            if insn_count & 0xFFFF == 0 {
                if let Some(dur) = timeout {
                    if start_time.elapsed() >= dur {
                        log::info!("Timeout after {} seconds", dur.as_secs());
                        break;
                    }
                }
            }
            // Update mtime in CSR file for TIME CSR reads
            self.cpu.csrs.mtime = self.bus.clint.mtime();

            // Update timer interrupt — STIP (bit 5)
            // STIP should be set if EITHER the CLINT timer has fired (SBI legacy path)
            // OR the Sstc stimecmp has fired. Both sources contribute independently.
            let clint_timer = self.bus.clint.timer_interrupt();
            let sstc_timer = self.cpu.csrs.stimecmp_pending();
            let mip = self.cpu.csrs.read(csr::MIP);
            if clint_timer || sstc_timer {
                self.cpu.csrs.write(csr::MIP, mip | (1 << 5)); // Set STIP
            } else {
                self.cpu.csrs.write(csr::MIP, mip & !(1 << 5)); // Clear STIP
            }

            // Update software interrupt
            if self.bus.clint.software_interrupt() {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip | (1 << 3)); // MSIP
            } else {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip & !(1 << 3));
            }

            // Update UART interrupt
            if self.bus.uart.has_interrupt() {
                self.bus.plic.set_pending(10); // UART IRQ = 10
            }

            // Update VirtIO block interrupt
            if self.bus.virtio_blk.has_interrupt() {
                self.bus.plic.set_pending(8); // VirtIO blk IRQ = 8
            }

            // Update VirtIO console interrupt
            if self.bus.virtio_console.has_interrupt() {
                self.bus.plic.set_pending(9); // VirtIO console IRQ = 9
            }

            // Update VirtIO RNG interrupt
            if self.bus.virtio_rng.has_interrupt() {
                self.bus.plic.set_pending(11); // VirtIO RNG IRQ = 11
            }

            // Update VirtIO net interrupt
            if self.bus.virtio_net.has_interrupt() {
                self.bus.plic.set_pending(12); // VirtIO net IRQ = 12
            }

            // External interrupts via PLIC → SEIP
            if self.bus.plic.has_interrupt(1) {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip | (1 << 9)); // SEIP
            } else {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip & !(1 << 9));
            }

            if trace {
                // Fetch and disassemble current instruction for trace
                let trace_pc = self.cpu.pc;
                let phys_pc = self
                    .cpu
                    .mmu
                    .translate(
                        trace_pc,
                        crate::cpu::mmu::AccessType::Execute,
                        self.cpu.mode,
                        &self.cpu.csrs,
                        &mut self.bus,
                    )
                    .unwrap_or(trace_pc);
                let raw16 = self.bus.read16(phys_pc);
                let (inst_raw, is_compressed) = if raw16 & 0x03 != 0x03 {
                    let expanded = crate::cpu::decode::expand_compressed(raw16 as u32);
                    (expanded, true)
                } else {
                    (self.bus.read32(phys_pc), false)
                };
                let disasm = crate::cpu::disasm::disassemble(inst_raw, trace_pc);
                let mode_ch = match self.cpu.mode {
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

            // Profile: record instruction before execution
            let mut prof_opcode: u8 = 0;
            if let Some(ref mut prof) = profiler {
                let prof_pc = self.cpu.pc;
                let phys = self
                    .cpu
                    .mmu
                    .translate(
                        prof_pc,
                        crate::cpu::mmu::AccessType::Execute,
                        self.cpu.mode,
                        &self.cpu.csrs,
                        &mut self.bus,
                    )
                    .unwrap_or(prof_pc);
                let raw16 = self.bus.read16(phys);
                let inst = if raw16 & 0x03 != 0x03 {
                    crate::cpu::decode::expand_compressed(raw16 as u32)
                } else {
                    self.bus.read32(phys)
                };
                let mode = self.cpu.mode as u8;
                let mn = crate::cpu::disasm::mnemonic(inst);
                prof.record_insn(prof_pc, mn, mode);

                prof_opcode = (inst & 0x7F) as u8;
                match prof_opcode {
                    0x03 | 0x07 => prof.record_load(),  // LOAD, FP LOAD
                    0x23 | 0x27 => prof.record_store(), // STORE, FP STORE
                    _ => {}
                }
            }

            // Save PC before step for branch profiling
            let pre_step_pc = if profiler.is_some() { self.cpu.pc } else { 0 };

            if !self.cpu.step(&mut self.bus) {
                // Report termination to GDB if connected
                if let Some(ref mut gdb_server) = gdb {
                    gdb_server.report_stop(&mut self.cpu, &mut self.bus, 5);
                }
                break;
            }

            insn_count += 1;

            // Profile: post-step recording
            if let Some(ref mut prof) = profiler {
                // Branch taken/not-taken
                if prof_opcode == 0x63 {
                    let diff = self.cpu.pc.wrapping_sub(pre_step_pc);
                    prof.record_branch(diff != 4 && diff != 2);
                }
                // Traps
                if let Some((cause, is_int)) = self.cpu.last_trap.take() {
                    prof.record_trap(cause, is_int);
                }
                // SBI calls
                if let Some((eid, fid)) = self.cpu.last_sbi.take() {
                    prof.record_sbi(eid, fid);
                }
            }

            // GDB: check for breakpoints and single-step
            if let Some(ref mut gdb_server) = gdb {
                if gdb_server.should_halt(self.cpu.pc) {
                    match gdb_server.report_stop(&mut self.cpu, &mut self.bus, 5) {
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
                poll_stdin_monitor(&mut self.bus, &self.cpu, &mut monitor);

                // Check if monitor requested quit
                if monitor.quit_requested {
                    log::info!("Monitor quit after {} instructions", insn_count);
                    break;
                }

                // Process VirtIO block queue
                if self.bus.virtio_blk.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_blk.process_queue(ram, dram_base);
                }

                // Process VirtIO console queues
                if self.bus.virtio_console.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_console.process_queues(ram, dram_base);
                }

                // Process VirtIO RNG queue
                if self.bus.virtio_rng.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_rng.process_queue(ram, dram_base);
                }

                // Process VirtIO net queues
                if self.bus.virtio_net.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_net.process_queues(ram, dram_base);
                }
            }
        }

        // Save snapshot if requested
        if let Some(ref snap_path) = self.config.save_snapshot {
            if let Err(e) = snapshot::save_snapshot(snap_path, &self.cpu, &mut self.bus) {
                eprintln!("Failed to save snapshot: {}", e);
            }
        }

        // Print profile summary
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
