use std::path::PathBuf;

use crate::cpu::csr;
use crate::cpu::Cpu;
use crate::devices::syscon::SysconAction;
use crate::dtb;
use crate::gdb::{GdbAction, GdbServer};
use crate::loader;
use crate::memory::rom::BootRom;
use crate::memory::{Bus, DRAM_BASE};

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

        log::info!("Starting emulation...");

        // Main execution loop
        let mut insn_count: u64 = 0;
        loop {
            if let Some(max) = max_insns {
                if insn_count >= max {
                    log::info!("Reached max instruction count ({})", max);
                    break;
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
                eprintln!(
                    "[{:>10}] PC={:#010x} mode={:?} a0={:#x} a1={:#x} a7={:#x} sp={:#x}",
                    insn_count,
                    self.cpu.pc,
                    self.cpu.mode,
                    self.cpu.regs[10],
                    self.cpu.regs[11],
                    self.cpu.regs[17],
                    self.cpu.regs[2],
                );
            }

            if !self.cpu.step(&mut self.bus) {
                // Report termination to GDB if connected
                if let Some(ref mut gdb_server) = gdb {
                    gdb_server.report_stop(&mut self.cpu, &mut self.bus, 5);
                }
                break;
            }

            insn_count += 1;

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
                poll_stdin(&mut self.bus.uart);

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

        log::info!("Emulation ended after {} instructions", insn_count);
    }
}

fn poll_stdin(uart: &mut crate::devices::uart::Uart) {
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
            uart.push_byte(buf[0]);
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
