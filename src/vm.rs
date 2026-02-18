use std::path::PathBuf;

use crate::cpu::csr;
use crate::cpu::Cpu;
use crate::dtb;
use crate::memory::rom::BootRom;
use crate::memory::{Bus, DRAM_BASE};

pub struct VmConfig {
    pub kernel_path: PathBuf,
    pub disk_path: Option<PathBuf>,
    pub ram_size_mib: u64,
    pub kernel_cmdline: String,
    pub load_addr: u64,
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

        // Load kernel
        let kernel_data = std::fs::read(&self.config.kernel_path).unwrap_or_else(|e| {
            eprintln!("Failed to read kernel: {}", e);
            std::process::exit(1);
        });

        let kernel_offset = self.config.load_addr - DRAM_BASE;
        self.bus.load_binary(&kernel_data, kernel_offset);

        log::info!(
            "Loaded kernel: {} ({} bytes) at {:#x}",
            self.config.kernel_path.display(),
            kernel_data.len(),
            self.config.load_addr
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

        // Generate and load DTB
        let has_disk = self.config.disk_path.is_some();
        let dtb_data = dtb::generate_dtb(ram_bytes, &self.config.kernel_cmdline, has_disk);
        // Place DTB at end of RAM (aligned)
        let dtb_addr = DRAM_BASE + ram_bytes - ((dtb_data.len() as u64 + 0xFFF) & !0xFFF);
        let dtb_offset = dtb_addr - DRAM_BASE;
        self.bus.load_binary(&dtb_data, dtb_offset);

        log::info!("DTB at {:#x} ({} bytes)", dtb_addr, dtb_data.len());

        // Generate boot ROM and load at DRAM_BASE
        let boot_code = BootRom::generate(self.config.load_addr, dtb_addr);
        self.bus.load_binary(&boot_code, 0);

        // Reset CPU — start at DRAM_BASE (boot ROM)
        self.cpu.reset(DRAM_BASE);

        // Set up terminal for raw mode
        let _raw_guard = setup_terminal();

        log::info!("Starting emulation...");

        // Main execution loop
        let mut insn_count: u64 = 0;
        loop {
            // Update mtime in CSR file for TIME CSR reads
            self.cpu.csrs.mtime = self.bus.clint.mtime();

            // Update timer interrupt
            // When CLINT timer fires, set MTIP (bit 7)
            if self.bus.clint.timer_interrupt() {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip | (1 << 7));
            } else {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip & !(1 << 7));
            }

            // Sstc extension: stimecmp drives STIP directly
            if self.cpu.csrs.stimecmp_pending() {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip | (1 << 5)); // STIP
            } else {
                // Only clear STIP if it was set by stimecmp (not by SBI set_timer)
                // For simplicity, let stimecmp control STIP entirely when Sstc is used
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip & !(1 << 5));
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

            // External interrupts via PLIC → SEIP
            if self.bus.plic.has_interrupt(1) {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip | (1 << 9)); // SEIP
            } else {
                let mip = self.cpu.csrs.read(csr::MIP);
                self.cpu.csrs.write(csr::MIP, mip & !(1 << 9));
            }

            if !self.cpu.step(&mut self.bus) {
                break;
            }

            insn_count += 1;

            // Periodic tasks (every 1024 instructions)
            if insn_count & 0x3FF == 0 {
                poll_stdin(&mut self.bus.uart);

                // Process VirtIO block queue
                if self.bus.virtio_blk.needs_processing() {
                    let dram_base = DRAM_BASE;
                    let ram = self.bus.ram.as_mut_slice();
                    self.bus.virtio_blk.process_queue(ram, dram_base);
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
        if ret > 0 && fds.revents & libc::POLLIN != 0
            && std::io::stdin().read(&mut buf).unwrap_or(0) == 1 {
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
