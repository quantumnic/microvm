use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod cpu;
mod devices;
mod dtb;
mod gdb;
mod loader;
mod memory;
mod monitor;
mod profile;
mod snapshot;
mod vm;

#[derive(Parser)]
#[command(
    name = "microvm",
    version,
    about = "Lightweight RISC-V system emulator — Boot Linux in one command"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inspect a VM snapshot file (show CPU state, CSRs, memory info)
    Inspect {
        /// Path to snapshot file
        #[arg(short, long)]
        snapshot: PathBuf,

        /// Show all general-purpose registers (not just non-zero)
        #[arg(long)]
        all_regs: bool,

        /// Show floating-point registers
        #[arg(long)]
        fpregs: bool,

        /// Show all CSR values (verbose)
        #[arg(long)]
        csrs: bool,

        /// Disassemble N instructions at current PC
        #[arg(long)]
        disasm: Option<u64>,
    },

    /// Dump the generated Device Tree in DTS (source) format
    Dts {
        /// RAM size in MiB (default: 128)
        #[arg(short, long, default_value = "128")]
        memory: u64,

        /// Include VirtIO block device in DTB
        #[arg(long)]
        disk: bool,

        /// Include initrd region in DTB
        #[arg(long)]
        initrd: bool,

        /// Kernel command line
        #[arg(long, default_value = "console=ttyS0")]
        cmdline: String,
    },

    /// Run a kernel or bare-metal binary
    Run {
        /// Path to kernel image (ELF or raw binary)
        #[arg(short, long)]
        kernel: PathBuf,

        /// Path to disk image (optional)
        #[arg(short, long)]
        disk: Option<PathBuf>,

        /// Path to initrd/initramfs image (optional)
        #[arg(short, long)]
        initrd: Option<PathBuf>,

        /// RAM size in MiB (default: 128)
        #[arg(short, long, default_value = "128")]
        memory: u64,

        /// Number of CPUs (default: 1)
        #[arg(long, default_value = "1")]
        cpus: u32,

        /// Kernel command line
        #[arg(long, default_value = "console=ttyS0")]
        cmdline: String,

        /// Load address for raw binary (hex, default: 0x80200000)
        #[arg(long, default_value = "0x80200000")]
        load_addr: String,

        /// Enable instruction tracing (prints PC, instruction, registers)
        #[arg(long)]
        trace: bool,

        /// Stop after N instructions (useful with --trace)
        #[arg(long)]
        max_insns: Option<u64>,

        /// Start GDB server on given port (e.g. --gdb 1234)
        #[arg(long)]
        gdb: Option<u16>,

        /// Stop after N seconds of wall-clock time
        #[arg(long)]
        timeout_secs: Option<u64>,

        /// Save VM snapshot to file on exit (Ctrl-C or timeout)
        #[arg(long)]
        save_snapshot: Option<PathBuf>,

        /// Load VM snapshot from file before running
        #[arg(long)]
        load_snapshot: Option<PathBuf>,

        /// Enable execution profiling (prints summary on exit)
        #[arg(long)]
        profile: bool,
    },
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Inspect {
            snapshot: snap_path,
            all_regs,
            fpregs,
            csrs,
            disasm,
        } => {
            snapshot::inspect_snapshot(&snap_path, all_regs, fpregs, csrs, disasm);
        }
        Commands::Dts {
            memory: mem_size,
            disk,
            initrd,
            cmdline,
        } => {
            let ram_bytes = mem_size * 1024 * 1024;
            let initrd_info = if initrd {
                // Dummy initrd region for display purposes
                let initrd_start = memory::DRAM_BASE + ram_bytes - 0x100000;
                let initrd_end = initrd_start + 0x100000;
                Some((initrd_start, initrd_end))
            } else {
                None
            };
            let dtb_data = dtb::generate_dtb(ram_bytes, &cmdline, disk, initrd_info);
            let dts = dtb::dtb_to_dts(&dtb_data);
            print!("{dts}");
        }
        Commands::Run {
            kernel,
            disk,
            initrd,
            memory: mem_size,
            cpus,
            cmdline,
            load_addr,
            trace,
            max_insns,
            gdb: gdb_port,
            timeout_secs,
            save_snapshot,
            load_snapshot,
            profile,
        } => {
            let addr = u64::from_str_radix(load_addr.trim_start_matches("0x"), 16)
                .expect("Invalid load address");

            let config = vm::VmConfig {
                kernel_path: kernel,
                disk_path: disk,
                initrd_path: initrd,
                ram_size_mib: mem_size,
                kernel_cmdline: cmdline,
                load_addr: addr,
                trace,
                max_insns,
                gdb_port,
                timeout_secs,
                save_snapshot,
                load_snapshot,
                profile,
                num_harts: cpus as usize,
            };

            let mut vm = vm::Vm::new(config);
            vm.run();
        }
    }
}
