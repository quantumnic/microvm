use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod cpu;
mod devices;
mod dtb;
mod gdb;
mod loader;
mod memory;
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
    },
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            kernel,
            disk,
            initrd,
            memory: mem_size,
            cpus: _,
            cmdline,
            load_addr,
            trace,
            max_insns,
            gdb: gdb_port,
            timeout_secs,
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
            };

            let mut vm = vm::Vm::new(config);
            vm.run();
        }
    }
}
