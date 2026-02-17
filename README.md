```
                 ╔══════════════════════════════════════╗
                 ║            ┌─┐ ┬┌─┐┬─┐┌─┐┬  ┬┌┬┐   ║
                 ║            │││ ││  ├┬┘│ │└┐┌┘│││   ║
                 ║            ┴ ┴ ┴└─┘┴└─└─┘ └┘ ┴ ┴   ║
                 ║                                      ║
                 ║   Boot Linux in One Command. 🚀      ║
                 ╚══════════════════════════════════════╝
```

# microvm

**Lightweight RISC-V system emulator — Boot Linux in one command.**

Built for kernel developers, OS enthusiasts, and anyone tired of QEMU's 100-flag incantations.

[![CI](https://github.com/redbasecap-buiss/microvm/actions/workflows/ci.yml/badge.svg)](https://github.com/redbasecap-buiss/microvm/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

---

## Why microvm?

| | **microvm** | **QEMU** | **TinyEMU** |
|---|---|---|---|
| **Setup** | `cargo install microvm` | Package manager + flags | Build from source |
| **Boot command** | `microvm run -k bzImage` | `qemu-system-riscv64 -machine virt -bios ...` (20+ flags) | Config file + CLI |
| **Binary size** | ~2 MB | ~50 MB | ~1 MB |
| **Architecture** | Pure Rust, safe | C, decades of code | C |
| **Target audience** | Kernel/OS developers | Everyone | Embedded |
| **Built-in tooling** | Planned: kernel build, rootfs, GDB | External tools | None |

**microvm doesn't replace QEMU.** It's for the 80% case: you have a kernel, you want to boot it, you want it *now*.

---

## Quick Start

### Install

```bash
cargo install --git https://github.com/redbasecap-buiss/microvm
```

### Run

```bash
# Boot a bare-metal RISC-V binary
microvm run --kernel my-kernel.bin

# Boot Linux with a disk image
microvm run --kernel Image --disk rootfs.img --memory 256

# Custom kernel command line
microvm run --kernel Image --cmdline "console=ttyS0 root=/dev/vda rw"
```

### Build from source

```bash
git clone https://github.com/redbasecap-buiss/microvm
cd microvm
cargo build --release
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      microvm                             │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────┐  │
│  │          │  │          │  │      Memory Bus        │  │
│  │  RV64GC  │──│   MMU    │──│                        │  │
│  │   CPU    │  │  (Sv39)  │  │  ┌─────┐  ┌────────┐  │  │
│  │          │  │          │  │  │ RAM  │  │ Boot   │  │  │
│  └──────────┘  └──────────┘  │  │      │  │ ROM    │  │  │
│       │                      │  └─────┘  └────────┘  │  │
│       │                      └──────────────────────┘  │
│       │                              │                   │
│  ┌────┴──────────────────────────────┴───────────────┐  │
│  │                  MMIO Devices                      │  │
│  │                                                    │  │
│  │  ┌────────┐  ┌───────┐  ┌──────┐  ┌───────────┐  │  │
│  │  │ UART   │  │ CLINT │  │ PLIC │  │  VirtIO   │  │  │
│  │  │ 16550  │  │ Timer │  │      │  │  (planned) │  │  │
│  │  └────────┘  └───────┘  └──────┘  └───────────┘  │  │
│  └────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
                    ┌─────┴─────┐
                    │ Terminal  │
                    │ (stdout)  │
                    └───────────┘
```

### Emulated Hardware

- **CPU**: RV64GC (RV64I + M + A + C extensions)
- **Privilege Modes**: Machine, Supervisor, User
- **MMU**: Sv39 (3-level page tables, 39-bit virtual address space)
- **UART**: 16550-compatible serial port (terminal I/O)
- **CLINT**: Core-Local Interruptor (timer + software interrupts)
- **PLIC**: Platform-Level Interrupt Controller
- **DTB**: Auto-generated Device Tree for Linux compatibility
- **Memory**: Configurable RAM (default 128 MiB)

### Memory Map

| Address | Size | Device |
|---------|------|--------|
| `0x0200_0000` | 64 KiB | CLINT |
| `0x0C00_0000` | 4 MiB | PLIC |
| `0x1000_0000` | 256 B | UART |
| `0x8000_0000` | configurable | DRAM |

---

## Roadmap

### v0.1.0 — Foundation ✅
- [x] RV64GC CPU (I, M, A, C extensions)
- [x] Privilege modes (M/S/U) with trap handling
- [x] Sv39 MMU with page table walking
- [x] 16550 UART with terminal I/O
- [x] CLINT (timer interrupts)
- [x] PLIC (external interrupts)
- [x] Auto-generated Device Tree Blob
- [x] Boot ROM trampoline
- [x] CLI with clap

### v0.2.0 — Linux Boot
- [ ] VirtIO Block device (disk images)
- [ ] VirtIO Console
- [ ] VirtIO Network (user-mode)
- [ ] F/D extensions (floating point)
- [ ] Boot actual Linux kernel to userspace

### v0.3.0 — Developer Experience
- [ ] Built-in kernel builder (`microvm build-kernel`)
- [ ] Root filesystem creator (`microvm mkrootfs`)
- [ ] GDB server (`microvm run --gdb`)
- [ ] Instruction tracing and profiling
- [ ] Snapshot/restore

### v1.0.0 — Production Ready
- [ ] Multi-core (SMP)
- [ ] 9p filesystem sharing
- [ ] Network (TAP backend)
- [ ] Performance optimization (JIT?)
- [ ] Plugin system for custom devices

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — see [LICENSE](LICENSE).
