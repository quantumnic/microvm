```
                 ╔══════════════════════════════════════╗
                 ║            ┌─┐ ┬┌─┐┬─┐┌─┐┬  ┬┌┬┐   ║
                 ║            │││ ││  ├┬┘│ │└┐┌┘│││   ║
                 ║            ┴ ┴ ┴└─┘┴└─└─┘ └┘ ┴ ┴   ║
                 ║                                      ║
                 ║   OS Development Playground 🚀        ║
                 ║   Build your first OS in 30 minutes   ║
                 ╚══════════════════════════════════════╝
```

# microvm

**Lightweight RISC-V system emulator & OS development playground.**

Boot your own kernel in one command. No QEMU flags, no complexity.

[![CI](https://github.com/redbasecap-buiss/microvm/actions/workflows/ci.yml/badge.svg)](https://github.com/redbasecap-buiss/microvm/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2021-orange.svg?logo=rust)](https://www.rust-lang.org/)
[![ISA](https://img.shields.io/badge/RISC--V-RV64GC-green.svg)](https://riscv.org/)
[![crates.io](https://img.shields.io/badge/crates.io-v0.1.0-blue.svg)](https://crates.io/crates/microvm)

---

## 🚀 Quick Start: Build Your First OS

```bash
# 1. Install microvm
cargo install --git https://github.com/redbasecap-buiss/microvm

# 2. Clone the starter kit
git clone https://github.com/redbasecap-buiss/microvm-starter-kit my-os
cd my-os/minimal-kernel

# 3. Build & boot your kernel
make
microvm run --kernel kernel.bin --load-addr 0x80000000
```

**Expected output:**
```
  ╔═══════════════════════════════════╗
  ║     🖥️  MyOS v0.1 on RISC-V       ║
  ║     Hello from my OS!              ║
  ╚═══════════════════════════════════╝

[mm] heap: 0x80006000 - 0x80800000 (2042 pages)
[mm] enabling Sv39 paging, satp=0x8000000080006
[sched] created task 1: 'Task A'
[sched] created task 2: 'Task B'
[sched] created task 3: 'Task C'
[kernel] starting scheduler...

[Task A] Hello! tick=0, pid=1, iteration=0
[Task B] World! tick=1, pid=2, iteration=0
[Task C] Written via syscall!
```

### Or use the init script:
```bash
# C kernel
./microvm-init.sh my-os
# Rust kernel
./microvm-init.sh my-os --rust
```

---

## 📖 Tutorials

Learn OS development step by step:

| # | Tutorial | What You'll Learn |
|---|----------|-------------------|
| 01 | [Hello World](docs/tutorials/01-hello-world.md) | UART output, first boot |
| 02 | [Interrupts](docs/tutorials/02-interrupts.md) | Timer interrupts, trap handling |
| 03 | [Virtual Memory](docs/tutorials/03-virtual-memory.md) | Sv39 page tables |
| 04 | [Userspace](docs/tutorials/04-userspace.md) | M-mode → U-mode, syscalls |
| 05 | [Scheduler](docs/tutorials/05-scheduler.md) | Round-robin multitasking |
| 06 | [Rust Kernel](docs/tutorials/06-rust-kernel.md) | Same thing in Rust |

---

## 🧰 Starter Kit

The [starter kit](starter-kit/) includes two complete kernel templates:

### C Kernel (`starter-kit/minimal-kernel/`)
A <500-line RISC-V kernel featuring:
- 16550 UART driver with printf
- Timer interrupt handling (CLINT)
- Sv39 virtual memory setup
- Round-robin scheduler (3 tasks)
- 4 syscalls (write, exit, yield, getpid)

### Rust Kernel (`starter-kit/rust-kernel/`)
A `#![no_std]` kernel with:
- UART driver
- Timer interrupts
- Inline assembly for CSR access

> 💡 The starter kit is also available as a standalone repo: [microvm-starter-kit](https://github.com/redbasecap-buiss/microvm-starter-kit)

---

## 🤔 Why RISC-V?

**RISC-V is the best architecture for learning OS development:**

- **Open & Free** — No licensing, full spec available online
- **Simple & Clean** — Designed for teaching, no legacy cruft
- **Modular** — Start with RV64I, add extensions as needed
- **Growing Ecosystem** — Linux, FreeBSD, toolchains all support it
- **Real Hardware** — SiFive, StarFive boards available today
- **Industry Momentum** — Google, Qualcomm, NASA all investing

x86 has 40 years of backwards compatibility baggage. ARM requires licenses. RISC-V is clean, open, and designed for the future.

---

## Why microvm?

| | **microvm** | **QEMU** | **TinyEMU** |
|---|---|---|---|
| **Setup** | `cargo install microvm` | Package manager + flags | Build from source |
| **Boot command** | `microvm run -k bzImage` | `qemu-system-riscv64 -machine virt ...` (20+ flags) | Config file + CLI |
| **Binary size** | ~2 MB | ~50 MB | ~1 MB |
| **Architecture** | Pure Rust, safe | C, decades of code | C |
| **OS Dev Kit** | ✅ Built-in templates & tutorials | ❌ BYO | ❌ None |
| **Target audience** | OS learners & kernel devs | Everyone | Embedded |

**microvm doesn't replace QEMU.** It's for the 80% case: you have a kernel, you want to boot it, you want it *now*.

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
```

### Memory Map

| Address | Size | Device |
|---------|------|--------|
| `0x0200_0000` | 64 KiB | CLINT |
| `0x0C00_0000` | 4 MiB | PLIC |
| `0x1000_0000` | 256 B | UART |
| `0x1000_1000` | 4 KiB | VirtIO Block |
| `0x1000_2000` | 4 KiB | VirtIO Console |
| `0x1000_3000` | 4 KiB | VirtIO RNG |
| `0x1000_4000` | 4 KiB | VirtIO Net |
| `0x1000_5000` | 4 KiB | Goldfish RTC |
| `0x8000_0000` | configurable | DRAM |

---

## Install

```bash
# From GitHub
cargo install --git https://github.com/redbasecap-buiss/microvm

# From source
git clone https://github.com/redbasecap-buiss/microvm
cd microvm
cargo build --release
```

## Usage

```bash
# Boot a bare-metal kernel
microvm run --kernel my-kernel.bin --load-addr 0x80000000

# Boot Linux with a disk
microvm run --kernel Image --disk rootfs.img --memory 256

# Run the built-in example
microvm run --example minimal-kernel
```

---

## Roadmap

### v0.1.0 — Foundation ✅
- [x] RV64GC CPU (I, M, A, C extensions)
- [x] Privilege modes (M/S/U) with trap handling
- [x] Sv39 MMU with page table walking
- [x] 16550 UART, CLINT, PLIC
- [x] Auto-generated Device Tree Blob
- [x] CLI with clap

### v0.2.0 — OS Dev Playground ✅
- [x] Starter Kit: C kernel template (<500 lines)
- [x] Starter Kit: Rust kernel template
- [x] 6 step-by-step tutorials
- [x] `microvm-init.sh` project scaffolding
- [x] Standalone starter kit repo

### v0.3.0 — Linux Boot
- [ ] VirtIO Block/Console/Network
- [ ] F/D extensions (floating point)
- [ ] Boot actual Linux kernel

### v0.4.0 — Developer Experience
- [ ] Built-in kernel builder
- [ ] GDB server
- [ ] Instruction tracing
- [ ] Snapshot/restore

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT — see [LICENSE](LICENSE).
