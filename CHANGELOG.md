# Changelog

## v0.3.0 — Test Suite & Bug Fixes (2026-02-18)

### 🐛 Bug Fixes

- **Fixed Bus mutability chain**: `read32`/`read64` now take `&mut self` to properly support UART side-effect reads through the full call chain
- **Fixed MMU translate**: Updated to accept `&mut Bus` for consistent mutability
- **Fixed PLIC claim**: Reading the claim register now properly clears the pending bit (side-effect on read), matching real hardware behavior
- **Removed unused imports**: Cleaned up `Arc`, `Mutex`, `Read` in UART

### ✨ New Features

- **Comprehensive test suite** (40 tests covering):
  - RV64I base instructions (ADDI, LUI, AUIPC, ADD, SUB, shifts, branches, JAL, JALR)
  - Load/store operations (byte, halfword, word, doubleword with sign/zero extension)
  - RV64M multiply/divide (MUL, DIV, DIVU, REM, div-by-zero edge case)
  - CSR read/write (MISA, MSCRATCH via CSRRW/CSRRS)
  - Compressed instruction expansion (C.NOP, C.LI)
  - Instruction decode verification (R-type, I-type, negative immediates)
  - Memory bus operations (read/write at all widths, binary loading)
  - CLINT timer and software interrupts
  - PLIC interrupt pending/enable/claim
  - UART TX/RX
  - Exception handling (ECALL, MTVEC trap dispatch)
  - DTB generation and boot ROM
  - Integration: Fibonacci computation, x0-always-zero invariant
  - RV64 32-bit word operations (ADDIW with sign extension)

- **Library crate** (`lib.rs`): All modules now publicly accessible for testing and embedding
- **Cycle/instret CSR counters**: `MCYCLE`, `MINSTRET`, and user-level `CYCLE`/`INSTRET` CSRs now track instruction count (needed for Linux boot)

## v0.2.0 — OS Dev Playground (2026-02-18)

### ✨ New Features

- **Starter Kit: C Kernel** (`starter-kit/minimal-kernel/`)
  - Complete RISC-V kernel in <500 lines of C
  - 16550 UART driver with printf-lite
  - Timer interrupt handling via CLINT
  - Sv39 virtual memory page table setup
  - Round-robin scheduler with 3 demo tasks
  - 4 syscalls: write, exit, yield, getpid
  - Cross-compilation with riscv64-elf-gcc

- **Starter Kit: Rust Kernel** (`starter-kit/rust-kernel/`)
  - `#![no_std]` `#![no_main]` RISC-V kernel
  - UART driver, timer interrupts
  - Assembly boot stub and trap entry

- **6 Tutorials** (`docs/tutorials/`)
  - 01: Hello World — UART output, first boot
  - 02: Interrupts — Timer interrupt handling
  - 03: Virtual Memory — Sv39 page tables
  - 04: Userspace — Privilege modes, syscalls
  - 05: Scheduler — Round-robin multitasking
  - 06: Rust Kernel — OS dev in Rust

- **Project Scaffolding** (`microvm-init.sh`)
  - One-command project creation from templates
  - Supports C and Rust templates

- **Standalone Starter Kit Repo**
  - [microvm-starter-kit](https://github.com/redbasecap-buiss/microvm-starter-kit)
  - Fork/clone independently from the emulator

### 📝 Changes

- README rebranded as "OS Development Playground"
- Updated roadmap

## v0.1.0 — Foundation (2025-01-15)

- RV64GC CPU emulation (I, M, A, C extensions)
- Machine/Supervisor/User privilege modes
- Sv39 MMU with 3-level page table walking
- 16550 UART with terminal I/O
- CLINT (timer + software interrupts)
- PLIC (external interrupts)
- Auto-generated Device Tree Blob
- Boot ROM trampoline
- CLI with clap
