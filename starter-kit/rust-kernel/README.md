# 🦀 RustOS — RISC-V Kernel in Rust

A minimal `#![no_std]` RISC-V kernel that boots on [microvm](https://github.com/quantumnic/microvm).

## Features

- 🖨️ UART output via 16550 driver
- ⏰ Timer interrupts via CLINT
- 🦀 Pure Rust (`no_std`, `no_main`)
- 🔒 Zero unsafe in application logic (only hardware access)

## Prerequisites

```bash
# Rust RISC-V target
rustup target add riscv64gc-unknown-none-elf

# objcopy (one of these)
brew install riscv64-elf-gcc   # macOS
# or: apt install gcc-riscv64-unknown-elf
# or: use llvm-objcopy
```

## Build & Run

```bash
make
make run
```

## Expected Output

```
  ╔═══════════════════════════════════╗
  ║   🦀 RustOS v0.1 on RISC-V        ║
  ║   Hello from my Rust OS!           ║
  ╚═══════════════════════════════════╝

[kernel] timer interrupts enabled
[kernel] entering idle loop...

[kernel] tick 1
[kernel] tick 2
...
[kernel] tick 10

[kernel] 10 ticks done. Halting.
```

## Tutorial

See [06-rust-kernel.md](../../docs/tutorials/06-rust-kernel.md) for a walkthrough.
