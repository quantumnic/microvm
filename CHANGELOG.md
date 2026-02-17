# Changelog

## [0.1.0] - 2026-02-18

### Added
- RV64GC CPU emulation (I, M, A, C extensions + Zicsr)
- Machine, Supervisor, and User privilege modes
- Sv39 MMU with 3-level page table translation
- 16550 UART with terminal I/O
- CLINT (Core-Local Interruptor) with timer interrupts
- PLIC (Platform-Level Interrupt Controller)
- Auto-generated Device Tree Blob for Linux compatibility
- Boot ROM trampoline (sets hartid, DTB pointer, jumps to kernel)
- CLI interface with `microvm run` command
- Configurable RAM size
- Raw terminal mode for serial console
- MIT License
