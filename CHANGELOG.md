# Changelog

## v0.33.0 — Boot Simulation Test Suite + RFENCE TLB Fix + AMO Tests

### Major Features
- **Bare-metal boot simulation kernel** (`tests/boot-sim/`): 18-test S-mode kernel exercising the full boot path — DTB validation, trap setup, SBI probes, Sv39 MMU, timer interrupts, UART MMIO, PLIC configuration, FP registers, LR/SC atomics, AMO operations, sscratch CSR, DBCN console, and Zbb bit manipulation. Built with `riscv64-elf-gcc` and runnable via `microvm run`.
- **SBI RFENCE TLB flush bugfix**: `remote_sfence_vma` and `remote_sfence_vma_asid` now properly flush the TLB (previously returned success without actually flushing). Supports both full TLB flush and per-page invalidation.

### New Tests
- 6 new integration tests: SBI RFENCE TLB flush, RFENCE vaddr-specific flush, AMOMIN/AMOMAX, AMOXOR/AMOAND/AMOOR, AMO doubleword (64-bit amoswap.d)
- Boot simulation kernel: 18 bare-metal S-mode tests covering CPU, MMU, SBI, devices, and extensions

### Bug Fixes
- SBI `remote_sfence_vma` (RFENCE ext, fid=1): now flushes TLB entries, critical for Linux boot where page table updates rely on remote TLB shootdown
- SBI `remote_sfence_vma_asid` (RFENCE ext, fid=2): same fix, with ASID-aware flush

### Stats
- 195 integration tests + 56+56 unit tests = 307 total, all passing
- Boot simulation: 18/18 bare-metal tests passing

## v0.32.0 — Sv57 Five-Level Page Tables

### Major Features
- **Sv57 (5-level) page table support**: The MMU now supports Sv57 translation (SATP mode 10) with 5-level page table walks covering a 57-bit virtual address space (128 PiB). Superpages at all levels (2 MiB, 1 GiB, 512 GiB, 256 TiB) are supported with proper alignment checks.
- **DTB mmu-type updated to `riscv,sv57`**: The device tree now advertises the highest supported MMU mode, allowing Linux to use Sv57 when configured.
- **SATP mode 10 accepted**: The CSR file now accepts Sv57 in addition to Bare, Sv39, and Sv48.

### Improvements
- README roadmap updated: F/D floating-point extensions and Sv57 marked as complete
- 2 new Sv57 tests: full 5-level page walk and 2 MiB superpage translation

### Stats
- 189 tests passing (up from 187)
- MMU: Sv39 (3-level), Sv48 (4-level), Sv57 (5-level) page table translation

## v0.26.0 — GDB Remote Debug Server

### Major Features
- **GDB remote serial protocol (RSP) stub**: Full-featured GDB server accessible via `--gdb <port>`. Connect with `riscv64-unknown-elf-gdb -ex 'target remote :<port>'` or any GDB-compatible debugger.
- **Register inspection**: Read/write all 32 general-purpose registers + PC via `g/G/p/P` packets. Little-endian hex encoding per GDB RSP spec.
- **Memory read/write**: Arbitrary memory access via `m/M` packets — inspect RAM, MMIO registers, device tree in-place.
- **Execution control**: Continue (`c`), single-step (`s`), `vCont` support. CPU halts on connect, waiting for GDB commands.
- **Software breakpoints**: Insert/remove breakpoints via `Z0/z0` packets. Breakpoints checked after each instruction.
- **Target description XML**: `qXfer:features:read` returns RISC-V 64-bit register layout so GDB auto-detects architecture.
- **Monitor commands**: `qRcmd` support for custom emulator commands.
- **Ctrl-C interrupt**: Send SIGINT (0x03) to halt a running emulation.

### Usage
```bash
# Start emulator with GDB server on port 1234
microvm run --kernel my-kernel.bin --gdb 1234

# In another terminal:
riscv64-unknown-elf-gdb -ex 'target remote :1234'
(gdb) break *0x80200000
(gdb) continue
(gdb) info registers
(gdb) x/10i $pc
```

### Stats
- 5 new GDB unit tests (hex encoding, register format, breakpoint management, address parsing)
- 144 tests passing (139 → 144)
- New module: `src/gdb.rs` (~530 lines)

## v0.24.0 — VirtIO Network Device

### Major Features
- **VirtIO network device (virtio-net)**: Full VirtIO MMIO v2 network device implementation with MAC address, link status, RX/TX virtqueues, and feature negotiation (VIRTIO_NET_F_MAC, VIRTIO_NET_F_STATUS, VIRTIO_F_VERSION_1). Without a TAP backend, TX packets are consumed and dropped cleanly — Linux can probe and initialize the driver without errors. Default MAC: 52:54:00:12:34:56.
- **DTB integration**: Network device added to device tree at MMIO address 0x10004000, IRQ 12, automatically discovered by Linux during boot.
- **Bus routing**: New VIRTIO3 memory region (0x10004000-0x10004FFF) with full 8/16/32/64-bit read/write dispatch.

### Improvements
- 10 new VirtIO net tests covering MMIO registers, feature negotiation, MAC/status config reads, queue setup, interrupt acknowledge, and TX queue processing with descriptor chain walking.
- VirtIO device count: 4 (block, console, RNG, network)

### Stats
- 217 tests passing (up from 197)
- Full RV64IMACSU with Sv39/Sv48 MMU
- VirtIO devices: block, console (hvc0), RNG (entropy), network

## v0.16.0 — Misaligned Access Support, UART THRE Fix, SBI Stubs

### Major Features
- **Misaligned memory access emulation**: LH/LHU/LW/LWU/LD/SH/SW/SD now handle misaligned addresses transparently via byte-by-byte decomposition. Critical for Linux boot — the kernel may generate misaligned accesses during early init and string operations.
- **UART 16550 THRE interrupt fix**: THRE (Transmit Holding Register Empty) interrupt now follows proper 16550 behavior — reading IIR clears the THRE condition, writing THR re-arms it, and enabling THRE in IER when THR is empty triggers the interrupt. Fixes console output stalls during Linux boot.
- **SBI CPPC and FWFT extension stubs**: Collaborative Processor Performance Control (0x43505043) and Firmware Features (0x46574654) extensions now return `SBI_ERR_NOT_SUPPORTED` cleanly. Linux probes these during early boot.

### Improvements
- DTB ISA string updated to include `svinval` extension
- DTB now includes `riscv,cbom-block-size` and `riscv,cboz-block-size` properties (64 bytes) — Linux cache management subsystem probes these
- 8 new tests covering misaligned loads/stores, UART THRE behavior, and SBI extension stubs

### Stats
- 107 tests passing (up from 99)
- Full RV64IMACSU with misaligned access support
- SBI firmware: timer, IPI, HSM, RFENCE, SRST, DBCN (+ PMU/SUSP/NACL/STA/CPPC/FWFT stubs)

## v0.15.0 — Bus MMIO Refactor, HPM Counters, SBI Extension Stubs

### Major Features
- **Bus MMIO routing refactor**: All MMIO reads/writes now go through a centralized `route()` dispatcher. 32-bit reads from UART and PLIC no longer decompose into 4 byte-reads — they call the device's native read method directly. This fixes correctness for MMIO registers where byte-access has side effects (e.g., UART RBR clears on read).
- **HPM counter CSR range (0xB03-0xB1F, 0xC03-0xC1F, 0x323-0x33F)**: Machine and user hardware performance monitor counter CSRs are now handled. All return 0 (no HPM events implemented). HPM event selector writes are silently ignored. Counter access respects `mcounteren`/`scounteren` bit fields.
- **`menvcfgh` CSR (0x31A)**: Now handled explicitly — reads 0, writes ignored (RV64 does not use the high half).
- **SBI extension stubs**: PMU (0x504D55), SUSP (0x535553), NACL (0x4E41434C), and STA (0x535441) extensions now return `SBI_ERR_NOT_SUPPORTED` cleanly instead of falling through to the generic unknown handler. Linux probes these early in boot.

### Improvements
- Bus routing is branchless-friendly with a single match dispatch instead of cascading if-else chains
- 7 new tests covering HPM counters, menvcfgh, PLIC/UART 32-bit MMIO, and counter access control

### Stats
- 99 tests passing (up from 92)
- Full RV64IMACSU instruction set with Sv39/Sv48 MMU
- SBI firmware: timer, IPI, HSM, RFENCE, SRST, DBCN (+ PMU/SUSP/NACL/STA stubs)

## v0.9.0 — CSR Privilege Enforcement, SATP Validation, Svinval Extension

### Major Features
- **CSR privilege level checking**: All CSR accesses are now validated against the current privilege mode per RISC-V spec (CSR address bits [9:8] encode minimum privilege). S-mode code accessing M-mode CSRs (mstatus, mepc, etc.) now correctly traps with illegal instruction — critical for Linux running in S-mode.
- **Read-only CSR write protection**: Writes to read-only CSRs (cycle, time, instret, mhartid, mvendorid, etc.) now trap as illegal instruction.
- **SATP mode validation**: Only Bare (mode 0) and Sv39 (mode 8) are accepted; writes with unsupported modes (Sv48, Sv57) are silently ignored per spec.
- **Svinval extension support**: SINVAL.VMA, SFENCE.W.INVAL, and SFENCE.INVAL.IR instructions are now handled (as nops, same as SFENCE.VMA).

### Improvements
- DTB now includes `riscv,isa-base` property required by Linux 6.4+
- DTB ISA string updated to `rv64imacsu_zicsr_zifencei_sstc` format
- Added `zicntr` to `riscv,isa-extensions` stringlist
- SBI spec version now returns proper v2.0 encoding (`(2 << 24) | 0`)
- 6 new tests covering CSR privilege checks, read-only CSR detection, SATP validation, and DTB properties

### Stats
- 80 tests passing (up from 74)
- Full RV64IMACSU instruction set with privilege enforcement
- Sv39 MMU with A/D bit management
- SBI firmware with timer, IPI, HSM, RFENCE, SRST, DBCN extensions

## v0.6.0 — M-mode Firmware, MMU A/D Bits, Counter Access Control

### Major Features
- **M-mode firmware boot ROM**: The boot ROM now acts as a minimal OpenSBI replacement — sets up PMP (full access), delegates exceptions/interrupts to S-mode, configures counter access, and drops to S-mode via MRET. This is a critical step toward Linux boot.
- **MMU Accessed/Dirty bit management**: Sv39 page table walker now sets A and D bits on page table entries as required by the RISC-V spec. Linux expects hardware A/D management and will page-fault without it.
- **Counter access control (MCOUNTEREN/SCOUNTEREN)**: User and supervisor mode counter CSR access (CYCLE, TIME, INSTRET) is now gated by MCOUNTEREN and SCOUNTEREN, with illegal instruction traps on unauthorized access.

### Improvements
- Superpage alignment checks in MMU (misaligned megapages/gigapages now properly fault)
- Boot ROM uses CSRRC/CSRRS for safe mstatus manipulation
- 5 new tests covering MMU A/D bits, counter access control, and firmware boot path

### Stats
- 57 tests passing (up from 52)
- Full RV64IMACSU instruction set
- Sv39 MMU with A/D bit management
- SBI firmware with timer, IPI, HSM, SRST extensions

## v0.5.0 — SBI Firmware, PMP Support, Interrupt Delegation, TIME CSR

## v0.4.0 — VirtIO MMIO Block Device

## v0.3.0 — Comprehensive Test Suite, Bug Fixes, Cycle Counters

## v0.2.0 — OS Dev Playground

## v0.1.0 — Initial Release
