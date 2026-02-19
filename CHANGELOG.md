# Changelog

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
