# Changelog

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
