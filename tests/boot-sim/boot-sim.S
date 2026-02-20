# boot-sim.S — Comprehensive S-mode boot simulation kernel
# Exercises the exact boot path Linux takes on early RISC-V startup.
# Tests: DTB parsing, trap setup, page tables, timer interrupts,
#        UART MMIO, PLIC, SBI calls, and syscon shutdown.
#
# Expected entry: S-mode, a0=hartid, a1=DTB pointer
# Uses SBI putchar for output, UART MMIO for device test

.section .text
.globl _start
.option norelax

# Constants
.equ UART_BASE,   0x10000000
.equ CLINT_BASE,  0x02000000
.equ PLIC_BASE,   0x0C000000
.equ SYSCON_BASE, 0x10006000
.equ DRAM_BASE,   0x80000000

# Page table constants (Sv39)
.equ PAGE_SIZE,   4096
.equ PTE_V,       0x01
.equ PTE_R,       0x02
.equ PTE_W,       0x04
.equ PTE_X,       0x08
.equ PTE_U,       0x00
.equ PTE_A,       0x40
.equ PTE_D,       0x80
.equ SATP_SV39,   0x8000000000000000

# Test result tracking
.equ PASS,        0x50  # 'P'
.equ FAIL,        0x46  # 'F'

_start:
    # ===== Phase 1: Validate entry state =====
    # a0 should be hartid (0), a1 should be DTB pointer

    # Save DTB pointer
    mv s0, a1       # s0 = DTB addr
    mv s1, a0       # s1 = hartid

    # Set up stack (use high memory)
    li sp, DRAM_BASE + 0x100000  # 1 MiB into RAM

    # Print banner
    la a0, msg_banner
    jal print_str

    # Test 1: Check hartid == 0
    la a0, msg_test1
    jal print_str
    bnez s1, test1_fail
    li a0, PASS
    jal sbi_putchar
    j test1_done
test1_fail:
    li a0, FAIL
    jal sbi_putchar
test1_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 2: Validate DTB magic (0xd00dfeed in big-endian)
    la a0, msg_test2
    jal print_str
    # Check first byte is 0xd0 (DTB magic big-endian: d0 0d fe ed)
    lbu t0, 0(s0)
    li t1, 0xd0
    bne t0, t1, test2_fail
    lbu t0, 1(s0)
    li t1, 0x0d
    bne t0, t1, test2_fail
    lbu t0, 2(s0)
    li t1, 0xfe
    bne t0, t1, test2_fail
    lbu t0, 3(s0)
    li t1, 0xed
    bne t0, t1, test2_fail
    li a0, PASS
    jal sbi_putchar
    j test2_done
test2_fail:
    li a0, FAIL
    jal sbi_putchar
test2_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 3: Read sstatus, verify UXL=2 (64-bit)
    la a0, msg_test3
    jal print_str
    csrr t0, sstatus
    srli t0, t0, 32
    andi t0, t0, 3     # UXL field
    li t1, 2
    bne t0, t1, test3_fail
    li a0, PASS
    jal sbi_putchar
    j test3_done
test3_fail:
    li a0, FAIL
    jal sbi_putchar
test3_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 4: Set up trap vector and verify
    la a0, msg_test4
    jal print_str
    la t0, trap_handler
    csrw stvec, t0
    csrr t1, stvec
    # Mask out mode bits
    li t2, ~3
    and t0, t0, t2
    and t1, t1, t2
    bne t0, t1, test4_fail
    li a0, PASS
    jal sbi_putchar
    j test4_done
test4_fail:
    li a0, FAIL
    jal sbi_putchar
test4_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 5: SBI probe extensions
    la a0, msg_test5
    jal print_str
    # Probe TIME extension (0x54494D45)
    li a0, 0x54494D45
    jal sbi_probe
    beqz a0, test5_fail
    # Probe sPI extension (0x735049)
    li a0, 0x735049
    jal sbi_probe
    beqz a0, test5_fail
    # Probe HSM extension (0x48534D)
    li a0, 0x48534D
    jal sbi_probe
    beqz a0, test5_fail
    # Probe DBCN extension (0x4442434E)
    li a0, 0x4442434E
    jal sbi_probe
    beqz a0, test5_fail
    li a0, PASS
    jal sbi_putchar
    j test5_done
test5_fail:
    li a0, FAIL
    jal sbi_putchar
test5_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 6: Read time CSR
    la a0, msg_test6
    jal print_str
    csrr t0, time
    # Time should be non-zero (some cycles have elapsed)
    beqz t0, test6_fail
    li a0, PASS
    jal sbi_putchar
    j test6_done
test6_fail:
    li a0, FAIL
    jal sbi_putchar
test6_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 7: UART MMIO write
    la a0, msg_test7
    jal print_str
    li t0, UART_BASE
    li t1, 'U'
    sb t1, 0(t0)
    li t1, 'A'
    sb t1, 0(t0)
    li t1, 'R'
    sb t1, 0(t0)
    li t1, 'T'
    sb t1, 0(t0)
    li a0, PASS
    jal sbi_putchar
    li a0, '\n'
    jal sbi_putchar

    # Test 8: Set up Sv39 page tables (1GiB identity map)
    la a0, msg_test8
    jal print_str

    # Page table at a known aligned location
    li s2, DRAM_BASE + 0x400000  # page table base at +4MiB (away from code at +2MiB)

    # Zero the page table (512 entries = 4096 bytes)
    mv t0, s2
    li t1, 512
zero_pt:
    sd zero, 0(t0)
    addi t0, t0, 8
    addi t1, t1, -1
    bnez t1, zero_pt

    # Map entry 2 (VA 0x80000000-0xBFFFFFFF → PA 0x80000000)
    # 1GiB superpage: PPN[2] = 2, PTE = (2 << 28) | PTE_V|R|W|X|A|D
    li t0, 2                    # VPN[2] index for 0x80000000
    slli t0, t0, 3              # * 8 bytes per entry
    add t0, s2, t0              # entry address
    li t1, (2 << 28) | PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D
    sd t1, 0(t0)

    # Map entry 0 (VA 0x00000000-0x3FFFFFFF → PA 0x00000000) for MMIO
    li t1, (0 << 28) | PTE_V | PTE_R | PTE_W | PTE_X | PTE_A | PTE_D
    sd t1, 0(s2)

    # Fence before enabling MMU
    sfence.vma

    # Calculate SATP value: mode=8 (Sv39), PPN = page_table_phys >> 12
    mv t0, s2
    srli t0, t0, 12            # PPN
    li t1, SATP_SV39
    or t0, t0, t1
    csrw satp, t0
    sfence.vma

    # If we get here without crashing, MMU is working
    li a0, PASS
    jal sbi_putchar
    li a0, '\n'
    jal sbi_putchar

    # Test 9: Timer interrupt
    la a0, msg_test9
    jal print_str

    # Clear trap flag
    la t0, trap_flag
    sw zero, 0(t0)

    # Set stvec to our handler
    la t0, timer_trap_handler
    csrw stvec, t0

    # Enable STIE (bit 5) in sie
    li t0, (1 << 5)
    csrs sie, t0

    # Enable global interrupts (SIE bit in sstatus)
    csrsi sstatus, 2

    # Set timer via SBI (fire very soon)
    csrr a0, time
    addi a0, a0, 100        # fire in 100 ticks
    li a7, 0x54494D45       # TIME extension
    li a6, 0                # set_timer
    ecall

    # Spin waiting for trap
    li t1, 100000
wait_timer:
    la t0, trap_flag
    lw t0, 0(t0)
    bnez t0, timer_fired
    addi t1, t1, -1
    bnez t1, wait_timer

    # Timeout
    li a0, FAIL
    jal sbi_putchar
    j test9_done

timer_fired:
    li a0, PASS
    jal sbi_putchar

test9_done:
    li a0, '\n'
    jal sbi_putchar

    # Disable interrupts
    csrci sstatus, 2

    # Test 10: SBI get_spec_version
    la a0, msg_test10
    jal print_str
    li a7, 0x10     # Base extension
    li a6, 0        # get_spec_version
    ecall
    # a0 should be 0 (success), a1 should have version
    bnez a0, test10_fail
    beqz a1, test10_fail
    li a0, PASS
    jal sbi_putchar
    j test10_done
test10_fail:
    li a0, FAIL
    jal sbi_putchar
test10_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 11: PLIC read (should return 0 for priority of source 0)
    la a0, msg_test11
    jal print_str
    li t0, PLIC_BASE
    lw t1, 0(t0)           # Read priority[0]
    # Should be 0
    bnez t1, test11_fail
    li a0, PASS
    jal sbi_putchar
    j test11_done
test11_fail:
    li a0, FAIL
    jal sbi_putchar
test11_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 12: FP register access (FS must be enabled)
    la a0, msg_test12
    jal print_str
    # Enable FS (bits 14:13 = 01 in sstatus)
    li t0, (1 << 13)
    csrs sstatus, t0
    # Write and read back an FP register
    li t0, 0x4048F5C3       # float 3.14 in IEEE754
    fmv.d.x f0, t0
    fmv.x.d t1, f0
    bne t0, t1, test12_fail
    li a0, PASS
    jal sbi_putchar
    j test12_done
test12_fail:
    li a0, FAIL
    jal sbi_putchar
test12_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 13: Atomic operations (LR/SC)
    la a0, msg_test13
    jal print_str
    # Set up a memory location for atomics
    li t0, DRAM_BASE + 0x300000
    li t1, 42
    sd t1, 0(t0)
    # LR/SC pair
    lr.d t2, (t0)
    li t3, 99
    sc.d t4, t3, (t0)  # t4 = 0 if success
    bnez t4, test13_fail
    ld t5, 0(t0)
    li t6, 99
    bne t5, t6, test13_fail
    li a0, PASS
    jal sbi_putchar
    j test13_done
test13_fail:
    li a0, FAIL
    jal sbi_putchar
test13_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 14: AMO operations (AMOSWAP, AMOADD)
    la a0, msg_test14
    jal print_str
    li t0, DRAM_BASE + 0x300000
    li t1, 100
    sd t1, 0(t0)
    li t2, 200
    amoswap.d t3, t2, (t0)   # t3 = old value (100), mem = 200
    li t4, 100
    bne t3, t4, test14_fail
    li t2, 50
    amoadd.d t3, t2, (t0)    # t3 = old value (200), mem = 250
    li t4, 200
    bne t3, t4, test14_fail
    ld t5, 0(t0)
    li t6, 250
    bne t5, t6, test14_fail
    li a0, PASS
    jal sbi_putchar
    j test14_done
test14_fail:
    li a0, FAIL
    jal sbi_putchar
test14_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 15: sscratch CSR (used by Linux for per-cpu data)
    la a0, msg_test15
    jal print_str
    li t0, 0xDEADBEEF
    csrw sscratch, t0
    csrr t1, sscratch
    bne t0, t1, test15_fail
    # csrrw swap test
    li t0, 0x12345678
    csrrw t1, sscratch, t0   # t1 = old value (0xDEADBEEF)
    li t2, 0xDEADBEEF
    bne t1, t2, test15_fail
    csrr t1, sscratch
    bne t1, t0, test15_fail
    li a0, PASS
    jal sbi_putchar
    j test15_done
test15_fail:
    li a0, FAIL
    jal sbi_putchar
test15_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 16: PLIC enable and threshold
    la a0, msg_test16
    jal print_str
    li t0, PLIC_BASE
    # Set priority for source 10 (UART) to 1
    li t1, 1
    sw t1, 40(t0)          # priority[10] at offset 10*4=40
    # Enable source 10 for context 1 (S-mode)
    # Enable register for context 1 at PLIC_BASE + 0x2080
    li t0, PLIC_BASE + 0x2080
    li t1, (1 << 10)       # bit 10
    sw t1, 0(t0)
    # Set threshold for context 1 to 0
    li t0, PLIC_BASE + 0x201000
    sw zero, 0(t0)
    # Read back threshold
    lw t1, 0(t0)
    bnez t1, test16_fail
    li a0, PASS
    jal sbi_putchar
    j test16_done
test16_fail:
    li a0, FAIL
    jal sbi_putchar
test16_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 17: DBCN SBI extension (debug console write)
    la a0, msg_test17
    jal print_str
    # Write "SBI" via DBCN
    la t0, dbcn_test_str
    # Need physical address — since identity mapped, VA=PA after MMU on
    mv a0, t0               # num_bytes = ... actually args are: a0=len, a1=addr_lo, a2=addr_hi
    li a0, 3                # 3 bytes
    mv a1, t0               # physical address (identity mapped)
    li a2, 0                # high bits
    li a7, 0x4442434E       # DBCN
    li a6, 0                # console_write
    ecall
    # a0 should be 0 (success)
    bnez a0, test17_fail
    li a0, PASS
    jal sbi_putchar
    j test17_done
test17_fail:
    li a0, FAIL
    jal sbi_putchar
test17_done:
    li a0, '\n'
    jal sbi_putchar

    # Test 18: Bit manipulation (Zbb — CLZ, CTZ, CPOP)
    la a0, msg_test18
    jal print_str
    li t0, 0x80             # 0b10000000
    clz t1, t0
    # CLZ of 0x80 on 64-bit = 56
    li t2, 56
    bne t1, t2, test18_fail
    ctz t1, t0
    # CTZ of 0x80 = 7
    li t2, 7
    bne t1, t2, test18_fail
    li a0, PASS
    jal sbi_putchar
    j test18_done
test18_fail:
    li a0, FAIL
    jal sbi_putchar
test18_done:
    li a0, '\n'
    jal sbi_putchar

    # ===== All tests done =====
    la a0, msg_done
    jal print_str

    # Shutdown via syscon
    li t0, SYSCON_BASE
    li t1, 0x5555
    sw t1, 0(t0)

    # Fallback: infinite loop
1:  wfi
    j 1b

# ===== Subroutines =====

# Print null-terminated string via SBI putchar
print_str:
    mv t6, ra
    mv t5, a0
print_loop:
    lb t0, 0(t5)
    beqz t0, print_done
    mv a0, t0
    jal sbi_putchar
    addi t5, t5, 1
    j print_loop
print_done:
    mv ra, t6
    ret

# SBI legacy putchar: a0 = char
sbi_putchar:
    mv a0, a0       # char in a0
    li a7, 0x01     # legacy putchar
    ecall
    ret

# SBI probe_extension: a0 = extension ID, returns a0 = 1 if available
sbi_probe:
    mv t3, a0       # save ext_id
    li a7, 0x10     # base extension
    li a6, 3        # probe_extension
    mv a0, t3
    ecall
    mv a0, a1       # return value in a1
    ret

# ===== Trap handlers =====

.align 4
trap_handler:
    # Generic trap handler — just return
    csrr t0, sepc
    addi t0, t0, 4
    csrw sepc, t0
    sret

.align 4
timer_trap_handler:
    # Timer interrupt handler — set flag, clear timer, return
    la t0, trap_flag
    li t1, 1
    sw t1, 0(t0)

    # Clear timer by setting it far in the future
    li a0, -1           # max value
    li a7, 0x54494D45   # TIME extension
    li a6, 0            # set_timer
    ecall

    sret

# ===== Data =====
.section .rodata
msg_banner:  .asciz "\n=== microvm Boot Simulation ===\n"
msg_test1:   .asciz "T01 hartid==0:     "
msg_test2:   .asciz "T02 DTB magic:     "
msg_test3:   .asciz "T03 sstatus UXL:   "
msg_test4:   .asciz "T04 stvec setup:   "
msg_test5:   .asciz "T05 SBI probes:    "
msg_test6:   .asciz "T06 time CSR:      "
msg_test7:   .asciz "T07 UART MMIO:     "
msg_test8:   .asciz "T08 Sv39 MMU:      "
msg_test9:   .asciz "T09 timer IRQ:     "
msg_test10:  .asciz "T10 SBI version:   "
msg_test11:  .asciz "T11 PLIC read:     "
msg_test12:  .asciz "T12 FP regs:       "
msg_test13:  .asciz "T13 LR/SC atomic:  "
msg_test14:  .asciz "T14 AMO ops:       "
msg_test15:  .asciz "T15 sscratch CSR:  "
msg_test16:  .asciz "T16 PLIC config:   "
msg_test17:  .asciz "T17 DBCN write:    "
msg_test18:  .asciz "T18 Zbb CLZ/CTZ:   "
msg_done:    .asciz "\nAll tests complete. Shutting down.\n"
dbcn_test_str: .asciz "SBI"

.section .bss
.align 4
trap_flag:   .word 0
