use super::csr::{self, CsrFile};
use super::PrivilegeMode;
use crate::memory::Bus;

#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
    Execute,
}

// PTE bits
const PTE_V: u64 = 1 << 0;
const PTE_R: u64 = 1 << 1;
const PTE_W: u64 = 1 << 2;
const PTE_X: u64 = 1 << 3;
const PTE_U: u64 = 1 << 4;
const PTE_A: u64 = 1 << 6;
const PTE_D: u64 = 1 << 7;

// Svpbmt: Page-Based Memory Types (PTE bits 62:61)
const PTE_PBMT_MASK: u64 = 0x3 << 61;
#[allow(dead_code)]
const PTE_PBMT_PMA: u64 = 0 << 61; // Use PMA attributes (default)
#[allow(dead_code)]
const PTE_PBMT_NC: u64 = 1 << 61; // Non-cacheable, idempotent (normal memory, no cache)
#[allow(dead_code)]
const PTE_PBMT_IO: u64 = 2 << 61; // Non-cacheable, non-idempotent (I/O)
const PTE_PBMT_RSVD: u64 = 3 << 61; // Reserved — causes page fault

/// TLB entry: cached virtual-to-physical page mapping
#[derive(Clone, Copy)]
struct TlbEntry {
    /// Virtual page number (vaddr >> 12)
    vpn: u64,
    /// Physical page number (paddr >> 12)
    ppn: u64,
    /// Page size shift (12 for 4K, 21 for 2M, 30 for 1G, 39 for 512G)
    page_shift: u8,
    /// PTE permission bits (R/W/X/U)
    pte_flags: u64,
    /// SATP value when this entry was created (for invalidation)
    satp: u64,
    /// Valid flag
    valid: bool,
}

impl Default for TlbEntry {
    fn default() -> Self {
        Self {
            vpn: 0,
            ppn: 0,
            page_shift: 12,
            pte_flags: 0,
            satp: 0,
            valid: false,
        }
    }
}

/// Number of TLB entries (must be power of 2)
const TLB_SIZE: usize = 256;

/// Sv39/Sv48 MMU with TLB — multi-level page table translation with A/D bit management
pub struct Mmu {
    /// Direct-mapped TLB cache
    tlb: Box<[TlbEntry; TLB_SIZE]>,
    /// TLB hit counter (for diagnostics)
    pub tlb_hits: u64,
    /// TLB miss counter (for diagnostics)
    pub tlb_misses: u64,
}

impl Default for Mmu {
    fn default() -> Self {
        Self::new()
    }
}

impl Mmu {
    pub fn new() -> Self {
        Self {
            tlb: Box::new([TlbEntry::default(); TLB_SIZE]),
            tlb_hits: 0,
            tlb_misses: 0,
        }
    }

    /// Flush the entire TLB (called on SFENCE.VMA, SINVAL.VMA, SATP writes)
    pub fn flush_tlb(&mut self) {
        for entry in self.tlb.iter_mut() {
            entry.valid = false;
        }
    }

    /// Flush TLB entries matching a specific virtual address
    pub fn flush_tlb_vaddr(&mut self, vaddr: u64) {
        let vpn = vaddr >> 12;
        // Check all entries since superpages may match different indices
        for entry in self.tlb.iter_mut() {
            if entry.valid {
                let mask = (1u64 << (entry.page_shift - 12)) - 1;
                if (entry.vpn & !mask) == (vpn & !mask) {
                    entry.valid = false;
                }
            }
        }
    }

    /// TLB index from virtual page number
    fn tlb_index(vpn: u64) -> usize {
        (vpn as usize) & (TLB_SIZE - 1)
    }

    /// Look up address in TLB
    fn tlb_lookup(
        &self,
        vaddr: u64,
        access: AccessType,
        mode: PrivilegeMode,
        csrs: &CsrFile,
    ) -> Option<u64> {
        let vpn = vaddr >> 12;
        let idx = Self::tlb_index(vpn);
        let entry = &self.tlb[idx];

        if !entry.valid {
            return None;
        }

        // Check SATP matches
        let satp = csrs.read(csr::SATP);
        if entry.satp != satp {
            return None;
        }

        // Check VPN matches (accounting for superpage size)
        let page_shift = entry.page_shift as u64;
        let vpn_mask = !((1u64 << (page_shift - 12)) - 1);
        if (entry.vpn & vpn_mask) != (vpn & vpn_mask) {
            return None;
        }

        // Check permissions
        if self
            .check_leaf_permissions(access, mode, entry.pte_flags, csrs)
            .is_err()
        {
            return None;
        }

        // For writes, check that dirty bit was already set (we only cache entries with A set,
        // and we need D for writes)
        if matches!(access, AccessType::Write) && entry.pte_flags & PTE_D == 0 {
            return None; // Force page walk to set D bit
        }

        // Construct physical address
        let offset_mask = (1u64 << page_shift) - 1;
        let phys = (entry.ppn << 12) | (vaddr & offset_mask);
        Some(phys)
    }

    /// Insert an entry into the TLB
    fn tlb_insert(&mut self, vaddr: u64, ppn: u64, page_shift: u8, pte_flags: u64, satp: u64) {
        let vpn = vaddr >> 12;
        let idx = Self::tlb_index(vpn);
        self.tlb[idx] = TlbEntry {
            vpn,
            ppn,
            page_shift,
            pte_flags,
            satp,
            valid: true,
        };
    }

    /// Translate virtual address to physical address.
    /// Returns Ok(physical_addr) or Err(exception_cause).
    /// Supports Sv39 (3-level) and Sv48 (4-level) page table walks.
    /// Sets Accessed and Dirty bits on page table entries as required by the spec.
    pub fn translate(
        &mut self,
        vaddr: u64,
        access: AccessType,
        mode: PrivilegeMode,
        csrs: &CsrFile,
        bus: &mut Bus,
    ) -> Result<u64, u64> {
        let satp = csrs.read(csr::SATP);
        let satp_mode = satp >> 60;

        // If bare mode or M-mode, no translation — but still check PMP
        if satp_mode == 0 || mode == PrivilegeMode::Machine {
            if !csrs.pmp_check(vaddr, 1, access, mode) {
                return Err(self.access_fault(access));
            }
            return Ok(vaddr);
        }

        // TLB lookup
        if let Some(phys) = self.tlb_lookup(vaddr, access, mode, csrs) {
            self.tlb_hits += 1;
            // PMP check still needed on TLB hits
            if !csrs.pmp_check(phys, 1, access, mode) {
                return Err(self.access_fault(access));
            }
            return Ok(phys);
        }
        self.tlb_misses += 1;

        let levels = match satp_mode {
            8 => 3,                // Sv39
            9 => 4,                // Sv48
            10 => 5,               // Sv57
            _ => return Ok(vaddr), // Unsupported mode, treat as bare
        };

        let ppn = satp & 0xFFF_FFFF_FFFF; // 44 bits
        let page_offset = vaddr & 0xFFF;

        // Extract VPN fields (each 9 bits)
        let vpn: [u64; 5] = [
            (vaddr >> 12) & 0x1FF,
            (vaddr >> 21) & 0x1FF,
            (vaddr >> 30) & 0x1FF,
            (vaddr >> 39) & 0x1FF,
            (vaddr >> 48) & 0x1FF,
        ];

        let mut a = ppn << 12;

        for level in (0..levels).rev() {
            let pte_addr = a + vpn[level] * 8;
            let pte = bus.read64(pte_addr);

            if pte & PTE_V == 0 {
                return Err(self.page_fault(access));
            }

            let r = pte & PTE_R;
            let w = pte & PTE_W;
            let x = pte & PTE_X;

            if r == 0 && w == 0 && x == 0 {
                // Pointer to next level
                a = ((pte >> 10) & 0xFFF_FFFF_FFFF) << 12;
                continue;
            }

            // Leaf PTE found

            // Svpbmt: check reserved PBMT encoding (11 = reserved → page fault)
            if pte & PTE_PBMT_MASK == PTE_PBMT_RSVD {
                return Err(self.page_fault(access));
            }

            // Check permissions
            self.check_leaf_permissions(access, mode, pte, csrs)?;

            // Superpage alignment check: lower PPN bits must be zero
            let misaligned = match level {
                4 => ((pte >> 10) & 0xFFFFFFFFF) != 0, // 256 TiB (Sv57 level 4)
                3 => ((pte >> 10) & 0x7FFFFFF) != 0,   // 512 GiB (Sv48 level 3)
                2 => ((pte >> 10) & 0x3FFFF) != 0,     // 1 GiB
                1 => ((pte >> 10) & 0x1FF) != 0,       // 2 MiB
                _ => false,
            };
            if misaligned {
                return Err(self.page_fault(access));
            }

            // Update A/D bits (hardware-managed, as Linux expects)
            let need_a = pte & PTE_A == 0;
            let need_d = matches!(access, AccessType::Write) && pte & PTE_D == 0;
            if need_a || need_d {
                let mut new_pte = pte | PTE_A;
                if need_d {
                    new_pte |= PTE_D;
                }
                bus.write64(pte_addr, new_pte);
            }

            // Construct physical address
            let ppn_pte = (pte >> 10) & 0xFFF_FFFF_FFFF;
            let page_shift = match level {
                4 => 48u8,
                3 => 39,
                2 => 30,
                1 => 21,
                0 => 12,
                _ => unreachable!(),
            };
            let offset_mask = (1u64 << page_shift) - 1;
            let phys = match level {
                4 => (ppn_pte & !0xFFFFFFFFF) << 12 | (vaddr & ((1u64 << 48) - 1)), // 256 TiB
                3 => (ppn_pte & !0x7FFFFFF) << 12 | (vaddr & 0xFF_FFFF_FFFF),       // 512 GiB
                2 => (ppn_pte & !0x3FFFF) << 12 | (vaddr & 0x3FFFFFFF),             // 1 GiB
                1 => (ppn_pte & !0x1FF) << 12 | (vaddr & 0x1FFFFF),                 // 2 MiB
                0 => (ppn_pte << 12) | page_offset,                                 // 4 KiB
                _ => unreachable!(),
            };

            // PMP check on the translated physical address
            if !csrs.pmp_check(phys, 1, access, mode) {
                return Err(self.access_fault(access));
            }

            // Cache in TLB (with updated A/D bits)
            let cached_flags = pte | PTE_A | if need_d { PTE_D } else { 0 };
            let base_ppn = (phys & !offset_mask) >> 12;
            self.tlb_insert(vaddr, base_ppn, page_shift, cached_flags, satp);

            return Ok(phys);
        }

        Err(self.page_fault(access))
    }

    /// Check leaf PTE permissions for given access type and privilege mode.
    fn check_leaf_permissions(
        &self,
        access: AccessType,
        mode: PrivilegeMode,
        pte: u64,
        csrs: &CsrFile,
    ) -> Result<(), u64> {
        let r = pte & PTE_R;
        let w = pte & PTE_W;
        let x = pte & PTE_X;
        let u = pte & PTE_U;

        match access {
            AccessType::Read => {
                let mstatus = csrs.read(csr::MSTATUS);
                let mxr = (mstatus >> 19) & 1;
                if r == 0 && !(mxr == 1 && x != 0) {
                    return Err(self.page_fault(access));
                }
            }
            AccessType::Write => {
                if w == 0 {
                    return Err(self.page_fault(access));
                }
            }
            AccessType::Execute => {
                if x == 0 {
                    return Err(self.page_fault(access));
                }
            }
        }

        // Check U-bit
        match mode {
            PrivilegeMode::User => {
                if u == 0 {
                    return Err(self.page_fault(access));
                }
            }
            PrivilegeMode::Supervisor => {
                if u != 0 {
                    let mstatus = csrs.read(csr::MSTATUS);
                    let sum = (mstatus >> 18) & 1;
                    if sum == 0 {
                        return Err(self.page_fault(access));
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn page_fault(&self, access: AccessType) -> u64 {
        match access {
            AccessType::Execute => 12,
            AccessType::Read => 13,
            AccessType::Write => 15,
        }
    }

    /// Access fault exceptions (distinct from page faults — used for PMP violations)
    fn access_fault(&self, access: AccessType) -> u64 {
        match access {
            AccessType::Execute => 1, // Instruction access fault
            AccessType::Read => 5,    // Load access fault
            AccessType::Write => 7,   // Store/AMO access fault
        }
    }
}
