use super::csr::{self, CsrFile};
use super::PrivilegeMode;
use crate::memory::Bus;

#[derive(Debug, Clone, Copy)]
pub enum AccessType {
    Read,
    Write,
    Execute,
}

/// Sv39 MMU — 3-level page table translation
pub struct Mmu;

impl Mmu {
    pub fn new() -> Self {
        Self
    }

    /// Translate virtual address to physical address.
    /// Returns Ok(physical_addr) or Err(exception_cause).
    pub fn translate(
        &self,
        vaddr: u64,
        access: AccessType,
        mode: PrivilegeMode,
        csrs: &CsrFile,
        bus: &mut Bus,
    ) -> Result<u64, u64> {
        let satp = csrs.read(csr::SATP);
        let satp_mode = satp >> 60;

        // If bare mode or M-mode, no translation
        if satp_mode == 0 || mode == PrivilegeMode::Machine {
            return Ok(vaddr);
        }

        // Sv39
        if satp_mode != 8 {
            return Ok(vaddr); // Only Sv39 supported
        }

        let ppn = satp & 0xFFF_FFFF_FFFF; // 44 bits
        let vpn = [
            (vaddr >> 12) & 0x1FF,
            (vaddr >> 21) & 0x1FF,
            (vaddr >> 30) & 0x1FF,
        ];
        let page_offset = vaddr & 0xFFF;

        let mut a = ppn << 12;

        for level in (0..3).rev() {
            let pte_addr = a + vpn[level] * 8;
            let pte = bus.read64(pte_addr);

            let v = pte & 1;
            if v == 0 {
                return Err(self.page_fault(access));
            }

            let r = (pte >> 1) & 1;
            let w = (pte >> 2) & 1;
            let x = (pte >> 3) & 1;
            let u = (pte >> 4) & 1;

            if r == 0 && w == 0 && x == 0 {
                // Pointer to next level
                a = ((pte >> 10) & 0xFFF_FFFF_FFFF) << 12;
                continue;
            }

            // Leaf PTE found
            // Check permissions
            match access {
                AccessType::Read => {
                    let mstatus = csrs.read(csr::MSTATUS);
                    let mxr = (mstatus >> 19) & 1;
                    if r == 0 && !(mxr == 1 && x == 1) {
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
                    if u == 1 {
                        let mstatus = csrs.read(csr::MSTATUS);
                        let sum = (mstatus >> 18) & 1;
                        if sum == 0 {
                            return Err(self.page_fault(access));
                        }
                    }
                }
                _ => {}
            }

            // Construct physical address
            let ppn_pte = (pte >> 10) & 0xFFF_FFFF_FFFF;
            let phys = match level {
                2 => {
                    // 1 GiB superpage
                    (ppn_pte & !0x3FFFF) << 12 | (vaddr & 0x3FFFFFFF)
                }
                1 => {
                    // 2 MiB superpage
                    (ppn_pte & !0x1FF) << 12 | (vaddr & 0x1FFFFF)
                }
                0 => {
                    // 4 KiB page
                    (ppn_pte << 12) | page_offset
                }
                _ => unreachable!(),
            };

            return Ok(phys);
        }

        Err(self.page_fault(access))
    }

    fn page_fault(&self, access: AccessType) -> u64 {
        match access {
            AccessType::Execute => 12,
            AccessType::Read => 13,
            AccessType::Write => 15,
        }
    }
}
