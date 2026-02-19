/// Device Tree Blob generator for Linux boot
/// Generates a minimal FDT (Flattened Device Tree) that Linux needs
use crate::memory;

const FDT_MAGIC: u32 = 0xD00DFEED;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;

struct DtbBuilder {
    struct_buf: Vec<u8>,
    strings_buf: Vec<u8>,
    mem_rsvmap: Vec<u8>,
}

impl DtbBuilder {
    fn new() -> Self {
        Self {
            struct_buf: Vec::new(),
            strings_buf: Vec::new(),
            mem_rsvmap: Vec::new(),
        }
    }

    fn begin_node(&mut self, name: &str) {
        self.write_u32(FDT_BEGIN_NODE);
        self.write_string(name);
        self.align4();
    }

    fn end_node(&mut self) {
        self.write_u32(FDT_END_NODE);
    }

    fn prop_u32(&mut self, name: &str, val: u32) {
        let name_off = self.add_string(name);
        self.write_u32(FDT_PROP);
        self.write_u32(4); // len
        self.write_u32(name_off);
        self.write_u32(val);
    }

    #[allow(dead_code)]
    fn prop_u64(&mut self, name: &str, val: u64) {
        let name_off = self.add_string(name);
        self.write_u32(FDT_PROP);
        self.write_u32(8);
        self.write_u32(name_off);
        self.write_u32((val >> 32) as u32);
        self.write_u32(val as u32);
    }

    fn prop_str(&mut self, name: &str, val: &str) {
        let name_off = self.add_string(name);
        let data = val.as_bytes();
        self.write_u32(FDT_PROP);
        self.write_u32((data.len() + 1) as u32); // +1 for null terminator
        self.write_u32(name_off);
        self.struct_buf.extend_from_slice(data);
        self.struct_buf.push(0);
        self.align4();
    }

    #[allow(dead_code)]
    fn prop_bytes(&mut self, name: &str, data: &[u8]) {
        let name_off = self.add_string(name);
        self.write_u32(FDT_PROP);
        self.write_u32(data.len() as u32);
        self.write_u32(name_off);
        self.struct_buf.extend_from_slice(data);
        self.align4();
    }

    fn prop_null(&mut self, name: &str) {
        let name_off = self.add_string(name);
        self.write_u32(FDT_PROP);
        self.write_u32(0);
        self.write_u32(name_off);
    }

    fn prop_stringlist(&mut self, name: &str, strings: &[&str]) {
        let name_off = self.add_string(name);
        let mut data = Vec::new();
        for s in strings {
            data.extend_from_slice(s.as_bytes());
            data.push(0);
        }
        self.write_u32(FDT_PROP);
        self.write_u32(data.len() as u32);
        self.write_u32(name_off);
        self.struct_buf.extend_from_slice(&data);
        self.align4();
    }

    fn prop_u32_array(&mut self, name: &str, vals: &[u32]) {
        let name_off = self.add_string(name);
        self.write_u32(FDT_PROP);
        self.write_u32((vals.len() * 4) as u32);
        self.write_u32(name_off);
        for v in vals {
            self.write_u32(*v);
        }
    }

    fn write_u32(&mut self, val: u32) {
        self.struct_buf.extend_from_slice(&val.to_be_bytes());
    }

    fn write_string(&mut self, s: &str) {
        self.struct_buf.extend_from_slice(s.as_bytes());
        self.struct_buf.push(0);
    }

    fn align4(&mut self) {
        while !self.struct_buf.len().is_multiple_of(4) {
            self.struct_buf.push(0);
        }
    }

    fn add_string(&mut self, s: &str) -> u32 {
        // Check if string already exists
        let needle = s.as_bytes();
        let slen = needle.len();
        if let Some(pos) = self
            .strings_buf
            .windows(slen + 1)
            .position(|w| w[..slen] == *needle && w[slen] == 0)
        {
            return pos as u32;
        }
        let off = self.strings_buf.len() as u32;
        self.strings_buf.extend_from_slice(needle);
        self.strings_buf.push(0);
        off
    }

    fn finish(mut self) -> Vec<u8> {
        self.struct_buf.extend_from_slice(&FDT_END.to_be_bytes());

        // Memory reservation map (empty — 2 × u64 zeros)
        self.mem_rsvmap = vec![0u8; 16];

        let header_size = 40u32;
        let off_mem_rsvmap = header_size;
        let off_dt_struct = off_mem_rsvmap + self.mem_rsvmap.len() as u32;
        let off_dt_strings = off_dt_struct + self.struct_buf.len() as u32;
        let total_size = off_dt_strings + self.strings_buf.len() as u32;

        let mut dtb = Vec::with_capacity(total_size as usize);
        // Header
        dtb.extend_from_slice(&FDT_MAGIC.to_be_bytes());
        dtb.extend_from_slice(&total_size.to_be_bytes());
        dtb.extend_from_slice(&off_dt_struct.to_be_bytes());
        dtb.extend_from_slice(&off_dt_strings.to_be_bytes());
        dtb.extend_from_slice(&off_mem_rsvmap.to_be_bytes());
        dtb.extend_from_slice(&17u32.to_be_bytes()); // version
        dtb.extend_from_slice(&16u32.to_be_bytes()); // last_comp_version
        dtb.extend_from_slice(&0u32.to_be_bytes()); // boot_cpuid_phys
        dtb.extend_from_slice(&(self.strings_buf.len() as u32).to_be_bytes());
        dtb.extend_from_slice(&(self.struct_buf.len() as u32).to_be_bytes());

        dtb.extend_from_slice(&self.mem_rsvmap);
        dtb.extend_from_slice(&self.struct_buf);
        dtb.extend_from_slice(&self.strings_buf);

        dtb
    }
}

/// Generate a Device Tree Blob for Linux boot
/// `initrd_info` is an optional (start, end) pair of physical addresses for the initrd.
pub fn generate_dtb(
    ram_size: u64,
    cmdline: &str,
    has_virtio_blk: bool,
    initrd_info: Option<(u64, u64)>,
) -> Vec<u8> {
    let mut b = DtbBuilder::new();

    // Root node
    b.begin_node("");
    b.prop_str("compatible", "microvm,riscv-virt");
    b.prop_str("model", "microvm RISC-V Virtual Machine");
    b.prop_u32("#address-cells", 2);
    b.prop_u32("#size-cells", 2);

    // Chosen
    b.begin_node("chosen");
    b.prop_str("bootargs", cmdline);
    b.prop_str("stdout-path", "/soc/uart@10000000");
    if let Some((start, end)) = initrd_info {
        b.prop_u64("linux,initrd-start", start);
        b.prop_u64("linux,initrd-end", end);
    }
    b.end_node();

    // Memory
    b.begin_node(&format!("memory@{:x}", memory::DRAM_BASE));
    b.prop_str("device_type", "memory");
    b.prop_u32_array(
        "reg",
        &[
            (memory::DRAM_BASE >> 32) as u32,
            memory::DRAM_BASE as u32,
            (ram_size >> 32) as u32,
            ram_size as u32,
        ],
    );
    b.end_node();

    // CPUs
    b.begin_node("cpus");
    b.prop_u32("#address-cells", 1);
    b.prop_u32("#size-cells", 0);
    b.prop_u32("timebase-frequency", 10_000_000);

    b.begin_node("cpu@0");
    b.prop_str("device_type", "cpu");
    b.prop_u32("reg", 0);
    b.prop_str("compatible", "riscv");
    b.prop_str(
        "riscv,isa",
        "rv64imacsu_zicsr_zifencei_zicbom_zicboz_zicbop_zicond_zihintpause_zawrs_zba_zbb_zbs_zbc_sstc_zicntr_svinval",
    );
    b.prop_str("riscv,isa-base", "rv64i");
    b.prop_str("mmu-type", "riscv,sv48");
    b.prop_str("status", "okay");
    // ISA extensions as stringlist for newer kernels (Linux 6.2+)
    b.prop_stringlist(
        "riscv,isa-extensions",
        &[
            "i",
            "m",
            "a",
            "c",
            "zicsr",
            "zifencei",
            "zicbom",
            "zicboz",
            "zicbop",
            "zicond",
            "zihintpause",
            "zawrs",
            "zba",
            "zbb",
            "zbs",
            "zbc",
            "sstc",
            "zicntr",
            "svinval",
        ],
    );
    // Cache block size for Zicbom (Linux probes this; 64 is standard)
    b.prop_u32("riscv,cbom-block-size", 64);
    b.prop_u32("riscv,cboz-block-size", 64);

    b.begin_node("interrupt-controller");
    b.prop_u32("#interrupt-cells", 1);
    b.prop_null("interrupt-controller");
    b.prop_str("compatible", "riscv,cpu-intc");
    b.prop_u32("phandle", 1);
    b.end_node(); // interrupt-controller

    b.end_node(); // cpu@0
    b.end_node(); // cpus

    // SOC
    b.begin_node("soc");
    b.prop_str("compatible", "simple-bus");
    b.prop_u32("#address-cells", 2);
    b.prop_u32("#size-cells", 2);
    b.prop_null("ranges");

    // CLINT
    b.begin_node(&format!("clint@{:x}", memory::CLINT_BASE));
    b.prop_str("compatible", "riscv,clint0");
    b.prop_u32_array(
        "reg",
        &[
            (memory::CLINT_BASE >> 32) as u32,
            memory::CLINT_BASE as u32,
            0,
            memory::CLINT_SIZE as u32,
        ],
    );
    b.prop_u32_array("interrupts-extended", &[1, 3, 1, 7]);
    b.end_node();

    // PLIC
    b.begin_node(&format!("plic@{:x}", memory::PLIC_BASE));
    b.prop_str("compatible", "riscv,plic0");
    b.prop_u32_array(
        "reg",
        &[
            (memory::PLIC_BASE >> 32) as u32,
            memory::PLIC_BASE as u32,
            0,
            memory::PLIC_SIZE as u32,
        ],
    );
    b.prop_u32("#interrupt-cells", 1);
    b.prop_null("interrupt-controller");
    b.prop_u32_array("interrupts-extended", &[1, 9, 1, 11]);
    b.prop_u32("riscv,ndev", 31);
    b.prop_u32("phandle", 2);
    b.end_node();

    // UART
    b.begin_node(&format!("uart@{:x}", memory::UART_BASE));
    b.prop_str("compatible", "ns16550a");
    b.prop_u32_array(
        "reg",
        &[
            (memory::UART_BASE >> 32) as u32,
            memory::UART_BASE as u32,
            0,
            memory::UART_SIZE as u32,
        ],
    );
    b.prop_u32("clock-frequency", 3686400);
    b.prop_u32_array("interrupts", &[10]);
    b.prop_u32("interrupt-parent", 2);
    b.end_node();

    // VirtIO MMIO Block Device
    if has_virtio_blk {
        b.begin_node(&format!("virtio_mmio@{:x}", memory::VIRTIO0_BASE));
        b.prop_str("compatible", "virtio,mmio");
        b.prop_u32_array(
            "reg",
            &[
                (memory::VIRTIO0_BASE >> 32) as u32,
                memory::VIRTIO0_BASE as u32,
                0,
                memory::VIRTIO0_SIZE as u32,
            ],
        );
        b.prop_u32_array("interrupts", &[8]);
        b.prop_u32("interrupt-parent", 2);
        b.end_node();
    }

    // VirtIO MMIO Console Device (always present — provides hvc0)
    b.begin_node(&format!("virtio_mmio@{:x}", memory::VIRTIO1_BASE));
    b.prop_str("compatible", "virtio,mmio");
    b.prop_u32_array(
        "reg",
        &[
            (memory::VIRTIO1_BASE >> 32) as u32,
            memory::VIRTIO1_BASE as u32,
            0,
            memory::VIRTIO1_SIZE as u32,
        ],
    );
    b.prop_u32_array("interrupts", &[9]);
    b.prop_u32("interrupt-parent", 2);
    b.end_node();

    b.end_node(); // soc
    b.end_node(); // root

    b.finish()
}
