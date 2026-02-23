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

/// Decompile a DTB (Flattened Device Tree) into human-readable DTS format.
/// This is useful for debugging boot issues — equivalent to `dtc -I dtb -O dts`.
pub fn dtb_to_dts(dtb: &[u8]) -> String {
    if dtb.len() < 40 {
        return "/* invalid DTB: too short */\n".to_string();
    }

    let magic = u32::from_be_bytes([dtb[0], dtb[1], dtb[2], dtb[3]]);
    if magic != FDT_MAGIC {
        return format!("/* invalid DTB magic: {:#x} */\n", magic);
    }

    let off_dt_struct = u32::from_be_bytes([dtb[8], dtb[9], dtb[10], dtb[11]]) as usize;
    let off_dt_strings = u32::from_be_bytes([dtb[12], dtb[13], dtb[14], dtb[15]]) as usize;

    let mut out = String::from("/dts-v1/;\n\n");
    let mut pos = off_dt_struct;
    let mut depth: usize = 0;

    loop {
        if pos + 4 > dtb.len() {
            break;
        }
        let token = u32::from_be_bytes([dtb[pos], dtb[pos + 1], dtb[pos + 2], dtb[pos + 3]]);
        pos += 4;

        match token {
            FDT_BEGIN_NODE => {
                let name = read_cstr(dtb, pos);
                pos += name.len() + 1;
                pos = align4_pos(pos);

                let indent = "\t".repeat(depth);
                if name.is_empty() {
                    out.push_str(&format!("{indent}/ {{\n"));
                } else {
                    out.push_str(&format!("{indent}{name} {{\n"));
                }
                depth += 1;
            }
            FDT_END_NODE => {
                depth = depth.saturating_sub(1);
                let indent = "\t".repeat(depth);
                out.push_str(&format!("{indent}}};\n"));
            }
            FDT_PROP => {
                if pos + 8 > dtb.len() {
                    break;
                }
                let len = u32::from_be_bytes([dtb[pos], dtb[pos + 1], dtb[pos + 2], dtb[pos + 3]])
                    as usize;
                let name_off =
                    u32::from_be_bytes([dtb[pos + 4], dtb[pos + 5], dtb[pos + 6], dtb[pos + 7]])
                        as usize;
                pos += 8;

                let prop_name = read_cstr(dtb, off_dt_strings + name_off);
                let data = if pos + len <= dtb.len() {
                    &dtb[pos..pos + len]
                } else {
                    &[]
                };
                pos += len;
                pos = align4_pos(pos);

                let indent = "\t".repeat(depth);
                if len == 0 {
                    out.push_str(&format!("{indent}{prop_name};\n"));
                } else {
                    let val = format_prop_value(&prop_name, data);
                    out.push_str(&format!("{indent}{prop_name} = {val};\n"));
                }
            }
            FDT_END => break,
            _ => {
                // Skip NOP or unknown tokens
            }
        }
    }

    out
}

/// Read a null-terminated string from a byte slice at the given offset.
fn read_cstr(data: &[u8], offset: usize) -> String {
    let mut end = offset;
    while end < data.len() && data[end] != 0 {
        end += 1;
    }
    String::from_utf8_lossy(&data[offset..end]).to_string()
}

/// Align position up to 4-byte boundary.
fn align4_pos(pos: usize) -> usize {
    (pos + 3) & !3
}

/// Format a property value for DTS output.
/// Heuristics: if data looks like a null-terminated string (or stringlist), show as string.
/// If length is a multiple of 4, show as <cell array>. Otherwise hex bytes.
fn format_prop_value(name: &str, data: &[u8]) -> String {
    // Known string properties
    let string_props = [
        "compatible",
        "model",
        "device_type",
        "bootargs",
        "stdout-path",
        "riscv,isa",
        "riscv,isa-base",
        "mmu-type",
        "status",
    ];

    // Check if it's a stringlist (multiple null-terminated strings)
    if is_stringlist(data) && data.len() > 1 {
        let strings: Vec<&str> = data[..data.len() - 1] // strip trailing null
            .split(|&b| b == 0)
            .filter_map(|s| std::str::from_utf8(s).ok())
            .collect();
        if !strings.is_empty()
            && (string_props.contains(&name) || strings.iter().all(|s| is_printable_str(s)))
        {
            let quoted: Vec<String> = strings.iter().map(|s| format!("\"{s}\"")).collect();
            return quoted.join(", ");
        }
    }

    // Single string
    if data.len() > 1 && data[data.len() - 1] == 0 {
        if let Ok(s) = std::str::from_utf8(&data[..data.len() - 1]) {
            if is_printable_str(s) {
                return format!("\"{s}\"");
            }
        }
    }

    // u32 array
    if data.len().is_multiple_of(4) && !data.is_empty() {
        let cells: Vec<String> = data
            .chunks(4)
            .map(|c| {
                let v = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                format!("{:#x}", v)
            })
            .collect();
        return format!("<{}>", cells.join(" "));
    }

    // Raw bytes
    let hex: Vec<String> = data.iter().map(|b| format!("{:02x}", b)).collect();
    format!("[{}]", hex.join(" "))
}

/// Check if data is a valid stringlist (one or more null-terminated printable strings).
fn is_stringlist(data: &[u8]) -> bool {
    if data.is_empty() || data[data.len() - 1] != 0 {
        return false;
    }
    let parts: Vec<&[u8]> = data[..data.len() - 1].split(|&b| b == 0).collect();
    if parts.is_empty() {
        return false;
    }
    parts.iter().all(|p| {
        !p.is_empty()
            && std::str::from_utf8(p)
                .map(is_printable_str)
                .unwrap_or(false)
    })
}

/// Check if a string contains only printable ASCII characters.
fn is_printable_str(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}

/// Generate a Device Tree Blob for Linux boot
/// `initrd_info` is an optional (start, end) pair of physical addresses for the initrd.
/// `num_harts` specifies the number of CPU harts (default 1).
pub fn generate_dtb(
    ram_size: u64,
    cmdline: &str,
    has_virtio_blk: bool,
    initrd_info: Option<(u64, u64)>,
) -> Vec<u8> {
    generate_dtb_smp(ram_size, cmdline, has_virtio_blk, initrd_info, 1)
}

/// Generate a Device Tree Blob with SMP support
pub fn generate_dtb_smp(
    ram_size: u64,
    cmdline: &str,
    has_virtio_blk: bool,
    initrd_info: Option<(u64, u64)>,
    num_harts: usize,
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

    // Phandle allocation: intc phandles start at 1 (one per hart)
    // PLIC phandle = num_harts + 1, syscon phandle = num_harts + 2
    let plic_phandle = num_harts as u32 + 1;
    let syscon_phandle = num_harts as u32 + 2;

    let isa_str = "rv64imafdcvsu_zicsr_zifencei_zicbom_zicboz_zicbop_zicond_zihintpause_zawrs_zacas_zabha_zfa_zimop_zcmop_zba_zbb_zbs_zbc_zbkb_zbkc_zbkx_zknd_zkne_zknh_zkr_zve32f_zve64f_zve64d_zvbb_zvkg_zvkned_zvknhb_zvksed_zvksh_zvl128b_sstc_zicntr_zihpm_svinval_svnapot_svpbmt_svadu_smstateen_ssstateen_sscofpmf_smcntrpmf_sdtrig";
    let isa_extensions: &[&str] = &[
        "i",
        "m",
        "a",
        "f",
        "d",
        "c",
        "zicsr",
        "zifencei",
        "zicbom",
        "zicboz",
        "zicbop",
        "zicond",
        "zihintpause",
        "zawrs",
        "zacas",
        "zabha",
        "zba",
        "zbb",
        "zbs",
        "zbc",
        "zbkb",
        "zbkc",
        "zbkx",
        "zknd",
        "zkne",
        "zknh",
        "zkr",
        "zfa",
        "zimop",
        "zcmop",
        "zcb",
        "v",
        "zve32f",
        "zve64f",
        "zve64d",
        "zvbb",
        "zvl128b",
        "sstc",
        "zicntr",
        "zihpm",
        "svinval",
        "svnapot",
        "svpbmt",
        "svadu",
        "smstateen",
        "ssstateen",
        "sscofpmf",
        "smcntrpmf",
        "sdtrig",
    ];

    for hart in 0..num_harts {
        let intc_phandle = hart as u32 + 1;
        b.begin_node(&format!("cpu@{hart}"));
        b.prop_str("device_type", "cpu");
        b.prop_u32("reg", hart as u32);
        b.prop_str("compatible", "riscv");
        b.prop_str("riscv,isa", isa_str);
        b.prop_str("riscv,isa-base", "rv64i");
        b.prop_str("mmu-type", "riscv,sv57");
        b.prop_str("status", "okay");
        b.prop_stringlist("riscv,isa-extensions", isa_extensions);
        b.prop_u32("riscv,cbom-block-size", 64);
        b.prop_u32("riscv,cboz-block-size", 64);

        b.begin_node("interrupt-controller");
        b.prop_u32("#interrupt-cells", 1);
        b.prop_null("interrupt-controller");
        b.prop_str("compatible", "riscv,cpu-intc");
        b.prop_u32("phandle", intc_phandle);
        b.end_node(); // interrupt-controller

        b.end_node(); // cpu@N
    }
    b.end_node(); // cpus

    // SOC
    b.begin_node("soc");
    b.prop_str("compatible", "simple-bus");
    b.prop_u32("#address-cells", 2);
    b.prop_u32("#size-cells", 2);
    b.prop_null("ranges");

    // CLINT — interrupts-extended lists [intc_phandle, 3(MSIP), intc_phandle, 7(MTIP)] per hart
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
    {
        let mut clint_ext = Vec::with_capacity(num_harts * 4);
        for hart in 0..num_harts {
            let phandle = hart as u32 + 1;
            clint_ext.extend_from_slice(&[phandle, 3, phandle, 7]); // MSIP=3, MTIP=7
        }
        b.prop_u32_array("interrupts-extended", &clint_ext);
    }
    b.end_node();

    // PLIC — interrupts-extended: [intc, 11(MEIP), intc, 9(SEIP)] per hart
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
    {
        let mut plic_ext = Vec::with_capacity(num_harts * 4);
        for hart in 0..num_harts {
            let phandle = hart as u32 + 1;
            plic_ext.extend_from_slice(&[phandle, 11, phandle, 9]); // MEIP=11, SEIP=9
        }
        b.prop_u32_array("interrupts-extended", &plic_ext);
    }
    b.prop_u32("riscv,ndev", 95);
    b.prop_u32("phandle", plic_phandle);
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
    b.prop_u32("reg-shift", 0); // byte-spaced registers
    b.prop_u32("reg-io-width", 1); // 8-bit I/O
    b.prop_u32("fifo-size", 16); // 16550A FIFO depth
    b.prop_u32_array("interrupts", &[10]);
    b.prop_u32("interrupt-parent", plic_phandle);
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
        b.prop_u32("interrupt-parent", plic_phandle);
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
    b.prop_u32("interrupt-parent", plic_phandle);
    b.end_node();

    // VirtIO MMIO RNG Device (provides entropy to guest)
    b.begin_node(&format!("virtio_mmio@{:x}", memory::VIRTIO2_BASE));
    b.prop_str("compatible", "virtio,mmio");
    b.prop_u32_array(
        "reg",
        &[
            (memory::VIRTIO2_BASE >> 32) as u32,
            memory::VIRTIO2_BASE as u32,
            0,
            memory::VIRTIO2_SIZE as u32,
        ],
    );
    b.prop_u32_array("interrupts", &[11]);
    b.prop_u32("interrupt-parent", plic_phandle);
    b.end_node();

    // VirtIO MMIO Network Device
    b.begin_node(&format!("virtio_mmio@{:x}", memory::VIRTIO3_BASE));
    b.prop_str("compatible", "virtio,mmio");
    b.prop_u32_array(
        "reg",
        &[
            (memory::VIRTIO3_BASE >> 32) as u32,
            memory::VIRTIO3_BASE as u32,
            0,
            memory::VIRTIO3_SIZE as u32,
        ],
    );
    b.prop_u32_array("interrupts", &[12]);
    b.prop_u32("interrupt-parent", plic_phandle);
    b.end_node();

    // Syscon (poweroff/reboot)
    b.begin_node(&format!("syscon@{:x}", memory::SYSCON_BASE));
    b.prop_str("compatible", "syscon");
    b.prop_u32_array(
        "reg",
        &[
            (memory::SYSCON_BASE >> 32) as u32,
            memory::SYSCON_BASE as u32,
            0,
            memory::SYSCON_SIZE as u32,
        ],
    );
    b.prop_u32("phandle", syscon_phandle);
    b.end_node();

    b.begin_node("poweroff");
    b.prop_str("compatible", "syscon-poweroff");
    b.prop_u32("regmap", syscon_phandle);
    b.prop_u32("offset", 0);
    b.prop_u32("value", 0x5555);
    b.end_node();

    b.begin_node("reboot");
    b.prop_str("compatible", "syscon-reboot");
    b.prop_u32("regmap", syscon_phandle);
    b.prop_u32("offset", 0);
    b.prop_u32("value", 0x7777);
    b.end_node();

    // Goldfish RTC (real-time clock)
    b.begin_node(&format!("rtc@{:x}", memory::RTC_BASE));
    b.prop_str("compatible", "google,goldfish-rtc");
    b.prop_u32_array(
        "reg",
        &[
            (memory::RTC_BASE >> 32) as u32,
            memory::RTC_BASE as u32,
            0,
            memory::RTC_SIZE as u32,
        ],
    );
    b.prop_u32_array("interrupts", &[13]); // PLIC IRQ 13
    b.prop_u32("interrupt-parent", plic_phandle);
    b.end_node();

    b.end_node(); // soc
    b.end_node(); // root

    b.finish()
}
