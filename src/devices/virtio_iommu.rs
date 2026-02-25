// VirtIO IOMMU Device (type 23)
//
// Implements I/O address translation and protection for DMA.
// Reference: VirtIO spec v1.3, section 5.14 (IOMMU device)
//
// Features:
// - Domain-based address translation (identity map by default)
// - Attach/detach endpoints to domains
// - Map/unmap I/O virtual address ranges
// - Probe endpoint capabilities
// - Two virtqueues: requestq (commands) + eventq (fault notifications)

// VirtIO MMIO register offsets (same transport as other VirtIO devices)
const MAGIC_VALUE: u64 = 0x000;
const VERSION: u64 = 0x004;
const DEVICE_ID: u64 = 0x008;
const VENDOR_ID: u64 = 0x00C;
const DEVICE_FEATURES: u64 = 0x010;
const DEVICE_FEATURES_SEL: u64 = 0x014;
const DRIVER_FEATURES: u64 = 0x020;
const DRIVER_FEATURES_SEL: u64 = 0x024;
const QUEUE_SEL: u64 = 0x030;
const QUEUE_NUM_MAX: u64 = 0x034;
const QUEUE_NUM: u64 = 0x038;
const QUEUE_READY: u64 = 0x044;
const QUEUE_NOTIFY: u64 = 0x050;
const INTERRUPT_STATUS: u64 = 0x060;
const INTERRUPT_ACK: u64 = 0x064;
const STATUS: u64 = 0x070;
const QUEUE_DESC_LOW: u64 = 0x080;
const QUEUE_DESC_HIGH: u64 = 0x084;
const QUEUE_AVAIL_LOW: u64 = 0x090;
const QUEUE_AVAIL_HIGH: u64 = 0x094;
const QUEUE_USED_LOW: u64 = 0x0A0;
const QUEUE_USED_HIGH: u64 = 0x0A4;
const CONFIG_GENERATION: u64 = 0x0FC;
const CONFIG_BASE: u64 = 0x100;

// VirtIO IOMMU request types
const VIRTIO_IOMMU_T_ATTACH: u8 = 1;
const VIRTIO_IOMMU_T_DETACH: u8 = 2;
const VIRTIO_IOMMU_T_MAP: u8 = 3;
const VIRTIO_IOMMU_T_UNMAP: u8 = 4;
const VIRTIO_IOMMU_T_PROBE: u8 = 5;

// VirtIO IOMMU status codes
const VIRTIO_IOMMU_S_OK: u8 = 0;
const VIRTIO_IOMMU_S_IOERR: u8 = 1;
const VIRTIO_IOMMU_S_UNSUPP: u8 = 2;
#[allow(dead_code)]
const VIRTIO_IOMMU_S_DEVERR: u8 = 3;
const VIRTIO_IOMMU_S_INVAL: u8 = 4;
const VIRTIO_IOMMU_S_RANGE: u8 = 5;
const VIRTIO_IOMMU_S_NOENT: u8 = 6;
#[allow(dead_code)]
const VIRTIO_IOMMU_S_FAULT: u8 = 7;
#[allow(dead_code)]
const VIRTIO_IOMMU_S_NOMEM: u8 = 8;

// VirtIO IOMMU map flags
const VIRTIO_IOMMU_MAP_F_READ: u32 = 1;
const VIRTIO_IOMMU_MAP_F_WRITE: u32 = 2;
#[allow(dead_code)]
const VIRTIO_IOMMU_MAP_F_MMIO: u32 = 4;

// VirtIO IOMMU feature bits
const VIRTIO_IOMMU_F_INPUT_RANGE: u64 = 1 << 0;
const VIRTIO_IOMMU_F_DOMAIN_RANGE: u64 = 1 << 1;
const VIRTIO_IOMMU_F_MAP_UNMAP: u64 = 1 << 2;
const VIRTIO_IOMMU_F_BYPASS: u64 = 1 << 3;
const VIRTIO_IOMMU_F_PROBE: u64 = 1 << 4;

// Probe property types
const VIRTIO_IOMMU_PROBE_T_NONE: u16 = 0;
const VIRTIO_IOMMU_PROBE_T_RESV_MEM: u16 = 1;

// Reserved memory subtypes
const VIRTIO_IOMMU_RESV_MEM_T_RESERVED: u8 = 0;
const VIRTIO_IOMMU_RESV_MEM_T_MSI: u8 = 1;

/// An I/O virtual address mapping within a domain
#[derive(Debug, Clone)]
struct IovaMapping {
    /// I/O virtual address (start)
    virt_start: u64,
    /// Physical address (start)
    phys_start: u64,
    /// Size in bytes
    size: u64,
    /// Access flags (read/write/mmio)
    flags: u32,
}

/// A domain groups endpoints and their shared address space
#[derive(Debug, Clone)]
struct Domain {
    /// Domain ID
    id: u32,
    /// Attached endpoint IDs
    endpoints: Vec<u32>,
    /// IOVA → physical mappings
    mappings: Vec<IovaMapping>,
}

/// Virtqueue state
#[derive(Debug, Clone, Default)]
struct Virtqueue {
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
    num: u32,
    ready: bool,
    last_avail_idx: u16,
}

/// VirtIO IOMMU device
pub struct VirtioIommu {
    // Transport state
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    queue_sel: u32,
    queues: [Virtqueue; 2], // 0=requestq, 1=eventq
    status: u32,
    interrupt_status: u32,

    // IOMMU state
    domains: Vec<Domain>,
    /// Endpoint → domain_id mapping
    endpoint_domain: Vec<(u32, u32)>,

    // Config space
    /// Page size mask (supported page sizes, default 4K = 0xFFFFF000)
    page_size_mask: u64,
    /// Input range start
    input_range_start: u64,
    /// Input range end (inclusive)
    input_range_end: u64,
    /// Domain range start
    domain_range_start: u32,
    /// Domain range end
    domain_range_end: u32,
    /// Probe buffer size
    probe_size: u32,
}

impl Default for VirtioIommu {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioIommu {
    pub fn new() -> Self {
        Self {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            queues: [Virtqueue::default(), Virtqueue::default()],
            status: 0,
            interrupt_status: 0,
            domains: Vec::new(),
            endpoint_domain: Vec::new(),
            page_size_mask: 0xFFFF_FFFF_FFFF_F000, // 4K pages and above
            input_range_start: 0,
            input_range_end: u64::MAX,
            domain_range_start: 0,
            domain_range_end: u32::MAX,
            probe_size: 64, // bytes available for probe response
        }
    }

    /// Get the device feature bits
    fn device_features(&self) -> u64 {
        VIRTIO_IOMMU_F_INPUT_RANGE
            | VIRTIO_IOMMU_F_DOMAIN_RANGE
            | VIRTIO_IOMMU_F_MAP_UNMAP
            | VIRTIO_IOMMU_F_BYPASS
            | VIRTIO_IOMMU_F_PROBE
    }

    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => 0x74726976,
            VERSION => 2,
            DEVICE_ID => 23,         // IOMMU
            VENDOR_ID => 0x554D4551, // "QEMU"
            DEVICE_FEATURES => {
                let features = self.device_features();
                if self.device_features_sel == 0 {
                    features as u32
                } else if self.device_features_sel == 1 {
                    (features >> 32) as u32
                } else {
                    0
                }
            }
            QUEUE_NUM_MAX => 256,
            QUEUE_READY => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].ready as u32
                } else {
                    0
                }
            }
            INTERRUPT_STATUS => self.interrupt_status,
            STATUS => self.status,
            CONFIG_GENERATION => 0,
            // Config space: virtio_iommu_config
            // offset 0x100: page_size_mask (u64)
            // offset 0x108: input_range.start (u64)
            // offset 0x110: input_range.end (u64)
            // offset 0x118: domain_range.start (u32)
            // offset 0x11C: domain_range.end (u32)
            // offset 0x120: probe_size (u32)
            off if off >= CONFIG_BASE => {
                let cfg_off = off - CONFIG_BASE;
                match cfg_off {
                    0x00 => self.page_size_mask as u32,
                    0x04 => (self.page_size_mask >> 32) as u32,
                    0x08 => self.input_range_start as u32,
                    0x0C => (self.input_range_start >> 32) as u32,
                    0x10 => self.input_range_end as u32,
                    0x14 => (self.input_range_end >> 32) as u32,
                    0x18 => self.domain_range_start,
                    0x1C => self.domain_range_end,
                    0x20 => self.probe_size,
                    _ => 0,
                }
            }
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        match offset {
            DEVICE_FEATURES_SEL => self.device_features_sel = val as u32,
            DRIVER_FEATURES => {
                if self.driver_features_sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                } else if self.driver_features_sel == 1 {
                    self.driver_features = (self.driver_features & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            DRIVER_FEATURES_SEL => self.driver_features_sel = val as u32,
            QUEUE_SEL => self.queue_sel = val as u32,
            QUEUE_NUM => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].num = val as u32;
                }
            }
            QUEUE_READY => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].ready = val != 0;
                }
            }
            QUEUE_NOTIFY => {
                // Queue notification — processed by VM loop calling process_requests
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !(val as u32);
            }
            STATUS => {
                self.status = val as u32;
                if self.status == 0 {
                    // Device reset
                    self.reset();
                }
            }
            QUEUE_DESC_LOW => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].desc_addr =
                        (self.queues[q].desc_addr & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            QUEUE_DESC_HIGH => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].desc_addr = (self.queues[q].desc_addr & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            QUEUE_AVAIL_LOW => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].avail_addr =
                        (self.queues[q].avail_addr & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            QUEUE_AVAIL_HIGH => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].avail_addr = (self.queues[q].avail_addr & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            QUEUE_USED_LOW => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].used_addr =
                        (self.queues[q].used_addr & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF);
                }
            }
            QUEUE_USED_HIGH => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].used_addr = (self.queues[q].used_addr & 0x0000_0000_FFFF_FFFF)
                        | ((val & 0xFFFF_FFFF) << 32);
                }
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.driver_features = 0;
        self.driver_features_sel = 0;
        self.device_features_sel = 0;
        self.queue_sel = 0;
        self.queues = [Virtqueue::default(), Virtqueue::default()];
        self.status = 0;
        self.interrupt_status = 0;
        self.domains.clear();
        self.endpoint_domain.clear();
    }

    pub fn has_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Process pending requests from the requestq virtqueue
    pub fn process_requests(&mut self, ram: &mut [u8]) {
        if !self.queues[0].ready {
            return;
        }

        let q = &self.queues[0];
        let desc_addr = q.desc_addr as usize;
        let avail_addr = q.avail_addr as usize;
        let used_addr = q.used_addr as usize;
        let queue_size = q.num as usize;
        if queue_size == 0 || desc_addr == 0 || avail_addr == 0 || used_addr == 0 {
            return;
        }

        // DRAM_BASE offset
        let dram_base = 0x8000_0000usize;
        let desc_off = desc_addr.wrapping_sub(dram_base);
        let avail_off = avail_addr.wrapping_sub(dram_base);
        let used_off = used_addr.wrapping_sub(dram_base);

        // Read avail index
        let avail_idx = if avail_off + 3 < ram.len() {
            u16::from_le_bytes([ram[avail_off + 2], ram[avail_off + 3]])
        } else {
            return;
        };

        let mut last_avail = self.queues[0].last_avail_idx;
        let mut used_count = 0u16;

        while last_avail != avail_idx {
            let ring_idx = (last_avail as usize) % queue_size;
            let desc_entry_off = avail_off + 4 + ring_idx * 2;
            if desc_entry_off + 1 >= ram.len() {
                break;
            }
            let head = u16::from_le_bytes([ram[desc_entry_off], ram[desc_entry_off + 1]]) as usize;

            // Read descriptor chain
            let (req_data, resp_desc_idx) =
                self.read_request_chain(ram, desc_off, head, queue_size, dram_base);

            // Process the request
            let (status, resp_data) = if req_data.is_empty() {
                (VIRTIO_IOMMU_S_IOERR, Vec::new())
            } else {
                self.handle_request(&req_data)
            };

            // Write response
            let written = self.write_response(
                ram,
                desc_off,
                resp_desc_idx,
                queue_size,
                dram_base,
                status,
                &resp_data,
            );

            // Update used ring
            let used_idx_off = used_off + 2;
            let cur_used = if used_idx_off + 1 < ram.len() {
                u16::from_le_bytes([ram[used_idx_off], ram[used_idx_off + 1]])
            } else {
                0
            };
            let used_ring_off = used_off + 4 + (cur_used as usize % queue_size) * 8;
            if used_ring_off + 7 < ram.len() {
                let head_bytes = (head as u32).to_le_bytes();
                ram[used_ring_off..used_ring_off + 4].copy_from_slice(&head_bytes);
                let len_bytes = (written as u32).to_le_bytes();
                ram[used_ring_off + 4..used_ring_off + 8].copy_from_slice(&len_bytes);
            }
            let new_used = cur_used.wrapping_add(1);
            if used_idx_off + 1 < ram.len() {
                let bytes = new_used.to_le_bytes();
                ram[used_idx_off] = bytes[0];
                ram[used_idx_off + 1] = bytes[1];
            }

            used_count += 1;
            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[0].last_avail_idx = last_avail;

        if used_count > 0 {
            self.interrupt_status |= 1;
        }
    }

    /// Read the request data from a descriptor chain
    fn read_request_chain(
        &self,
        ram: &[u8],
        desc_off: usize,
        head: usize,
        queue_size: usize,
        _dram_base: usize,
    ) -> (Vec<u8>, usize) {
        let mut data = Vec::new();
        let mut idx = head;
        let mut last_device_writable = head;
        let mut count = 0;

        loop {
            if count >= queue_size {
                break;
            }
            let d_off = desc_off + idx * 16;
            if d_off + 15 >= ram.len() {
                break;
            }

            let addr = u64::from_le_bytes(ram[d_off..d_off + 8].try_into().unwrap()) as usize;
            let len = u32::from_le_bytes(ram[d_off + 8..d_off + 12].try_into().unwrap()) as usize;
            let flags = u16::from_le_bytes(ram[d_off + 12..d_off + 14].try_into().unwrap());
            let next = u16::from_le_bytes(ram[d_off + 14..d_off + 16].try_into().unwrap()) as usize;

            let buf_off = addr.wrapping_sub(0x8000_0000);
            let is_write = flags & 2 != 0; // VRING_DESC_F_WRITE

            if is_write {
                last_device_writable = idx;
            } else if buf_off + len <= ram.len() {
                data.extend_from_slice(&ram[buf_off..buf_off + len]);
            }

            count += 1;
            if flags & 1 != 0 {
                // VRING_DESC_F_NEXT
                idx = next;
            } else {
                break;
            }
        }

        (data, last_device_writable)
    }

    /// Write response data into the device-writable descriptor
    #[allow(clippy::too_many_arguments)]
    fn write_response(
        &self,
        ram: &mut [u8],
        desc_off: usize,
        desc_idx: usize,
        _queue_size: usize,
        _dram_base: usize,
        status: u8,
        extra_data: &[u8],
    ) -> usize {
        let d_off = desc_off + desc_idx * 16;
        if d_off + 15 >= ram.len() {
            return 0;
        }

        let addr = u64::from_le_bytes(ram[d_off..d_off + 8].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(ram[d_off + 8..d_off + 12].try_into().unwrap()) as usize;
        let buf_off = addr.wrapping_sub(0x8000_0000);

        if buf_off >= ram.len() {
            return 0;
        }

        // Write status byte
        ram[buf_off] = status;
        let mut written = 1;

        // Write padding (3 bytes to align to 4)
        for i in 1..4.min(len) {
            if buf_off + i < ram.len() {
                ram[buf_off + i] = 0;
            }
            written += 1;
        }

        // Write extra response data after the 4-byte header
        if written < len {
            let copy_len = extra_data.len().min(len - written);
            if buf_off + written + copy_len <= ram.len() {
                ram[buf_off + written..buf_off + written + copy_len]
                    .copy_from_slice(&extra_data[..copy_len]);
                written += copy_len;
            }
        }

        written
    }

    /// Handle a single IOMMU request, returns (status, extra_response_data)
    fn handle_request(&mut self, data: &[u8]) -> (u8, Vec<u8>) {
        if data.is_empty() {
            return (VIRTIO_IOMMU_S_IOERR, Vec::new());
        }

        let req_type = data[0];
        match req_type {
            VIRTIO_IOMMU_T_ATTACH => self.handle_attach(data),
            VIRTIO_IOMMU_T_DETACH => self.handle_detach(data),
            VIRTIO_IOMMU_T_MAP => self.handle_map(data),
            VIRTIO_IOMMU_T_UNMAP => self.handle_unmap(data),
            VIRTIO_IOMMU_T_PROBE => self.handle_probe(data),
            _ => (VIRTIO_IOMMU_S_UNSUPP, Vec::new()),
        }
    }

    /// Handle ATTACH request: attach endpoint to domain
    /// Format: type(1) + reserved(3) + domain(4) + endpoint(4) + reserved(8)
    fn handle_attach(&mut self, data: &[u8]) -> (u8, Vec<u8>) {
        if data.len() < 16 {
            return (VIRTIO_IOMMU_S_INVAL, Vec::new());
        }

        let domain_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let endpoint_id = u32::from_le_bytes(data[8..12].try_into().unwrap());

        // Check if endpoint is already attached to a different domain
        if let Some(pos) = self
            .endpoint_domain
            .iter()
            .position(|(ep, _)| *ep == endpoint_id)
        {
            let existing_domain = self.endpoint_domain[pos].1;
            if existing_domain != domain_id {
                // Detach from old domain first
                if let Some(d) = self.domains.iter_mut().find(|d| d.id == existing_domain) {
                    d.endpoints.retain(|&e| e != endpoint_id);
                }
                // Clean up empty domain
                self.domains
                    .retain(|d| !(d.id == existing_domain && d.endpoints.is_empty()));
                self.endpoint_domain.remove(pos);
            } else {
                // Already attached to this domain
                return (VIRTIO_IOMMU_S_OK, Vec::new());
            }
        }

        // Find or create domain
        if !self.domains.iter().any(|d| d.id == domain_id) {
            self.domains.push(Domain {
                id: domain_id,
                endpoints: Vec::new(),
                mappings: Vec::new(),
            });
        }

        let domain = self.domains.iter_mut().find(|d| d.id == domain_id).unwrap();
        if !domain.endpoints.contains(&endpoint_id) {
            domain.endpoints.push(endpoint_id);
        }
        self.endpoint_domain.push((endpoint_id, domain_id));

        (VIRTIO_IOMMU_S_OK, Vec::new())
    }

    /// Handle DETACH request: detach endpoint from domain
    /// Format: type(1) + reserved(3) + domain(4) + endpoint(4) + reserved(8)
    fn handle_detach(&mut self, data: &[u8]) -> (u8, Vec<u8>) {
        if data.len() < 16 {
            return (VIRTIO_IOMMU_S_INVAL, Vec::new());
        }

        let domain_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let endpoint_id = u32::from_le_bytes(data[8..12].try_into().unwrap());

        // Check endpoint is attached to this domain
        let pos = self
            .endpoint_domain
            .iter()
            .position(|(ep, dom)| *ep == endpoint_id && *dom == domain_id);
        if pos.is_none() {
            return (VIRTIO_IOMMU_S_NOENT, Vec::new());
        }
        self.endpoint_domain.remove(pos.unwrap());

        // Remove from domain
        if let Some(domain) = self.domains.iter_mut().find(|d| d.id == domain_id) {
            domain.endpoints.retain(|&e| e != endpoint_id);
            // Clean up empty domains
            if domain.endpoints.is_empty() {
                self.domains.retain(|d| d.id != domain_id);
            }
        }

        (VIRTIO_IOMMU_S_OK, Vec::new())
    }

    /// Handle MAP request: create IOVA → physical mapping in a domain
    /// Format: type(1) + reserved(3) + domain(4) + virt_start(8) + virt_end(8) + phys_start(8) + flags(4)
    fn handle_map(&mut self, data: &[u8]) -> (u8, Vec<u8>) {
        if data.len() < 36 {
            return (VIRTIO_IOMMU_S_INVAL, Vec::new());
        }

        let domain_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let virt_start = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let virt_end = u64::from_le_bytes(data[16..24].try_into().unwrap());
        let phys_start = u64::from_le_bytes(data[24..32].try_into().unwrap());
        let flags = u32::from_le_bytes(data[32..36].try_into().unwrap());

        // Validate range
        if virt_end < virt_start {
            return (VIRTIO_IOMMU_S_RANGE, Vec::new());
        }

        // Validate alignment (must be page-aligned)
        if virt_start & 0xFFF != 0 || phys_start & 0xFFF != 0 {
            return (VIRTIO_IOMMU_S_RANGE, Vec::new());
        }

        // Validate flags — at least read or write must be set
        if flags & (VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE) == 0 {
            return (VIRTIO_IOMMU_S_INVAL, Vec::new());
        }

        // Validate input range
        if virt_start < self.input_range_start || virt_end > self.input_range_end {
            return (VIRTIO_IOMMU_S_RANGE, Vec::new());
        }

        let domain = match self.domains.iter_mut().find(|d| d.id == domain_id) {
            Some(d) => d,
            None => return (VIRTIO_IOMMU_S_NOENT, Vec::new()),
        };

        let size = virt_end - virt_start + 1;

        // Check for overlapping mappings
        for m in &domain.mappings {
            let m_end = m.virt_start + m.size - 1;
            if virt_start <= m_end && virt_end >= m.virt_start {
                return (VIRTIO_IOMMU_S_INVAL, Vec::new());
            }
        }

        domain.mappings.push(IovaMapping {
            virt_start,
            phys_start,
            size,
            flags,
        });

        (VIRTIO_IOMMU_S_OK, Vec::new())
    }

    /// Handle UNMAP request: remove IOVA mappings in a domain
    /// Format: type(1) + reserved(3) + domain(4) + virt_start(8) + virt_end(8)
    fn handle_unmap(&mut self, data: &[u8]) -> (u8, Vec<u8>) {
        if data.len() < 24 {
            return (VIRTIO_IOMMU_S_INVAL, Vec::new());
        }

        let domain_id = u32::from_le_bytes(data[4..8].try_into().unwrap());
        let virt_start = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let virt_end = u64::from_le_bytes(data[16..24].try_into().unwrap());

        if virt_end < virt_start {
            return (VIRTIO_IOMMU_S_RANGE, Vec::new());
        }

        let domain = match self.domains.iter_mut().find(|d| d.id == domain_id) {
            Some(d) => d,
            None => return (VIRTIO_IOMMU_S_NOENT, Vec::new()),
        };

        // Remove all mappings that fall within the unmap range
        domain.mappings.retain(|m| {
            let m_end = m.virt_start + m.size - 1;
            // Keep if completely outside the unmap range
            m_end < virt_start || m.virt_start > virt_end
        });

        (VIRTIO_IOMMU_S_OK, Vec::new())
    }

    /// Handle PROBE request: probe endpoint capabilities
    /// Format: type(1) + reserved(3) + endpoint(4)
    /// Response: properties (reserved memory regions, etc.)
    fn handle_probe(&self, data: &[u8]) -> (u8, Vec<u8>) {
        if data.len() < 8 {
            return (VIRTIO_IOMMU_S_INVAL, Vec::new());
        }

        let _endpoint_id = u32::from_le_bytes(data[4..8].try_into().unwrap());

        // Build probe response with reserved memory properties
        let mut resp = Vec::new();

        // Report MSI reserved memory region (common for interrupt remapping)
        // Property header: type(2) + length(2)
        // RESV_MEM property: subtype(1) + reserved(3) + start(8) + end(8)
        let prop_len: u16 = 20; // subtype(1) + reserved(3) + start(8) + end(8)
        resp.extend_from_slice(&VIRTIO_IOMMU_PROBE_T_RESV_MEM.to_le_bytes());
        resp.extend_from_slice(&prop_len.to_le_bytes());
        resp.push(VIRTIO_IOMMU_RESV_MEM_T_MSI);
        resp.extend_from_slice(&[0u8; 3]); // reserved padding
                                           // MSI region: 0xFEE00000 - 0xFEEFFFFF (standard x86-like MSI doorbell, also used on RISC-V)
        resp.extend_from_slice(&0x0000_0000_FEE0_0000u64.to_le_bytes());
        resp.extend_from_slice(&0x0000_0000_FEEF_FFFFu64.to_le_bytes());

        // Report a general reserved region (MMIO hole)
        resp.extend_from_slice(&VIRTIO_IOMMU_PROBE_T_RESV_MEM.to_le_bytes());
        resp.extend_from_slice(&prop_len.to_le_bytes());
        resp.push(VIRTIO_IOMMU_RESV_MEM_T_RESERVED);
        resp.extend_from_slice(&[0u8; 3]);
        resp.extend_from_slice(&0x0000_0000_0000_0000u64.to_le_bytes()); // start
        resp.extend_from_slice(&0x0000_0000_7FFF_FFFFu64.to_le_bytes()); // end (below DRAM)

        // Terminator
        resp.extend_from_slice(&VIRTIO_IOMMU_PROBE_T_NONE.to_le_bytes());
        resp.extend_from_slice(&0u16.to_le_bytes());

        // Pad to probe_size
        while resp.len() < self.probe_size as usize {
            resp.push(0);
        }

        (VIRTIO_IOMMU_S_OK, resp)
    }

    /// Translate an IOVA for an endpoint, returns physical address or None
    #[allow(dead_code)]
    pub fn translate(&self, endpoint_id: u32, iova: u64, write: bool) -> Option<u64> {
        // Find which domain this endpoint belongs to
        let domain_id = self
            .endpoint_domain
            .iter()
            .find(|(ep, _)| *ep == endpoint_id)
            .map(|(_, dom)| *dom);

        let domain_id = match domain_id {
            Some(id) => id,
            None => {
                // Endpoint not attached — if bypass is supported, identity map
                if self.driver_features & VIRTIO_IOMMU_F_BYPASS != 0 {
                    return Some(iova);
                }
                return None;
            }
        };

        let domain = self.domains.iter().find(|d| d.id == domain_id)?;

        // Find mapping
        for m in &domain.mappings {
            if iova >= m.virt_start && iova < m.virt_start + m.size {
                // Check permissions
                if write && (m.flags & VIRTIO_IOMMU_MAP_F_WRITE == 0) {
                    return None; // Write not permitted
                }
                if !write && (m.flags & VIRTIO_IOMMU_MAP_F_READ == 0) {
                    return None; // Read not permitted
                }
                let offset = iova - m.virt_start;
                return Some(m.phys_start + offset);
            }
        }

        None // No mapping found — fault
    }

    /// Get the number of domains
    #[allow(dead_code)]
    pub fn domain_count(&self) -> usize {
        self.domains.len()
    }

    /// Get the number of attached endpoints
    #[allow(dead_code)]
    pub fn endpoint_count(&self) -> usize {
        self.endpoint_domain.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iommu_mmio_identity() {
        let dev = VirtioIommu::new();
        assert_eq!(dev.read(MAGIC_VALUE), 0x74726976);
        assert_eq!(dev.read(VERSION), 2);
        assert_eq!(dev.read(DEVICE_ID), 23);
        assert_eq!(dev.read(VENDOR_ID), 0x554D4551);
    }

    #[test]
    fn test_iommu_features() {
        let mut dev = VirtioIommu::new();
        dev.write(DEVICE_FEATURES_SEL, 0);
        let feat_lo = dev.read(DEVICE_FEATURES);
        assert_ne!(feat_lo & (1 << 0), 0); // INPUT_RANGE
        assert_ne!(feat_lo & (1 << 1), 0); // DOMAIN_RANGE
        assert_ne!(feat_lo & (1 << 2), 0); // MAP_UNMAP
        assert_ne!(feat_lo & (1 << 3), 0); // BYPASS
        assert_ne!(feat_lo & (1 << 4), 0); // PROBE
    }

    #[test]
    fn test_iommu_config_space() {
        let dev = VirtioIommu::new();
        // page_size_mask low
        let psm_lo = dev.read(CONFIG_BASE);
        assert_eq!(psm_lo, 0xFFFF_F000);
        // probe_size
        let ps = dev.read(CONFIG_BASE + 0x20);
        assert_eq!(ps, 64);
    }

    #[test]
    fn test_iommu_queue_setup() {
        let mut dev = VirtioIommu::new();
        dev.write(QUEUE_SEL, 0);
        assert_eq!(dev.read(QUEUE_NUM_MAX), 256);
        assert_eq!(dev.read(QUEUE_READY), 0);
        dev.write(QUEUE_NUM, 128);
        dev.write(QUEUE_READY, 1);
        assert_eq!(dev.read(QUEUE_READY), 1);
    }

    #[test]
    fn test_iommu_reset() {
        let mut dev = VirtioIommu::new();
        dev.write(QUEUE_SEL, 0);
        dev.write(QUEUE_READY, 1);
        dev.write(STATUS, 0); // reset
        assert_eq!(dev.read(QUEUE_READY), 0);
        assert_eq!(dev.read(STATUS), 0);
    }

    #[test]
    fn test_iommu_interrupt_ack() {
        let mut dev = VirtioIommu::new();
        dev.interrupt_status = 1;
        assert!(dev.has_interrupt());
        dev.write(INTERRUPT_ACK, 1);
        assert!(!dev.has_interrupt());
    }

    #[test]
    fn test_iommu_attach_detach() {
        let mut dev = VirtioIommu::new();
        // Attach endpoint 7 to domain 1
        let mut req = vec![0u8; 20];
        req[0] = VIRTIO_IOMMU_T_ATTACH;
        req[4..8].copy_from_slice(&1u32.to_le_bytes()); // domain
        req[8..12].copy_from_slice(&7u32.to_le_bytes()); // endpoint
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert_eq!(dev.domain_count(), 1);
        assert_eq!(dev.endpoint_count(), 1);

        // Detach
        req[0] = VIRTIO_IOMMU_T_DETACH;
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert_eq!(dev.domain_count(), 0);
        assert_eq!(dev.endpoint_count(), 0);
    }

    #[test]
    fn test_iommu_attach_multiple_endpoints() {
        let mut dev = VirtioIommu::new();
        // Attach ep 1 and ep 2 to domain 5
        for ep in [1u32, 2] {
            let mut req = vec![0u8; 20];
            req[0] = VIRTIO_IOMMU_T_ATTACH;
            req[4..8].copy_from_slice(&5u32.to_le_bytes());
            req[8..12].copy_from_slice(&ep.to_le_bytes());
            let (status, _) = dev.handle_request(&req);
            assert_eq!(status, VIRTIO_IOMMU_S_OK);
        }
        assert_eq!(dev.domain_count(), 1);
        assert_eq!(dev.endpoint_count(), 2);
    }

    #[test]
    fn test_iommu_reattach_endpoint() {
        let mut dev = VirtioIommu::new();
        // Attach ep 1 to domain 1
        let mut req = vec![0u8; 20];
        req[0] = VIRTIO_IOMMU_T_ATTACH;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&req);

        // Reattach ep 1 to domain 2
        req[4..8].copy_from_slice(&2u32.to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert_eq!(dev.domain_count(), 1); // domain 1 removed (empty), domain 2 created
        assert_eq!(dev.endpoint_count(), 1);
    }

    #[test]
    fn test_iommu_detach_noent() {
        let mut dev = VirtioIommu::new();
        let mut req = vec![0u8; 20];
        req[0] = VIRTIO_IOMMU_T_DETACH;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..12].copy_from_slice(&99u32.to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_NOENT);
    }

    #[test]
    fn test_iommu_map_basic() {
        let mut dev = VirtioIommu::new();
        // First attach an endpoint
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map IOVA 0x1000-0x1FFF → phys 0x80001000
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes()); // domain
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes()); // virt_start
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes()); // virt_end
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes()); // phys_start
        req[32..36]
            .copy_from_slice(&(VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE).to_le_bytes());

        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
    }

    #[test]
    fn test_iommu_map_no_domain() {
        let mut dev = VirtioIommu::new();
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&99u32.to_le_bytes()); // nonexistent domain
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&(VIRTIO_IOMMU_MAP_F_READ).to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_NOENT);
    }

    #[test]
    fn test_iommu_map_invalid_flags() {
        let mut dev = VirtioIommu::new();
        // Attach
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map with flags=0 (invalid)
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&0u32.to_le_bytes()); // no flags
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_INVAL);
    }

    #[test]
    fn test_iommu_map_bad_alignment() {
        let mut dev = VirtioIommu::new();
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1001u64.to_le_bytes()); // misaligned!
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&VIRTIO_IOMMU_MAP_F_READ.to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_RANGE);
    }

    #[test]
    fn test_iommu_map_overlap() {
        let mut dev = VirtioIommu::new();
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map 0x1000-0x1FFF
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&VIRTIO_IOMMU_MAP_F_READ.to_le_bytes());
        dev.handle_request(&req);

        // Try overlapping map 0x1000-0x2FFF
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x2FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_2000u64.to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_INVAL);
    }

    #[test]
    fn test_iommu_map_inverted_range() {
        let mut dev = VirtioIommu::new();
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x2000u64.to_le_bytes()); // start > end
        req[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&VIRTIO_IOMMU_MAP_F_READ.to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_RANGE);
    }

    #[test]
    fn test_iommu_unmap() {
        let mut dev = VirtioIommu::new();
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&VIRTIO_IOMMU_MAP_F_READ.to_le_bytes());
        dev.handle_request(&req);

        // Unmap
        let mut unmap = vec![0u8; 28];
        unmap[0] = VIRTIO_IOMMU_T_UNMAP;
        unmap[4..8].copy_from_slice(&1u32.to_le_bytes());
        unmap[8..16].copy_from_slice(&0x0000u64.to_le_bytes());
        unmap[16..24].copy_from_slice(&0xFFFFu64.to_le_bytes());
        let (status, _) = dev.handle_request(&unmap);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);

        // Translate should fail now
        assert!(dev.translate(1, 0x1000, false).is_none());
    }

    #[test]
    fn test_iommu_translate_mapped() {
        let mut dev = VirtioIommu::new();
        // Attach
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map 0x1000-0x1FFF → 0x80001000
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36]
            .copy_from_slice(&(VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE).to_le_bytes());
        dev.handle_request(&req);

        // Translate
        assert_eq!(dev.translate(1, 0x1000, false), Some(0x8000_1000));
        assert_eq!(dev.translate(1, 0x1800, true), Some(0x8000_1800));
        assert_eq!(dev.translate(1, 0x2000, false), None); // out of range
    }

    #[test]
    fn test_iommu_translate_read_only() {
        let mut dev = VirtioIommu::new();
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map read-only
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&VIRTIO_IOMMU_MAP_F_READ.to_le_bytes());
        dev.handle_request(&req);

        assert_eq!(dev.translate(1, 0x1000, false), Some(0x8000_1000));
        assert_eq!(dev.translate(1, 0x1000, true), None); // write denied
    }

    #[test]
    fn test_iommu_translate_bypass() {
        let mut dev = VirtioIommu::new();
        dev.driver_features = VIRTIO_IOMMU_F_BYPASS;
        // No attachment — bypass should return identity
        assert_eq!(dev.translate(99, 0x1234, false), Some(0x1234));
    }

    #[test]
    fn test_iommu_translate_no_bypass() {
        let dev = VirtioIommu::new();
        // No attachment, no bypass
        assert_eq!(dev.translate(99, 0x1234, false), None);
    }

    #[test]
    fn test_iommu_probe() {
        let mut dev = VirtioIommu::new();
        let mut req = vec![0u8; 12];
        req[0] = VIRTIO_IOMMU_T_PROBE;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        let (status, data) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert!(!data.is_empty());
        // First property should be RESV_MEM (type 1)
        let prop_type = u16::from_le_bytes([data[0], data[1]]);
        assert_eq!(prop_type, VIRTIO_IOMMU_PROBE_T_RESV_MEM);
    }

    #[test]
    fn test_iommu_unknown_request() {
        let mut dev = VirtioIommu::new();
        let req = vec![0xFF, 0, 0, 0];
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_UNSUPP);
    }

    #[test]
    fn test_iommu_short_request() {
        let mut dev = VirtioIommu::new();
        let (status, _) = dev.handle_request(&[]);
        assert_eq!(status, VIRTIO_IOMMU_S_IOERR);
    }

    #[test]
    fn test_iommu_attach_short_data() {
        let mut dev = VirtioIommu::new();
        let req = vec![VIRTIO_IOMMU_T_ATTACH, 0, 0, 0]; // too short
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_INVAL);
    }

    #[test]
    fn test_iommu_map_mmio_flag() {
        let mut dev = VirtioIommu::new();
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map with MMIO flag
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x1000_0000u64.to_le_bytes()); // MMIO region
        req[32..36].copy_from_slice(
            &(VIRTIO_IOMMU_MAP_F_READ | VIRTIO_IOMMU_MAP_F_WRITE | VIRTIO_IOMMU_MAP_F_MMIO)
                .to_le_bytes(),
        );
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);
        assert_eq!(dev.translate(1, 0x1000, false), Some(0x1000_0000));
    }

    #[test]
    fn test_iommu_unmap_no_domain() {
        let mut dev = VirtioIommu::new();
        let mut req = vec![0u8; 28];
        req[0] = VIRTIO_IOMMU_T_UNMAP;
        req[4..8].copy_from_slice(&99u32.to_le_bytes());
        req[8..16].copy_from_slice(&0u64.to_le_bytes());
        req[16..24].copy_from_slice(&0xFFFFu64.to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_NOENT);
    }

    #[test]
    fn test_iommu_map_multiple_regions() {
        let mut dev = VirtioIommu::new();
        let mut attach = vec![0u8; 20];
        attach[0] = VIRTIO_IOMMU_T_ATTACH;
        attach[4..8].copy_from_slice(&1u32.to_le_bytes());
        attach[8..12].copy_from_slice(&1u32.to_le_bytes());
        dev.handle_request(&attach);

        // Map region 1: 0x1000-0x1FFF
        let mut req = vec![0u8; 40];
        req[0] = VIRTIO_IOMMU_T_MAP;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x1FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_1000u64.to_le_bytes());
        req[32..36].copy_from_slice(&VIRTIO_IOMMU_MAP_F_READ.to_le_bytes());
        dev.handle_request(&req);

        // Map region 2: 0x3000-0x3FFF
        req[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        req[16..24].copy_from_slice(&0x3FFFu64.to_le_bytes());
        req[24..32].copy_from_slice(&0x8000_3000u64.to_le_bytes());
        let (status, _) = dev.handle_request(&req);
        assert_eq!(status, VIRTIO_IOMMU_S_OK);

        // Both translate correctly
        assert_eq!(dev.translate(1, 0x1500, false), Some(0x8000_1500));
        assert_eq!(dev.translate(1, 0x3500, false), Some(0x8000_3500));
        // Gap doesn't translate
        assert_eq!(dev.translate(1, 0x2000, false), None);
    }

    #[test]
    fn test_iommu_attach_same_twice() {
        let mut dev = VirtioIommu::new();
        let mut req = vec![0u8; 20];
        req[0] = VIRTIO_IOMMU_T_ATTACH;
        req[4..8].copy_from_slice(&1u32.to_le_bytes());
        req[8..12].copy_from_slice(&1u32.to_le_bytes());
        let (s1, _) = dev.handle_request(&req);
        let (s2, _) = dev.handle_request(&req);
        assert_eq!(s1, VIRTIO_IOMMU_S_OK);
        assert_eq!(s2, VIRTIO_IOMMU_S_OK);
        assert_eq!(dev.endpoint_count(), 1); // not duplicated
    }

    #[test]
    fn test_iommu_driver_features() {
        let mut dev = VirtioIommu::new();
        dev.write(DRIVER_FEATURES_SEL, 0);
        dev.write(DRIVER_FEATURES, 0x1F); // all features
        assert_eq!(dev.driver_features & 0xFFFF_FFFF, 0x1F);
        dev.write(DRIVER_FEATURES_SEL, 1);
        dev.write(DRIVER_FEATURES, 0);
        assert_eq!(dev.driver_features, 0x1F);
    }

    #[test]
    fn test_iommu_desc_addr_setup() {
        let mut dev = VirtioIommu::new();
        dev.write(QUEUE_SEL, 0);
        dev.write(QUEUE_DESC_LOW, 0x1000);
        dev.write(QUEUE_DESC_HIGH, 0x80);
        dev.write(QUEUE_AVAIL_LOW, 0x2000);
        dev.write(QUEUE_AVAIL_HIGH, 0x80);
        dev.write(QUEUE_USED_LOW, 0x3000);
        dev.write(QUEUE_USED_HIGH, 0x80);
        assert_eq!(dev.queues[0].desc_addr, 0x80_0000_1000);
        assert_eq!(dev.queues[0].avail_addr, 0x80_0000_2000);
        assert_eq!(dev.queues[0].used_addr, 0x80_0000_3000);
    }
}
