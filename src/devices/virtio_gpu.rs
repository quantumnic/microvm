// VirtIO GPU Device (v2, 2D operations)
//
// Implements VirtIO GPU device type 16 with 2D scanout capabilities.
// Provides framebuffer support for Linux console/display output.
// Reference: VirtIO spec v1.2, section 5.7 (GPU device).

// VirtIO MMIO register offsets
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

const STATUS_DRIVER_OK: u32 = 4;

// Virtqueue descriptor flags
const VRING_DESC_F_NEXT: u16 = 1;
const VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: u32 = 64;

// GPU command types (controlq)
const VIRTIO_GPU_CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const VIRTIO_GPU_CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const VIRTIO_GPU_CMD_RESOURCE_UNREF: u32 = 0x0102;
const VIRTIO_GPU_CMD_SET_SCANOUT: u32 = 0x0103;
const VIRTIO_GPU_CMD_RESOURCE_FLUSH: u32 = 0x0104;
const VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
const VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
const VIRTIO_GPU_CMD_GET_CAPSET_INFO: u32 = 0x0108;
const VIRTIO_GPU_CMD_GET_CAPSET: u32 = 0x0109;
const VIRTIO_GPU_CMD_GET_EDID: u32 = 0x010A;

// GPU response types
const VIRTIO_GPU_RESP_OK_NODATA: u32 = 0x1100;
const VIRTIO_GPU_RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const VIRTIO_GPU_RESP_OK_CAPSET_INFO: u32 = 0x1102;
const VIRTIO_GPU_RESP_OK_CAPSET: u32 = 0x1103;
const VIRTIO_GPU_RESP_OK_EDID: u32 = 0x1104;
const VIRTIO_GPU_RESP_ERR_UNSPEC: u32 = 0x1200;
const VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1202;
const VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER: u32 = 0x1203;

// GPU formats
const VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM: u32 = 1;
const VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM: u32 = 67;

// Feature bits
const VIRTIO_GPU_F_EDID: u64 = 1 << 1;

// Default display dimensions
const DEFAULT_WIDTH: u32 = 1024;
const DEFAULT_HEIGHT: u32 = 768;
const MAX_SCANOUTS: u32 = 1;

/// A 2D GPU resource (framebuffer)
#[allow(dead_code)]
struct GpuResource {
    id: u32,
    width: u32,
    height: u32,
    format: u32,
    /// Pixel data (RGBA, 4 bytes per pixel)
    data: Vec<u8>,
    /// Guest backing memory entries: (addr, length)
    backing: Vec<(u64, u32)>,
}

/// Scanout configuration
struct Scanout {
    resource_id: u32,
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    enabled: bool,
}

/// VirtIO queue state
struct Virtqueue {
    num: u32,
    ready: bool,
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
    last_avail_idx: u16,
}

impl Virtqueue {
    fn new() -> Self {
        Self {
            num: 0,
            ready: false,
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            last_avail_idx: 0,
        }
    }
}

impl Default for VirtioGpu {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VirtioGpu {
    // MMIO transport state
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    status: u32,
    interrupt_status: u32,
    queue_sel: u32,
    // Two queues: controlq (0) and cursorq (1)
    queues: [Virtqueue; 2],
    // GPU state
    resources: Vec<GpuResource>,
    scanouts: Vec<Scanout>,
    // Config space: events_read (4 bytes) + events_clear (4 bytes) + num_scanouts (4 bytes) + num_capsets (4 bytes)
    events_read: u32,
    notify_pending: bool,
}

impl VirtioGpu {
    pub fn new() -> Self {
        Self {
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            status: 0,
            interrupt_status: 0,
            queue_sel: 0,
            queues: [Virtqueue::new(), Virtqueue::new()],
            resources: Vec::new(),
            scanouts: vec![Scanout {
                resource_id: 0,
                x: 0,
                y: 0,
                width: DEFAULT_WIDTH,
                height: DEFAULT_HEIGHT,
                enabled: false,
            }],
            events_read: 0,
            notify_pending: false,
        }
    }

    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => 0x7472_6976, // "virt"
            VERSION => 2,
            DEVICE_ID => 16,         // GPU device
            VENDOR_ID => 0x554D4551, // "QEMU"
            DEVICE_FEATURES => {
                if self.device_features_sel == 0 {
                    // VIRTIO_GPU_F_EDID
                    VIRTIO_GPU_F_EDID as u32
                } else {
                    0
                }
            }
            QUEUE_NUM_MAX => QUEUE_SIZE,
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
            // Config space: events_read(0x100), events_clear(0x104), num_scanouts(0x108), num_capsets(0x10c)
            CONFIG_BASE => self.events_read,
            0x104 => 0, // events_clear (write-only, reads as 0)
            0x108 => MAX_SCANOUTS,
            0x10C => 0, // num_capsets
            _ => 0,
        }
    }

    pub fn write(&mut self, offset: u64, val: u64) {
        let val32 = val as u32;
        match offset {
            DEVICE_FEATURES_SEL => self.device_features_sel = val32,
            DRIVER_FEATURES => {
                if self.driver_features_sel == 0 {
                    self.driver_features =
                        (self.driver_features & 0xFFFF_FFFF_0000_0000) | val32 as u64;
                } else {
                    self.driver_features =
                        (self.driver_features & 0x0000_0000_FFFF_FFFF) | ((val32 as u64) << 32);
                }
            }
            DRIVER_FEATURES_SEL => self.driver_features_sel = val32,
            QUEUE_SEL => self.queue_sel = val32,
            QUEUE_NUM => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].num = val32;
                }
            }
            QUEUE_READY => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].ready = val32 != 0;
                }
            }
            QUEUE_NOTIFY => {
                self.notify_pending = true;
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !val32;
            }
            STATUS => {
                self.status = val32;
                if val32 == 0 {
                    // Device reset
                    self.reset();
                }
            }
            QUEUE_DESC_LOW => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].desc_addr =
                        (self.queues[q].desc_addr & 0xFFFF_FFFF_0000_0000) | val32 as u64;
                }
            }
            QUEUE_DESC_HIGH => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].desc_addr =
                        (self.queues[q].desc_addr & 0x0000_0000_FFFF_FFFF) | ((val32 as u64) << 32);
                }
            }
            QUEUE_AVAIL_LOW => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].avail_addr =
                        (self.queues[q].avail_addr & 0xFFFF_FFFF_0000_0000) | val32 as u64;
                }
            }
            QUEUE_AVAIL_HIGH => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].avail_addr = (self.queues[q].avail_addr & 0x0000_0000_FFFF_FFFF)
                        | ((val32 as u64) << 32);
                }
            }
            QUEUE_USED_LOW => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].used_addr =
                        (self.queues[q].used_addr & 0xFFFF_FFFF_0000_0000) | val32 as u64;
                }
            }
            QUEUE_USED_HIGH => {
                let q = self.queue_sel as usize;
                if q < 2 {
                    self.queues[q].used_addr =
                        (self.queues[q].used_addr & 0x0000_0000_FFFF_FFFF) | ((val32 as u64) << 32);
                }
            }
            // Config space writes
            0x104 => {
                // events_clear: writing clears the corresponding bits in events_read
                self.events_read &= !val32;
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.device_features_sel = 0;
        self.driver_features = 0;
        self.driver_features_sel = 0;
        self.status = 0;
        self.interrupt_status = 0;
        self.queue_sel = 0;
        self.queues = [Virtqueue::new(), Virtqueue::new()];
        self.resources.clear();
        self.scanouts = vec![Scanout {
            resource_id: 0,
            x: 0,
            y: 0,
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            enabled: false,
        }];
        self.events_read = 0;
        self.notify_pending = false;
    }

    pub fn has_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    pub fn needs_processing(&self) -> bool {
        self.notify_pending && (self.status & STATUS_DRIVER_OK) != 0
    }

    /// Process controlq commands from the guest
    pub fn process_controlq(&mut self, ram: &mut [u8], dram_base: u64) {
        self.notify_pending = false;

        let q = &self.queues[0];
        if !q.ready || q.desc_addr == 0 {
            return;
        }

        let desc_addr = q.desc_addr;
        let avail_addr = q.avail_addr;
        let used_addr = q.used_addr;
        let queue_num = q.num;
        let mut last_avail = q.last_avail_idx;

        // Read avail ring index
        let avail_idx = read_ram_u16(ram, avail_addr + 2, dram_base);

        while last_avail != avail_idx {
            let ring_idx = (last_avail % queue_num as u16) as u64;
            let desc_idx = read_ram_u16(ram, avail_addr + 4 + ring_idx * 2, dram_base) as u64;

            // Walk the descriptor chain, collecting read and write buffers
            let (request_data, write_descs) =
                collect_descriptors(ram, desc_addr, desc_idx, queue_num, dram_base);

            // Process the GPU command
            let response = self.handle_command(&request_data, ram, dram_base);

            // Write response to the first writable descriptor
            let mut written = 0u32;
            if !write_descs.is_empty() {
                let (waddr, wlen) = write_descs[0];
                let copy_len = response.len().min(wlen as usize);
                write_ram_bytes(ram, waddr, &response[..copy_len], dram_base);
                written = copy_len as u32;
            }

            // Update used ring
            let used_idx = read_ram_u16(ram, used_addr + 2, dram_base);
            let used_ring_off = 4 + (used_idx % queue_num as u16) as u64 * 8;
            write_ram_u32(ram, used_addr + used_ring_off, desc_idx as u32, dram_base);
            write_ram_u32(ram, used_addr + used_ring_off + 4, written, dram_base);
            write_ram_u16(ram, used_addr + 2, used_idx.wrapping_add(1), dram_base);

            last_avail = last_avail.wrapping_add(1);
        }

        self.queues[0].last_avail_idx = last_avail;

        // Signal interrupt after processing commands
        self.interrupt_status |= 1;
    }

    fn handle_command(&mut self, data: &[u8], ram: &mut [u8], dram_base: u64) -> Vec<u8> {
        if data.len() < 24 {
            // Minimum header size: type(4) + flags(4) + fence_id(8) + ctx_id(4) + ring_idx(1) + padding(3)
            return gpu_response_header(VIRTIO_GPU_RESP_ERR_UNSPEC);
        }

        let cmd_type = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let fence_id = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        match cmd_type {
            VIRTIO_GPU_CMD_GET_DISPLAY_INFO => self.cmd_get_display_info(flags, fence_id),
            VIRTIO_GPU_CMD_RESOURCE_CREATE_2D => self.cmd_resource_create_2d(data, flags, fence_id),
            VIRTIO_GPU_CMD_RESOURCE_UNREF => self.cmd_resource_unref(data, flags, fence_id),
            VIRTIO_GPU_CMD_SET_SCANOUT => self.cmd_set_scanout(data, flags, fence_id),
            VIRTIO_GPU_CMD_RESOURCE_FLUSH => self.cmd_resource_flush(data, flags, fence_id),
            VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D => {
                self.cmd_transfer_to_host_2d(data, ram, dram_base, flags, fence_id)
            }
            VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING => {
                self.cmd_resource_attach_backing(data, ram, dram_base, flags, fence_id)
            }
            VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING => {
                self.cmd_resource_detach_backing(data, flags, fence_id)
            }
            VIRTIO_GPU_CMD_GET_CAPSET_INFO => self.cmd_get_capset_info(flags, fence_id),
            VIRTIO_GPU_CMD_GET_CAPSET => self.cmd_get_capset(flags, fence_id),
            VIRTIO_GPU_CMD_GET_EDID => self.cmd_get_edid(data, flags, fence_id),
            _ => {
                log::trace!("VirtIO GPU: unknown command type {:#x}", cmd_type);
                gpu_response_header(VIRTIO_GPU_RESP_ERR_UNSPEC)
            }
        }
    }

    fn cmd_get_display_info(&self, flags: u32, fence_id: u64) -> Vec<u8> {
        // Response: header (24 bytes) + 16 * display_info (24 bytes each) = 408 bytes
        let mut resp = Vec::with_capacity(24 + MAX_SCANOUTS as usize * 24);
        push_header(&mut resp, VIRTIO_GPU_RESP_OK_DISPLAY_INFO, flags, fence_id);

        for i in 0..MAX_SCANOUTS as usize {
            let scanout = &self.scanouts[i];
            // struct virtio_gpu_rect: x, y, width, height (each u32)
            resp.extend_from_slice(&scanout.x.to_le_bytes());
            resp.extend_from_slice(&scanout.y.to_le_bytes());
            resp.extend_from_slice(&scanout.width.to_le_bytes());
            resp.extend_from_slice(&scanout.height.to_le_bytes());
            // enabled flag (u32) + flags (u32)
            resp.extend_from_slice(&(1u32).to_le_bytes()); // enabled
            resp.extend_from_slice(&0u32.to_le_bytes()); // flags
        }

        // Pad remaining scanouts (up to 16 total per spec)
        for _ in MAX_SCANOUTS..16 {
            resp.extend_from_slice(&[0u8; 24]);
        }

        resp
    }

    fn cmd_resource_create_2d(&mut self, data: &[u8], flags: u32, fence_id: u64) -> Vec<u8> {
        if data.len() < 24 + 16 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let off = 24;
        let resource_id =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let format =
            u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let width =
            u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
        let height = u32::from_le_bytes([
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]);

        if resource_id == 0 {
            return gpu_response_with_fence(
                VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                flags,
                fence_id,
            );
        }

        // Validate format
        if format != VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM
            && format != VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM
            && format != 2
            && format != 121
        {
            // Accept common formats: B8G8R8A8 (1), B8G8R8X8 (2), R8G8B8A8 (67), R8G8B8X8 (121)
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }

        // Remove existing resource with same ID
        self.resources.retain(|r| r.id != resource_id);

        let data_size = (width as usize) * (height as usize) * 4;
        self.resources.push(GpuResource {
            id: resource_id,
            width,
            height,
            format,
            data: vec![0u8; data_size],
            backing: Vec::new(),
        });

        log::trace!(
            "VirtIO GPU: created resource {} ({}x{} format={})",
            resource_id,
            width,
            height,
            format
        );

        gpu_response_with_fence(VIRTIO_GPU_RESP_OK_NODATA, flags, fence_id)
    }

    fn cmd_resource_unref(&mut self, data: &[u8], flags: u32, fence_id: u64) -> Vec<u8> {
        if data.len() < 24 + 4 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let resource_id = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        // Disable scanouts using this resource
        for s in &mut self.scanouts {
            if s.resource_id == resource_id {
                s.resource_id = 0;
                s.enabled = false;
            }
        }

        let before = self.resources.len();
        self.resources.retain(|r| r.id != resource_id);
        if self.resources.len() == before {
            return gpu_response_with_fence(
                VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                flags,
                fence_id,
            );
        }

        gpu_response_with_fence(VIRTIO_GPU_RESP_OK_NODATA, flags, fence_id)
    }

    fn cmd_set_scanout(&mut self, data: &[u8], flags: u32, fence_id: u64) -> Vec<u8> {
        if data.len() < 24 + 24 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let off = 24;
        // rect: x, y, width, height
        let x = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let y = u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let w = u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
        let h = u32::from_le_bytes([
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]);
        let scanout_id = u32::from_le_bytes([
            data[off + 16],
            data[off + 17],
            data[off + 18],
            data[off + 19],
        ]);
        let resource_id = u32::from_le_bytes([
            data[off + 20],
            data[off + 21],
            data[off + 22],
            data[off + 23],
        ]);

        if scanout_id >= MAX_SCANOUTS {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }

        let scanout = &mut self.scanouts[scanout_id as usize];

        if resource_id == 0 {
            // Disable scanout
            scanout.resource_id = 0;
            scanout.enabled = false;
        } else {
            if !self.resources.iter().any(|r| r.id == resource_id) {
                return gpu_response_with_fence(
                    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                    flags,
                    fence_id,
                );
            }
            scanout.resource_id = resource_id;
            scanout.x = x;
            scanout.y = y;
            scanout.width = w;
            scanout.height = h;
            scanout.enabled = true;
        }

        gpu_response_with_fence(VIRTIO_GPU_RESP_OK_NODATA, flags, fence_id)
    }

    fn cmd_resource_flush(&self, data: &[u8], flags: u32, fence_id: u64) -> Vec<u8> {
        if data.len() < 24 + 20 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let resource_id = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);

        if resource_id == 0 || !self.resources.iter().any(|r| r.id == resource_id) {
            return gpu_response_with_fence(
                VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                flags,
                fence_id,
            );
        }

        // In a real implementation, this would push the updated region to a display.
        // For emulation we just acknowledge — the framebuffer data is already in the resource.
        log::trace!("VirtIO GPU: flush resource {}", resource_id);

        gpu_response_with_fence(VIRTIO_GPU_RESP_OK_NODATA, flags, fence_id)
    }

    fn cmd_transfer_to_host_2d(
        &mut self,
        data: &[u8],
        ram: &[u8],
        dram_base: u64,
        flags: u32,
        fence_id: u64,
    ) -> Vec<u8> {
        if data.len() < 24 + 28 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let off = 24;
        // rect: x, y, width, height
        let r_x = u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let r_y = u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);
        let r_w =
            u32::from_le_bytes([data[off + 8], data[off + 9], data[off + 10], data[off + 11]]);
        let r_h = u32::from_le_bytes([
            data[off + 12],
            data[off + 13],
            data[off + 14],
            data[off + 15],
        ]);
        let _offset64 = u64::from_le_bytes([
            data[off + 16],
            data[off + 17],
            data[off + 18],
            data[off + 19],
            data[off + 20],
            data[off + 21],
            data[off + 22],
            data[off + 23],
        ]);
        let resource_id = u32::from_le_bytes([
            data[off + 24],
            data[off + 25],
            data[off + 26],
            data[off + 27],
        ]);

        let resource = match self.resources.iter_mut().find(|r| r.id == resource_id) {
            Some(r) => r,
            None => {
                return gpu_response_with_fence(
                    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                    flags,
                    fence_id,
                );
            }
        };

        // Copy pixels from guest backing memory into resource data
        // The backing pages contain the framebuffer in linear layout
        let stride = resource.width as usize * 4;
        let backing_offset: usize = 0;

        // Build a flat view of the backing memory
        let mut backing_data: Vec<u8> = Vec::new();
        for &(addr, len) in &resource.backing {
            for i in 0..len as u64 {
                let phys = addr + i;
                if phys >= dram_base {
                    let ram_off = (phys - dram_base) as usize;
                    if ram_off < ram.len() {
                        backing_data.push(ram[ram_off]);
                    } else {
                        backing_data.push(0);
                    }
                } else {
                    backing_data.push(0);
                }
            }
        }

        // Copy the requested rectangle from backing into resource
        for row in 0..r_h as usize {
            let dst_y = r_y as usize + row;
            if dst_y >= resource.height as usize {
                break;
            }
            let dst_off = dst_y * stride + r_x as usize * 4;
            let src_off = backing_offset + row * (r_w as usize * 4);
            let copy_bytes = (r_w as usize * 4).min(stride.saturating_sub(r_x as usize * 4));

            if src_off + copy_bytes <= backing_data.len()
                && dst_off + copy_bytes <= resource.data.len()
            {
                resource.data[dst_off..dst_off + copy_bytes]
                    .copy_from_slice(&backing_data[src_off..src_off + copy_bytes]);
            }
        }
        let _ = backing_offset;

        gpu_response_with_fence(VIRTIO_GPU_RESP_OK_NODATA, flags, fence_id)
    }

    fn cmd_resource_attach_backing(
        &mut self,
        data: &[u8],
        _ram: &[u8],
        _dram_base: u64,
        flags: u32,
        fence_id: u64,
    ) -> Vec<u8> {
        if data.len() < 24 + 8 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let off = 24;
        let resource_id =
            u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]]);
        let nr_entries =
            u32::from_le_bytes([data[off + 4], data[off + 5], data[off + 6], data[off + 7]]);

        let resource = match self.resources.iter_mut().find(|r| r.id == resource_id) {
            Some(r) => r,
            None => {
                return gpu_response_with_fence(
                    VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID,
                    flags,
                    fence_id,
                );
            }
        };

        // Read memory entries from the data following the command
        // Each entry: addr(8) + length(4) + padding(4) = 16 bytes
        resource.backing.clear();
        let entries_off = off + 8;
        for i in 0..nr_entries as usize {
            let e_off = entries_off + i * 16;
            if e_off + 12 <= data.len() {
                let addr = u64::from_le_bytes([
                    data[e_off],
                    data[e_off + 1],
                    data[e_off + 2],
                    data[e_off + 3],
                    data[e_off + 4],
                    data[e_off + 5],
                    data[e_off + 6],
                    data[e_off + 7],
                ]);
                let length = u32::from_le_bytes([
                    data[e_off + 8],
                    data[e_off + 9],
                    data[e_off + 10],
                    data[e_off + 11],
                ]);
                resource.backing.push((addr, length));
            }
        }

        log::trace!(
            "VirtIO GPU: attached {} backing pages to resource {}",
            nr_entries,
            resource_id
        );

        gpu_response_with_fence(VIRTIO_GPU_RESP_OK_NODATA, flags, fence_id)
    }

    fn cmd_resource_detach_backing(&mut self, data: &[u8], flags: u32, fence_id: u64) -> Vec<u8> {
        if data.len() < 24 + 4 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let resource_id = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        match self.resources.iter_mut().find(|r| r.id == resource_id) {
            Some(r) => {
                r.backing.clear();
                gpu_response_with_fence(VIRTIO_GPU_RESP_OK_NODATA, flags, fence_id)
            }
            None => {
                gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID, flags, fence_id)
            }
        }
    }

    fn cmd_get_capset_info(&self, flags: u32, fence_id: u64) -> Vec<u8> {
        // No capability sets supported — return zeroes
        let mut resp = Vec::with_capacity(24 + 16);
        push_header(&mut resp, VIRTIO_GPU_RESP_OK_CAPSET_INFO, flags, fence_id);
        resp.extend_from_slice(&[0u8; 16]); // capset_id, capset_max_version, capset_max_size, padding
        resp
    }

    fn cmd_get_capset(&self, flags: u32, fence_id: u64) -> Vec<u8> {
        let mut resp = Vec::with_capacity(24);
        push_header(&mut resp, VIRTIO_GPU_RESP_OK_CAPSET, flags, fence_id);
        resp
    }

    fn cmd_get_edid(&self, data: &[u8], flags: u32, fence_id: u64) -> Vec<u8> {
        if data.len() < 24 + 4 {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }
        let scanout_id = u32::from_le_bytes([data[24], data[25], data[26], data[27]]);

        if scanout_id >= MAX_SCANOUTS {
            return gpu_response_with_fence(VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER, flags, fence_id);
        }

        let scanout = &self.scanouts[scanout_id as usize];
        let edid = generate_edid(scanout.width, scanout.height);

        let mut resp = Vec::with_capacity(24 + 4 + 4 + 256);
        push_header(&mut resp, VIRTIO_GPU_RESP_OK_EDID, flags, fence_id);
        resp.extend_from_slice(&(edid.len() as u32).to_le_bytes()); // size
        resp.extend_from_slice(&0u32.to_le_bytes()); // padding
                                                     // EDID data padded to 256 bytes
        resp.extend_from_slice(&edid);
        if edid.len() < 256 {
            resp.extend_from_slice(&vec![0u8; 256 - edid.len()]);
        }
        resp
    }
}

// Helper: build a GPU response header
fn gpu_response_header(resp_type: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    v.extend_from_slice(&resp_type.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // flags
    v.extend_from_slice(&0u64.to_le_bytes()); // fence_id
    v.extend_from_slice(&0u32.to_le_bytes()); // ctx_id
    v.extend_from_slice(&0u32.to_le_bytes()); // ring_idx + padding
    v
}

fn gpu_response_with_fence(resp_type: u32, flags: u32, fence_id: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(24);
    push_header(&mut v, resp_type, flags, fence_id);
    v
}

fn push_header(v: &mut Vec<u8>, resp_type: u32, flags: u32, fence_id: u64) {
    v.extend_from_slice(&resp_type.to_le_bytes());
    v.extend_from_slice(&flags.to_le_bytes());
    v.extend_from_slice(&fence_id.to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes()); // ctx_id
    v.extend_from_slice(&0u32.to_le_bytes()); // ring_idx + padding
}

/// Generate a minimal EDID block for the given resolution
fn generate_edid(width: u32, height: u32) -> Vec<u8> {
    let mut edid = vec![0u8; 128];

    // Header
    edid[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);

    // Manufacturer ID: "VRT" (VirtIO) encoded as PnP ID
    // V=0x16, R=0x12, T=0x14 → ((0x16-1)<<10)|((0x12-1)<<5)|(0x14-1) = 0xAA53
    edid[8] = 0xAA;
    edid[9] = 0x53;

    // Product code
    edid[10] = 0x01;
    edid[11] = 0x00;

    // Serial number
    edid[12..16].copy_from_slice(&[0x01, 0x00, 0x00, 0x00]);

    // Week 1, year 2024 (2024-1990=34)
    edid[16] = 1;
    edid[17] = 34;

    // EDID version 1.4
    edid[18] = 1;
    edid[19] = 4;

    // Basic display parameters: digital, 8 bits/color, RGB
    edid[20] = 0xA5;
    // Max H/V image size in cm (approximate)
    edid[21] = (width / 40) as u8;
    edid[22] = (height / 40) as u8;
    // Gamma (2.2 = 120 + 100 = 220 → stored as 120)
    edid[23] = 120;
    // Supported features
    edid[24] = 0x06;

    // Chromaticity coordinates (sRGB approximation)
    edid[25..35].copy_from_slice(&[0xEE, 0x91, 0xA3, 0x54, 0x4C, 0x99, 0x26, 0x0F, 0x50, 0x54]);

    // Standard timings (unused — fill with 0x01 0x01)
    for i in (38..54).step_by(2) {
        edid[i] = 0x01;
        edid[i + 1] = 0x01;
    }

    // Detailed timing descriptor for preferred mode
    let pixel_clock = ((width as u64) * (height as u64) * 60 / 10000) as u16;
    edid[54] = pixel_clock as u8;
    edid[55] = (pixel_clock >> 8) as u8;
    edid[56] = (width & 0xFF) as u8;
    edid[57] = 0; // H blanking low
    edid[58] = ((width >> 4) & 0xF0) as u8; // H active high | H blanking high
    edid[59] = (height & 0xFF) as u8;
    edid[60] = 0; // V blanking low
    edid[61] = ((height >> 4) & 0xF0) as u8; // V active high | V blanking high

    // Display descriptor: monitor name
    let name_block_start = 72;
    edid[name_block_start] = 0;
    edid[name_block_start + 1] = 0;
    edid[name_block_start + 2] = 0;
    edid[name_block_start + 3] = 0xFC; // Monitor name tag
    edid[name_block_start + 4] = 0;
    let name = b"microvm GPU\n";
    for (i, &b) in name.iter().enumerate() {
        if name_block_start + 5 + i < 90 {
            edid[name_block_start + 5 + i] = b;
        }
    }

    // Compute checksum
    let sum: u8 = edid[0..127].iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    edid[127] = 0u8.wrapping_sub(sum);

    edid
}

// --- RAM helpers (same pattern as other VirtIO devices) ---

fn read_ram_u16(ram: &[u8], addr: u64, dram_base: u64) -> u16 {
    let off = (addr - dram_base) as usize;
    if off + 1 < ram.len() {
        u16::from_le_bytes([ram[off], ram[off + 1]])
    } else {
        0
    }
}

fn read_ram_u32(ram: &[u8], addr: u64, dram_base: u64) -> u32 {
    let off = (addr - dram_base) as usize;
    if off + 3 < ram.len() {
        u32::from_le_bytes([ram[off], ram[off + 1], ram[off + 2], ram[off + 3]])
    } else {
        0
    }
}

fn read_ram_u64(ram: &[u8], addr: u64, dram_base: u64) -> u64 {
    let off = (addr - dram_base) as usize;
    if off + 7 < ram.len() {
        u64::from_le_bytes([
            ram[off],
            ram[off + 1],
            ram[off + 2],
            ram[off + 3],
            ram[off + 4],
            ram[off + 5],
            ram[off + 6],
            ram[off + 7],
        ])
    } else {
        0
    }
}

fn write_ram_u16(ram: &mut [u8], addr: u64, val: u16, dram_base: u64) {
    let off = (addr - dram_base) as usize;
    if off + 1 < ram.len() {
        let bytes = val.to_le_bytes();
        ram[off] = bytes[0];
        ram[off + 1] = bytes[1];
    }
}

fn write_ram_u32(ram: &mut [u8], addr: u64, val: u32, dram_base: u64) {
    let off = (addr - dram_base) as usize;
    if off + 3 < ram.len() {
        let bytes = val.to_le_bytes();
        ram[off] = bytes[0];
        ram[off + 1] = bytes[1];
        ram[off + 2] = bytes[2];
        ram[off + 3] = bytes[3];
    }
}

fn write_ram_bytes(ram: &mut [u8], addr: u64, data: &[u8], dram_base: u64) {
    let off = (addr - dram_base) as usize;
    if off + data.len() <= ram.len() {
        ram[off..off + data.len()].copy_from_slice(data);
    }
}

/// Walk a descriptor chain and return (read_data, write_descriptors)
fn collect_descriptors(
    ram: &[u8],
    desc_table: u64,
    start_idx: u64,
    queue_num: u32,
    dram_base: u64,
) -> (Vec<u8>, Vec<(u64, u32)>) {
    let mut read_data = Vec::new();
    let mut write_descs = Vec::new();
    let mut idx = start_idx;
    let mut count = 0u32;

    loop {
        if count >= queue_num {
            break;
        }
        count += 1;

        let desc_off = desc_table + idx * 16;
        let addr = read_ram_u64(ram, desc_off, dram_base);
        let len = read_ram_u32(ram, desc_off + 8, dram_base);
        let flags = read_ram_u16(ram, desc_off + 12, dram_base);
        let next = read_ram_u16(ram, desc_off + 14, dram_base);

        if flags & VRING_DESC_F_WRITE != 0 {
            write_descs.push((addr, len));
        } else {
            // Read descriptor — copy data from guest memory
            for i in 0..len as u64 {
                let phys = addr + i;
                if phys >= dram_base {
                    let ram_off = (phys - dram_base) as usize;
                    if ram_off < ram.len() {
                        read_data.push(ram[ram_off]);
                    } else {
                        read_data.push(0);
                    }
                } else {
                    read_data.push(0);
                }
            }
        }

        if flags & VRING_DESC_F_NEXT == 0 {
            break;
        }
        idx = next as u64;
    }

    (read_data, write_descs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_magic_and_device_id() {
        let gpu = VirtioGpu::new();
        assert_eq!(gpu.read(MAGIC_VALUE), 0x7472_6976);
        assert_eq!(gpu.read(VERSION), 2);
        assert_eq!(gpu.read(DEVICE_ID), 16);
        assert_eq!(gpu.read(VENDOR_ID), 0x554D4551);
    }

    #[test]
    fn gpu_config_space() {
        let gpu = VirtioGpu::new();
        assert_eq!(gpu.read(CONFIG_BASE), 0); // events_read
        assert_eq!(gpu.read(0x108), MAX_SCANOUTS); // num_scanouts
        assert_eq!(gpu.read(0x10C), 0); // num_capsets
    }

    #[test]
    fn gpu_queue_setup() {
        let mut gpu = VirtioGpu::new();
        gpu.write(QUEUE_SEL, 0);
        assert_eq!(gpu.read(QUEUE_NUM_MAX), QUEUE_SIZE);
        gpu.write(QUEUE_NUM, 32);
        gpu.write(QUEUE_READY, 1);
        assert_eq!(gpu.read(QUEUE_READY), 1);
    }

    #[test]
    fn gpu_queue_addresses() {
        let mut gpu = VirtioGpu::new();
        gpu.write(QUEUE_SEL, 0);
        gpu.write(QUEUE_DESC_LOW, 0x1000);
        gpu.write(QUEUE_DESC_HIGH, 0x0);
        gpu.write(QUEUE_AVAIL_LOW, 0x2000);
        gpu.write(QUEUE_AVAIL_HIGH, 0x0);
        gpu.write(QUEUE_USED_LOW, 0x3000);
        gpu.write(QUEUE_USED_HIGH, 0x0);
        assert_eq!(gpu.queues[0].desc_addr, 0x1000);
        assert_eq!(gpu.queues[0].avail_addr, 0x2000);
        assert_eq!(gpu.queues[0].used_addr, 0x3000);
    }

    #[test]
    fn gpu_status_and_reset() {
        let mut gpu = VirtioGpu::new();
        gpu.write(STATUS, 0x0F);
        assert_eq!(gpu.read(STATUS), 0x0F);
        gpu.write(STATUS, 0); // reset
        assert_eq!(gpu.read(STATUS), 0);
    }

    #[test]
    fn gpu_interrupt_ack() {
        let mut gpu = VirtioGpu::new();
        gpu.interrupt_status = 3;
        assert_eq!(gpu.read(INTERRUPT_STATUS), 3);
        gpu.write(INTERRUPT_ACK, 1);
        assert_eq!(gpu.read(INTERRUPT_STATUS), 2);
        gpu.write(INTERRUPT_ACK, 2);
        assert_eq!(gpu.read(INTERRUPT_STATUS), 0);
    }

    #[test]
    fn gpu_features() {
        let mut gpu = VirtioGpu::new();
        gpu.write(DEVICE_FEATURES_SEL, 0);
        assert_eq!(gpu.read(DEVICE_FEATURES), VIRTIO_GPU_F_EDID as u32);
        gpu.write(DEVICE_FEATURES_SEL, 1);
        assert_eq!(gpu.read(DEVICE_FEATURES), 0);
    }

    #[test]
    fn gpu_driver_features() {
        let mut gpu = VirtioGpu::new();
        gpu.write(DRIVER_FEATURES_SEL, 0);
        gpu.write(DRIVER_FEATURES, 0xABCD);
        assert_eq!(gpu.driver_features & 0xFFFF_FFFF, 0xABCD);
        gpu.write(DRIVER_FEATURES_SEL, 1);
        gpu.write(DRIVER_FEATURES, 0x1234);
        assert_eq!(gpu.driver_features >> 32, 0x1234);
    }

    #[test]
    fn gpu_events_clear() {
        let mut gpu = VirtioGpu::new();
        gpu.events_read = 0x03;
        assert_eq!(gpu.read(CONFIG_BASE), 0x03);
        gpu.write(0x104, 0x01); // clear bit 0
        assert_eq!(gpu.read(CONFIG_BASE), 0x02);
    }

    #[test]
    fn gpu_get_display_info() {
        let gpu = VirtioGpu::new();
        let resp = gpu.cmd_get_display_info(0, 0);
        // Header (24) + 16 scanouts * 24 bytes = 408
        assert_eq!(resp.len(), 24 + 16 * 24);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_DISPLAY_INFO);
        // First scanout width/height
        let w = u32::from_le_bytes([resp[32], resp[33], resp[34], resp[35]]);
        let h = u32::from_le_bytes([resp[36], resp[37], resp[38], resp[39]]);
        assert_eq!(w, DEFAULT_WIDTH);
        assert_eq!(h, DEFAULT_HEIGHT);
    }

    #[test]
    fn gpu_resource_create_and_unref() {
        let mut gpu = VirtioGpu::new();
        // Create resource
        let mut cmd = vec![0u8; 24 + 16];
        cmd[0..4].copy_from_slice(&VIRTIO_GPU_CMD_RESOURCE_CREATE_2D.to_le_bytes());
        cmd[24..28].copy_from_slice(&1u32.to_le_bytes()); // resource_id=1
        cmd[28..32].copy_from_slice(&VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.to_le_bytes());
        cmd[32..36].copy_from_slice(&640u32.to_le_bytes()); // width
        cmd[36..40].copy_from_slice(&480u32.to_le_bytes()); // height
        let resp = gpu.cmd_resource_create_2d(&cmd, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_NODATA);
        assert_eq!(gpu.resources.len(), 1);
        assert_eq!(gpu.resources[0].width, 640);
        assert_eq!(gpu.resources[0].height, 480);

        // Unref resource
        let mut cmd2 = vec![0u8; 28];
        cmd2[24..28].copy_from_slice(&1u32.to_le_bytes());
        let resp2 = gpu.cmd_resource_unref(&cmd2, 0, 0);
        let resp_type2 = u32::from_le_bytes([resp2[0], resp2[1], resp2[2], resp2[3]]);
        assert_eq!(resp_type2, VIRTIO_GPU_RESP_OK_NODATA);
        assert_eq!(gpu.resources.len(), 0);
    }

    #[test]
    fn gpu_resource_create_invalid_id() {
        let mut gpu = VirtioGpu::new();
        let mut cmd = vec![0u8; 24 + 16];
        cmd[0..4].copy_from_slice(&VIRTIO_GPU_CMD_RESOURCE_CREATE_2D.to_le_bytes());
        // resource_id = 0 is invalid
        cmd[28..32].copy_from_slice(&VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.to_le_bytes());
        cmd[32..36].copy_from_slice(&100u32.to_le_bytes());
        cmd[36..40].copy_from_slice(&100u32.to_le_bytes());
        let resp = gpu.cmd_resource_create_2d(&cmd, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID);
    }

    #[test]
    fn gpu_set_scanout() {
        let mut gpu = VirtioGpu::new();
        // Create resource first
        let mut cmd = vec![0u8; 24 + 16];
        cmd[24..28].copy_from_slice(&1u32.to_le_bytes());
        cmd[28..32].copy_from_slice(&VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.to_le_bytes());
        cmd[32..36].copy_from_slice(&1024u32.to_le_bytes());
        cmd[36..40].copy_from_slice(&768u32.to_le_bytes());
        gpu.cmd_resource_create_2d(&cmd, 0, 0);

        // Set scanout
        let mut cmd2 = vec![0u8; 24 + 24];
        cmd2[32..36].copy_from_slice(&1024u32.to_le_bytes()); // width
        cmd2[36..40].copy_from_slice(&768u32.to_le_bytes()); // height
        cmd2[40..44].copy_from_slice(&0u32.to_le_bytes()); // scanout_id=0
        cmd2[44..48].copy_from_slice(&1u32.to_le_bytes()); // resource_id=1
        let resp = gpu.cmd_set_scanout(&cmd2, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_NODATA);
        assert!(gpu.scanouts[0].enabled);
        assert_eq!(gpu.scanouts[0].resource_id, 1);
    }

    #[test]
    fn gpu_set_scanout_disable() {
        let mut gpu = VirtioGpu::new();
        gpu.scanouts[0].enabled = true;
        gpu.scanouts[0].resource_id = 1;

        // Disable scanout by setting resource_id=0
        let mut cmd = vec![0u8; 24 + 24];
        cmd[40..44].copy_from_slice(&0u32.to_le_bytes()); // scanout_id=0
                                                          // resource_id=0 (disable)
        let resp = gpu.cmd_set_scanout(&cmd, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_NODATA);
        assert!(!gpu.scanouts[0].enabled);
    }

    #[test]
    fn gpu_attach_and_detach_backing() {
        let mut gpu = VirtioGpu::new();
        // Create resource
        let mut cmd = vec![0u8; 24 + 16];
        cmd[24..28].copy_from_slice(&1u32.to_le_bytes());
        cmd[28..32].copy_from_slice(&VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.to_le_bytes());
        cmd[32..36].copy_from_slice(&4u32.to_le_bytes()); // 4x4
        cmd[36..40].copy_from_slice(&4u32.to_le_bytes());
        gpu.cmd_resource_create_2d(&cmd, 0, 0);

        // Attach backing: 1 entry at addr=0x80001000, length=64
        let mut cmd2 = vec![0u8; 24 + 8 + 16];
        cmd2[24..28].copy_from_slice(&1u32.to_le_bytes()); // resource_id
        cmd2[28..32].copy_from_slice(&1u32.to_le_bytes()); // nr_entries
        cmd2[32..40].copy_from_slice(&0x8000_1000u64.to_le_bytes()); // addr
        cmd2[40..44].copy_from_slice(&64u32.to_le_bytes()); // length
        let ram = vec![0u8; 1024];
        let resp = gpu.cmd_resource_attach_backing(&cmd2, &ram, 0x8000_0000, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_NODATA);
        assert_eq!(gpu.resources[0].backing.len(), 1);

        // Detach backing
        let mut cmd3 = vec![0u8; 28];
        cmd3[24..28].copy_from_slice(&1u32.to_le_bytes());
        let resp2 = gpu.cmd_resource_detach_backing(&cmd3, 0, 0);
        let resp_type2 = u32::from_le_bytes([resp2[0], resp2[1], resp2[2], resp2[3]]);
        assert_eq!(resp_type2, VIRTIO_GPU_RESP_OK_NODATA);
        assert_eq!(gpu.resources[0].backing.len(), 0);
    }

    #[test]
    fn gpu_transfer_to_host_2d() {
        let mut gpu = VirtioGpu::new();
        let dram_base: u64 = 0x8000_0000;

        // Create a 4x4 resource
        let mut cmd = vec![0u8; 24 + 16];
        cmd[24..28].copy_from_slice(&1u32.to_le_bytes());
        cmd[28..32].copy_from_slice(&VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.to_le_bytes());
        cmd[32..36].copy_from_slice(&4u32.to_le_bytes());
        cmd[36..40].copy_from_slice(&4u32.to_le_bytes());
        gpu.cmd_resource_create_2d(&cmd, 0, 0);

        // Set up RAM with pixel data
        let mut ram = vec![0u8; 0x2000];
        // Write 64 bytes (4x4x4) of pixel data at offset 0x1000
        for i in 0..64 {
            ram[0x1000 + i] = (i as u8).wrapping_mul(3);
        }

        // Attach backing
        let mut cmd2 = vec![0u8; 24 + 8 + 16];
        cmd2[24..28].copy_from_slice(&1u32.to_le_bytes());
        cmd2[28..32].copy_from_slice(&1u32.to_le_bytes());
        cmd2[32..40].copy_from_slice(&(dram_base + 0x1000).to_le_bytes());
        cmd2[40..44].copy_from_slice(&64u32.to_le_bytes());
        gpu.cmd_resource_attach_backing(&cmd2, &ram, dram_base, 0, 0);

        // Transfer 4x4 rect
        let mut cmd3 = vec![0u8; 24 + 28];
        // rect: x=0, y=0, w=4, h=4
        cmd3[32..36].copy_from_slice(&4u32.to_le_bytes()); // width
        cmd3[36..40].copy_from_slice(&4u32.to_le_bytes()); // height
        cmd3[48..52].copy_from_slice(&1u32.to_le_bytes()); // resource_id

        let resp = gpu.cmd_transfer_to_host_2d(&cmd3, &ram, dram_base, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_NODATA);

        // Verify pixels were copied
        assert_eq!(gpu.resources[0].data[0], 0);
        assert_eq!(gpu.resources[0].data[1], 3);
        assert_eq!(gpu.resources[0].data[2], 6);
    }

    #[test]
    fn gpu_resource_flush_valid() {
        let mut gpu = VirtioGpu::new();
        // Create resource
        let mut cmd = vec![0u8; 24 + 16];
        cmd[24..28].copy_from_slice(&1u32.to_le_bytes());
        cmd[28..32].copy_from_slice(&VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.to_le_bytes());
        cmd[32..36].copy_from_slice(&100u32.to_le_bytes());
        cmd[36..40].copy_from_slice(&100u32.to_le_bytes());
        gpu.cmd_resource_create_2d(&cmd, 0, 0);

        // Flush
        let mut cmd2 = vec![0u8; 44];
        cmd2[40..44].copy_from_slice(&1u32.to_le_bytes()); // resource_id
        let resp = gpu.cmd_resource_flush(&cmd2, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_NODATA);
    }

    #[test]
    fn gpu_resource_flush_invalid() {
        let gpu = VirtioGpu::new();
        let mut cmd = vec![0u8; 44];
        cmd[40..44].copy_from_slice(&99u32.to_le_bytes());
        let resp = gpu.cmd_resource_flush(&cmd, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID);
    }

    #[test]
    fn gpu_get_edid() {
        let gpu = VirtioGpu::new();
        let mut cmd = vec![0u8; 28];
        cmd[24..28].copy_from_slice(&0u32.to_le_bytes()); // scanout 0
        let resp = gpu.cmd_get_edid(&cmd, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_EDID);
        // Verify EDID header at offset 32 (24 header + 4 size + 4 padding)
        assert_eq!(resp[32], 0x00);
        assert_eq!(resp[33], 0xFF);
        assert_eq!(resp[34], 0xFF);
    }

    #[test]
    fn gpu_get_edid_invalid_scanout() {
        let gpu = VirtioGpu::new();
        let mut cmd = vec![0u8; 28];
        cmd[24..28].copy_from_slice(&99u32.to_le_bytes());
        let resp = gpu.cmd_get_edid(&cmd, 0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER);
    }

    #[test]
    fn gpu_edid_checksum() {
        let edid = generate_edid(1024, 768);
        let sum: u8 = edid.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
        assert_eq!(sum, 0, "EDID checksum must be 0");
    }

    #[test]
    fn gpu_capset_info() {
        let gpu = VirtioGpu::new();
        let resp = gpu.cmd_get_capset_info(0, 0);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_OK_CAPSET_INFO);
    }

    #[test]
    fn gpu_has_interrupt() {
        let mut gpu = VirtioGpu::new();
        assert!(!gpu.has_interrupt());
        gpu.interrupt_status = 1;
        assert!(gpu.has_interrupt());
    }

    #[test]
    fn gpu_unref_clears_scanout() {
        let mut gpu = VirtioGpu::new();
        // Create resource and assign to scanout
        gpu.resources.push(GpuResource {
            id: 5,
            width: 100,
            height: 100,
            format: VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM,
            data: vec![0; 40000],
            backing: Vec::new(),
        });
        gpu.scanouts[0].resource_id = 5;
        gpu.scanouts[0].enabled = true;

        let mut cmd = vec![0u8; 28];
        cmd[24..28].copy_from_slice(&5u32.to_le_bytes());
        gpu.cmd_resource_unref(&cmd, 0, 0);
        assert!(!gpu.scanouts[0].enabled);
        assert_eq!(gpu.scanouts[0].resource_id, 0);
    }

    #[test]
    fn gpu_handle_unknown_command() {
        let mut gpu = VirtioGpu::new();
        let mut data = vec![0u8; 24];
        data[0..4].copy_from_slice(&0xFFFFu32.to_le_bytes()); // unknown type
        let resp = gpu.handle_command(&data, &mut [], 0x8000_0000);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_ERR_UNSPEC);
    }

    #[test]
    fn gpu_handle_short_command() {
        let mut gpu = VirtioGpu::new();
        let data = vec![0u8; 10]; // too short
        let resp = gpu.handle_command(&data, &mut [], 0x8000_0000);
        let resp_type = u32::from_le_bytes([resp[0], resp[1], resp[2], resp[3]]);
        assert_eq!(resp_type, VIRTIO_GPU_RESP_ERR_UNSPEC);
    }

    #[test]
    fn gpu_fence_propagation() {
        let mut gpu = VirtioGpu::new();
        // Create resource with fence
        let mut cmd = vec![0u8; 24 + 16];
        cmd[0..4].copy_from_slice(&VIRTIO_GPU_CMD_RESOURCE_CREATE_2D.to_le_bytes());
        cmd[4..8].copy_from_slice(&1u32.to_le_bytes()); // flags = FENCE
        cmd[8..16].copy_from_slice(&42u64.to_le_bytes()); // fence_id = 42
        cmd[24..28].copy_from_slice(&1u32.to_le_bytes());
        cmd[28..32].copy_from_slice(&VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM.to_le_bytes());
        cmd[32..36].copy_from_slice(&10u32.to_le_bytes());
        cmd[36..40].copy_from_slice(&10u32.to_le_bytes());
        let resp = gpu.handle_command(&cmd, &mut [], 0x8000_0000);
        // Verify fence_id is echoed back
        let fence = u64::from_le_bytes([
            resp[8], resp[9], resp[10], resp[11], resp[12], resp[13], resp[14], resp[15],
        ]);
        assert_eq!(fence, 42);
    }
}
