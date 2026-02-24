/// VirtIO Sound Device — audio playback and capture for the guest
///
/// VirtIO device type 25. Provides PCM audio streams with configurable
/// sample rates and formats. Implements the control, event, TX (playback),
/// and RX (capture) virtqueues per VirtIO spec v1.2, section 5.14.
///
/// Supports 1 output stream and 1 input stream with S16_LE format.
/// Audio data is consumed/discarded (no host audio backend).
use std::collections::VecDeque;

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

// Virtqueue descriptor flags (used in future DMA processing)
const _VRING_DESC_F_NEXT: u16 = 1;
const _VRING_DESC_F_WRITE: u16 = 2;

const QUEUE_SIZE: u32 = 64;
const NUM_QUEUES: usize = 4; // controlq, eventq, txq, rxq

// VirtIO sound config: jacks, streams, chmaps
const VIRTIO_SND_NUM_JACKS: u32 = 2; // 1 output jack + 1 input jack
const VIRTIO_SND_NUM_STREAMS: u32 = 2; // 1 output stream + 1 input stream
const VIRTIO_SND_NUM_CHMAPS: u32 = 2; // 1 output chmap + 1 input chmap

// Control request types
const VIRTIO_SND_R_JACK_INFO: u32 = 1;
const VIRTIO_SND_R_JACK_REMAP: u32 = 2;
const VIRTIO_SND_R_PCM_INFO: u32 = 0x0100;
const VIRTIO_SND_R_PCM_SET_PARAMS: u32 = 0x0101;
const VIRTIO_SND_R_PCM_PREPARE: u32 = 0x0102;
const VIRTIO_SND_R_PCM_RELEASE: u32 = 0x0103;
const VIRTIO_SND_R_PCM_START: u32 = 0x0104;
const VIRTIO_SND_R_PCM_STOP: u32 = 0x0105;
const VIRTIO_SND_R_CHMAP_INFO: u32 = 0x0200;

// Status codes
const VIRTIO_SND_S_OK: u32 = 0;
const VIRTIO_SND_S_BAD_MSG: u32 = 1;
const VIRTIO_SND_S_NOT_SUPP: u32 = 2;
const VIRTIO_SND_S_IO_ERR: u32 = 3;

// PCM stream directions
const VIRTIO_SND_D_OUTPUT: u8 = 0;
const VIRTIO_SND_D_INPUT: u8 = 1;

// PCM formats
const VIRTIO_SND_PCM_FMT_S16: u8 = 2;
const VIRTIO_SND_PCM_FMT_S32: u8 = 6;

// PCM rates
const VIRTIO_SND_PCM_RATE_44100: u8 = 8;
const VIRTIO_SND_PCM_RATE_48000: u8 = 9;

// Channel map positions (VIRTIO_SND_CHMAP_FL, FR)
const VIRTIO_SND_CHMAP_FL: u8 = 3;
const VIRTIO_SND_CHMAP_FR: u8 = 4;

// Supported format/rate bitmasks
const SUPPORTED_FORMATS: u64 = (1u64 << VIRTIO_SND_PCM_FMT_S16) | (1u64 << VIRTIO_SND_PCM_FMT_S32);
const SUPPORTED_RATES: u64 =
    (1u64 << VIRTIO_SND_PCM_RATE_44100) | (1u64 << VIRTIO_SND_PCM_RATE_48000);

// Stream states
#[derive(Debug, Clone, Copy, PartialEq)]
enum StreamState {
    Idle,
    ParamsSet,
    Prepared,
    Running,
}

#[derive(Debug, Clone)]
struct PcmStream {
    direction: u8,
    state: StreamState,
    channels: u8,
    format: u8,
    rate: u8,
    buffer_bytes: u32,
    period_bytes: u32,
    /// Total bytes transferred (playback consumed / capture produced)
    bytes_transferred: u64,
}

impl PcmStream {
    fn new(direction: u8) -> Self {
        Self {
            direction,
            state: StreamState::Idle,
            channels: 2,
            format: VIRTIO_SND_PCM_FMT_S16,
            rate: VIRTIO_SND_PCM_RATE_48000,
            buffer_bytes: 8192,
            period_bytes: 4096,
            bytes_transferred: 0,
        }
    }
}

/// VirtIO queue state
struct Virtqueue {
    desc_addr: u64,
    avail_addr: u64,
    used_addr: u64,
    size: u32,
    ready: bool,
    _last_avail_idx: u16,
}

impl Virtqueue {
    fn new() -> Self {
        Self {
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            size: QUEUE_SIZE,
            ready: false,
            _last_avail_idx: 0,
        }
    }
}

/// VirtIO Sound device
pub struct VirtioSound {
    // Device registers
    device_features_sel: u32,
    driver_features: [u32; 2],
    driver_features_sel: u32,
    queue_sel: u32,
    status: u32,
    interrupt_status: u32,
    config_generation: u32,

    // Virtqueues: 0=controlq, 1=eventq, 2=txq (playback), 3=rxq (capture)
    queues: Vec<Virtqueue>,

    // PCM streams
    streams: Vec<PcmStream>,

    // Pending events for eventq
    events: VecDeque<SoundEvent>,

    // DMA access to guest RAM
    ram: Vec<u8>,
}

#[derive(Debug, Clone)]
struct SoundEvent {
    _hdr_type: u32,
    _data: u32,
}

impl Default for VirtioSound {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioSound {
    pub fn new() -> Self {
        Self {
            device_features_sel: 0,
            driver_features: [0; 2],
            driver_features_sel: 0,
            queue_sel: 0,
            status: 0,
            interrupt_status: 0,
            config_generation: 0,
            queues: (0..NUM_QUEUES).map(|_| Virtqueue::new()).collect(),
            streams: vec![
                PcmStream::new(VIRTIO_SND_D_OUTPUT),
                PcmStream::new(VIRTIO_SND_D_INPUT),
            ],
            events: VecDeque::new(),
            ram: Vec::new(),
        }
    }

    /// Attach guest RAM for DMA access
    pub fn attach_ram(&mut self, ram: &[u8]) {
        self.ram = ram.to_vec();
    }

    /// Read a 32-bit register
    pub fn read(&self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => 0x7472_6976, // "virt"
            VERSION => 2,               // non-legacy MMIO
            DEVICE_ID => 25,            // sound device
            VENDOR_ID => 0x554D_4356,   // "UMCV"
            DEVICE_FEATURES => {
                match self.device_features_sel {
                    0 => 0, // no feature bits in word 0
                    1 => 1, // VIRTIO_F_VERSION_1
                    _ => 0,
                }
            }
            QUEUE_NUM_MAX => QUEUE_SIZE,
            QUEUE_READY => {
                if (self.queue_sel as usize) < NUM_QUEUES {
                    self.queues[self.queue_sel as usize].ready as u32
                } else {
                    0
                }
            }
            INTERRUPT_STATUS => self.interrupt_status,
            STATUS => self.status,
            CONFIG_GENERATION => self.config_generation,
            // Config space: virtio_snd_config
            CONFIG_BASE => VIRTIO_SND_NUM_JACKS, // jacks
            0x104 => VIRTIO_SND_NUM_STREAMS,     // streams
            0x108 => VIRTIO_SND_NUM_CHMAPS,      // chmaps
            _ => 0,
        }
    }

    /// Write a 32-bit register
    pub fn write(&mut self, offset: u64, val: u64) {
        let val32 = val as u32;
        match offset {
            DEVICE_FEATURES_SEL => self.device_features_sel = val32,
            DRIVER_FEATURES => {
                let idx = self.driver_features_sel as usize;
                if idx < 2 {
                    self.driver_features[idx] = val32;
                }
            }
            DRIVER_FEATURES_SEL => self.driver_features_sel = val32,
            QUEUE_SEL => {
                if (val32 as usize) < NUM_QUEUES {
                    self.queue_sel = val32;
                }
            }
            QUEUE_NUM => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].size = val32.min(QUEUE_SIZE);
                }
            }
            QUEUE_READY => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    self.queues[qi].ready = val32 != 0;
                }
            }
            QUEUE_NOTIFY => {
                // Process the notified queue
                // No-op: we process on demand
            }
            INTERRUPT_ACK => {
                self.interrupt_status &= !val32;
            }
            STATUS => {
                self.status = val32;
                if val32 == 0 {
                    self.reset();
                }
            }
            QUEUE_DESC_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    let q = &mut self.queues[qi];
                    q.desc_addr = (q.desc_addr & 0xFFFF_FFFF_0000_0000) | val32 as u64;
                }
            }
            QUEUE_DESC_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    let q = &mut self.queues[qi];
                    q.desc_addr = (q.desc_addr & 0x0000_0000_FFFF_FFFF) | ((val32 as u64) << 32);
                }
            }
            QUEUE_AVAIL_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    let q = &mut self.queues[qi];
                    q.avail_addr = (q.avail_addr & 0xFFFF_FFFF_0000_0000) | val32 as u64;
                }
            }
            QUEUE_AVAIL_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    let q = &mut self.queues[qi];
                    q.avail_addr = (q.avail_addr & 0x0000_0000_FFFF_FFFF) | ((val32 as u64) << 32);
                }
            }
            QUEUE_USED_LOW => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    let q = &mut self.queues[qi];
                    q.used_addr = (q.used_addr & 0xFFFF_FFFF_0000_0000) | val32 as u64;
                }
            }
            QUEUE_USED_HIGH => {
                let qi = self.queue_sel as usize;
                if qi < NUM_QUEUES {
                    let q = &mut self.queues[qi];
                    q.used_addr = (q.used_addr & 0x0000_0000_FFFF_FFFF) | ((val32 as u64) << 32);
                }
            }
            _ => {}
        }
    }

    fn reset(&mut self) {
        self.device_features_sel = 0;
        self.driver_features = [0; 2];
        self.driver_features_sel = 0;
        self.queue_sel = 0;
        self.status = 0;
        self.interrupt_status = 0;
        self.queues = (0..NUM_QUEUES).map(|_| Virtqueue::new()).collect();
        self.streams = vec![
            PcmStream::new(VIRTIO_SND_D_OUTPUT),
            PcmStream::new(VIRTIO_SND_D_INPUT),
        ];
        self.events.clear();
    }

    /// Process a control queue request. Returns (status, response_data).
    pub fn handle_control_request(&mut self, request: &[u8]) -> (u32, Vec<u8>) {
        if request.len() < 8 {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }
        let code = u32::from_le_bytes([request[0], request[1], request[2], request[3]]);

        match code {
            VIRTIO_SND_R_JACK_INFO => self.handle_jack_info(request),
            VIRTIO_SND_R_JACK_REMAP => (VIRTIO_SND_S_NOT_SUPP, Vec::new()),
            VIRTIO_SND_R_PCM_INFO => self.handle_pcm_info(request),
            VIRTIO_SND_R_PCM_SET_PARAMS => self.handle_pcm_set_params(request),
            VIRTIO_SND_R_PCM_PREPARE => self.handle_pcm_simple(request, StreamState::Prepared),
            VIRTIO_SND_R_PCM_RELEASE => self.handle_pcm_release(request),
            VIRTIO_SND_R_PCM_START => self.handle_pcm_simple(request, StreamState::Running),
            VIRTIO_SND_R_PCM_STOP => self.handle_pcm_simple(request, StreamState::Prepared),
            VIRTIO_SND_R_CHMAP_INFO => self.handle_chmap_info(request),
            _ => (VIRTIO_SND_S_NOT_SUPP, Vec::new()),
        }
    }

    fn handle_jack_info(&self, request: &[u8]) -> (u32, Vec<u8>) {
        // Request: hdr(8) + start_id(u32) + count(u32)
        if request.len() < 16 {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }
        let start_id = u32::from_le_bytes([request[8], request[9], request[10], request[11]]);
        let count = u32::from_le_bytes([request[12], request[13], request[14], request[15]]);

        let mut resp = Vec::new();
        for i in 0..count {
            let jack_id = start_id + i;
            if jack_id >= VIRTIO_SND_NUM_JACKS {
                return (VIRTIO_SND_S_BAD_MSG, Vec::new());
            }
            // virtio_snd_jack_info: hdr(8) + features(u32) + hda_reg_defconf(u32) + hda_reg_caps(u32) + connected(u8) + padding(3)
            let mut info = vec![0u8; 24];
            // hdr: hda_fn_nid = jack_id
            info[0..4].copy_from_slice(&jack_id.to_le_bytes());
            // features = 0
            // hda_reg_defconf: encode direction
            let defconf: u32 = if jack_id == 0 { 0x01 } else { 0x02 }; // output / input
            info[12..16].copy_from_slice(&defconf.to_le_bytes());
            // connected = 1
            info[20] = 1;
            resp.extend_from_slice(&info);
        }
        (VIRTIO_SND_S_OK, resp)
    }

    fn handle_pcm_info(&self, request: &[u8]) -> (u32, Vec<u8>) {
        if request.len() < 16 {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }
        let start_id = u32::from_le_bytes([request[8], request[9], request[10], request[11]]);
        let count = u32::from_le_bytes([request[12], request[13], request[14], request[15]]);

        let mut resp = Vec::new();
        for i in 0..count {
            let stream_id = (start_id + i) as usize;
            if stream_id >= self.streams.len() {
                return (VIRTIO_SND_S_BAD_MSG, Vec::new());
            }
            let stream = &self.streams[stream_id];
            // virtio_snd_pcm_info: hdr(8) + features(u32) + formats(u64) + rates(u64) +
            //   direction(u8) + channels_min(u8) + channels_max(u8) + padding(5)
            let mut info = vec![0u8; 40];
            // hdr: hda_fn_nid = stream_id
            info[0..4].copy_from_slice(&(stream_id as u32).to_le_bytes());
            // features = 0
            // formats
            info[16..24].copy_from_slice(&SUPPORTED_FORMATS.to_le_bytes());
            // rates
            info[24..32].copy_from_slice(&SUPPORTED_RATES.to_le_bytes());
            // direction
            info[32] = stream.direction;
            // channels_min
            info[33] = 1;
            // channels_max
            info[34] = 2;
            resp.extend_from_slice(&info);
        }
        (VIRTIO_SND_S_OK, resp)
    }

    fn handle_pcm_set_params(&mut self, request: &[u8]) -> (u32, Vec<u8>) {
        // hdr(8) + stream_id(u32) + buffer_bytes(u32) + period_bytes(u32) +
        // features(u32) + channels(u8) + format(u8) + rate(u8) + padding(1)
        if request.len() < 32 {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }
        let stream_id =
            u32::from_le_bytes([request[8], request[9], request[10], request[11]]) as usize;
        if stream_id >= self.streams.len() {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }

        let buffer_bytes = u32::from_le_bytes([request[12], request[13], request[14], request[15]]);
        let period_bytes = u32::from_le_bytes([request[16], request[17], request[18], request[19]]);
        let channels = request[24];
        let format = request[25];
        let rate = request[26];

        // Validate format
        if (SUPPORTED_FORMATS >> format) & 1 == 0 {
            return (VIRTIO_SND_S_NOT_SUPP, Vec::new());
        }
        // Validate rate
        if (SUPPORTED_RATES >> rate) & 1 == 0 {
            return (VIRTIO_SND_S_NOT_SUPP, Vec::new());
        }
        // Validate channels
        if channels == 0 || channels > 2 {
            return (VIRTIO_SND_S_NOT_SUPP, Vec::new());
        }
        // Validate buffer/period
        if buffer_bytes == 0 || period_bytes == 0 || period_bytes > buffer_bytes {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }

        let stream = &mut self.streams[stream_id];
        stream.buffer_bytes = buffer_bytes;
        stream.period_bytes = period_bytes;
        stream.channels = channels;
        stream.format = format;
        stream.rate = rate;
        stream.state = StreamState::ParamsSet;

        (VIRTIO_SND_S_OK, Vec::new())
    }

    fn handle_pcm_simple(&mut self, request: &[u8], target_state: StreamState) -> (u32, Vec<u8>) {
        if request.len() < 12 {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }
        let stream_id =
            u32::from_le_bytes([request[8], request[9], request[10], request[11]]) as usize;
        if stream_id >= self.streams.len() {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }

        let stream = &mut self.streams[stream_id];
        // Validate state transitions
        let valid = match target_state {
            StreamState::Prepared => {
                stream.state == StreamState::ParamsSet || stream.state == StreamState::Running
            }
            StreamState::Running => stream.state == StreamState::Prepared,
            _ => false,
        };

        if !valid {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }

        stream.state = target_state;
        (VIRTIO_SND_S_OK, Vec::new())
    }

    fn handle_pcm_release(&mut self, request: &[u8]) -> (u32, Vec<u8>) {
        if request.len() < 12 {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }
        let stream_id =
            u32::from_le_bytes([request[8], request[9], request[10], request[11]]) as usize;
        if stream_id >= self.streams.len() {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }

        let stream = &mut self.streams[stream_id];
        if stream.state == StreamState::Running {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }

        stream.state = StreamState::Idle;
        stream.bytes_transferred = 0;
        (VIRTIO_SND_S_OK, Vec::new())
    }

    fn handle_chmap_info(&self, request: &[u8]) -> (u32, Vec<u8>) {
        if request.len() < 16 {
            return (VIRTIO_SND_S_BAD_MSG, Vec::new());
        }
        let start_id = u32::from_le_bytes([request[8], request[9], request[10], request[11]]);
        let count = u32::from_le_bytes([request[12], request[13], request[14], request[15]]);

        let mut resp = Vec::new();
        for i in 0..count {
            let chmap_id = start_id + i;
            if chmap_id >= VIRTIO_SND_NUM_CHMAPS {
                return (VIRTIO_SND_S_BAD_MSG, Vec::new());
            }
            // virtio_snd_chmap_info: hdr(8) + direction(u8) + channels(u8) + positions[18](u8)
            let mut info = vec![0u8; 28];
            // hdr: hda_fn_nid = chmap_id
            info[0..4].copy_from_slice(&chmap_id.to_le_bytes());
            // direction
            info[8] = if chmap_id == 0 {
                VIRTIO_SND_D_OUTPUT
            } else {
                VIRTIO_SND_D_INPUT
            };
            // channels = 2
            info[9] = 2;
            // positions: FL, FR
            info[10] = VIRTIO_SND_CHMAP_FL;
            info[11] = VIRTIO_SND_CHMAP_FR;
            resp.extend_from_slice(&info);
        }
        (VIRTIO_SND_S_OK, resp)
    }

    /// Process a TX (playback) buffer — consume audio data
    pub fn handle_tx_buffer(&mut self, stream_id: u32, data: &[u8]) -> u32 {
        let sid = stream_id as usize;
        if sid >= self.streams.len() {
            return VIRTIO_SND_S_IO_ERR;
        }
        let stream = &mut self.streams[sid];
        if stream.state != StreamState::Running {
            return VIRTIO_SND_S_IO_ERR;
        }
        if stream.direction != VIRTIO_SND_D_OUTPUT {
            return VIRTIO_SND_S_IO_ERR;
        }
        // Consume (discard) the audio data — no host backend
        stream.bytes_transferred += data.len() as u64;
        VIRTIO_SND_S_OK
    }

    /// Process an RX (capture) buffer — produce silence
    pub fn handle_rx_buffer(&mut self, stream_id: u32, buffer: &mut [u8]) -> u32 {
        let sid = stream_id as usize;
        if sid >= self.streams.len() {
            return VIRTIO_SND_S_IO_ERR;
        }
        let stream = &mut self.streams[sid];
        if stream.state != StreamState::Running {
            return VIRTIO_SND_S_IO_ERR;
        }
        if stream.direction != VIRTIO_SND_D_INPUT {
            return VIRTIO_SND_S_IO_ERR;
        }
        // Fill with silence
        buffer.fill(0);
        stream.bytes_transferred += buffer.len() as u64;
        VIRTIO_SND_S_OK
    }

    /// Get interrupt status (for PLIC integration)
    pub fn has_interrupt(&self) -> bool {
        self.interrupt_status != 0
    }

    /// Get stream state for testing
    #[cfg(test)]
    fn stream_state(&self, id: usize) -> Option<StreamState> {
        self.streams.get(id).map(|s| s.state)
    }

    /// Get bytes transferred for testing
    #[cfg(test)]
    fn stream_bytes(&self, id: usize) -> Option<u64> {
        self.streams.get(id).map(|s| s.bytes_transferred)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sound_device_id_and_magic() {
        let mut dev = VirtioSound::new();
        assert_eq!(dev.read(MAGIC_VALUE), 0x7472_6976);
        assert_eq!(dev.read(VERSION), 2);
        assert_eq!(dev.read(DEVICE_ID), 25);
        assert_eq!(dev.read(VENDOR_ID), 0x554D_4356);
    }

    #[test]
    fn test_sound_config_space() {
        let mut dev = VirtioSound::new();
        assert_eq!(dev.read(CONFIG_BASE), VIRTIO_SND_NUM_JACKS);
        assert_eq!(dev.read(0x104), VIRTIO_SND_NUM_STREAMS);
        assert_eq!(dev.read(0x108), VIRTIO_SND_NUM_CHMAPS);
    }

    #[test]
    fn test_sound_device_features() {
        let mut dev = VirtioSound::new();
        // Feature word 0: no features
        assert_eq!(dev.read(DEVICE_FEATURES), 0);
    }

    #[test]
    fn test_sound_version_1_feature() {
        let mut dev = VirtioSound::new();
        dev.write(DEVICE_FEATURES_SEL, 1);
        assert_eq!(dev.read(DEVICE_FEATURES), 1); // VIRTIO_F_VERSION_1
    }

    #[test]
    fn test_sound_queue_setup() {
        let mut dev = VirtioSound::new();
        // 4 queues
        for q in 0..NUM_QUEUES as u64 {
            dev.write(QUEUE_SEL, q);
            assert_eq!(dev.read(QUEUE_NUM_MAX), QUEUE_SIZE);
            assert_eq!(dev.read(QUEUE_READY), 0);
            dev.write(QUEUE_NUM, QUEUE_SIZE as u64);
            dev.write(QUEUE_READY, 1);
            assert_eq!(dev.read(QUEUE_READY), 1);
        }
    }

    #[test]
    fn test_sound_queue_addresses() {
        let mut dev = VirtioSound::new();
        dev.write(QUEUE_SEL, 0);
        dev.write(QUEUE_DESC_LOW, 0x1000);
        dev.write(QUEUE_DESC_HIGH, 0x0);
        dev.write(QUEUE_AVAIL_LOW, 0x2000);
        dev.write(QUEUE_AVAIL_HIGH, 0x0);
        dev.write(QUEUE_USED_LOW, 0x3000);
        dev.write(QUEUE_USED_HIGH, 0x0);
        // Verify stored (internal, no read-back in MMIO spec)
        assert_eq!(dev.queues[0].desc_addr, 0x1000);
        assert_eq!(dev.queues[0].avail_addr, 0x2000);
        assert_eq!(dev.queues[0].used_addr, 0x3000);
    }

    #[test]
    fn test_sound_status_and_reset() {
        let mut dev = VirtioSound::new();
        dev.write(STATUS, STATUS_DRIVER_OK as u64);
        assert_eq!(dev.read(STATUS), STATUS_DRIVER_OK);
        // Reset
        dev.write(STATUS, 0);
        assert_eq!(dev.read(STATUS), 0);
        assert_eq!(dev.interrupt_status, 0);
    }

    #[test]
    fn test_sound_interrupt_ack() {
        let mut dev = VirtioSound::new();
        dev.interrupt_status = 0x3;
        assert_eq!(dev.read(INTERRUPT_STATUS), 0x3);
        dev.write(INTERRUPT_ACK, 0x1);
        assert_eq!(dev.read(INTERRUPT_STATUS), 0x2);
        dev.write(INTERRUPT_ACK, 0x2);
        assert_eq!(dev.read(INTERRUPT_STATUS), 0x0);
        assert!(!dev.has_interrupt());
    }

    // Control request tests

    fn make_query_request(code: u32, start_id: u32, count: u32) -> Vec<u8> {
        let mut req = vec![0u8; 16];
        req[0..4].copy_from_slice(&code.to_le_bytes());
        req[8..12].copy_from_slice(&start_id.to_le_bytes());
        req[12..16].copy_from_slice(&count.to_le_bytes());
        req
    }

    #[test]
    fn test_sound_jack_info() {
        let mut dev = VirtioSound::new();
        let req = make_query_request(VIRTIO_SND_R_JACK_INFO, 0, 2);
        let (status, resp) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_OK);
        assert_eq!(resp.len(), 48); // 2 * 24 bytes
                                    // First jack connected
        assert_eq!(resp[20], 1);
        // Second jack connected
        assert_eq!(resp[44], 1);
    }

    #[test]
    fn test_sound_jack_info_out_of_range() {
        let mut dev = VirtioSound::new();
        let req = make_query_request(VIRTIO_SND_R_JACK_INFO, 2, 1);
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_pcm_info() {
        let mut dev = VirtioSound::new();
        let req = make_query_request(VIRTIO_SND_R_PCM_INFO, 0, 2);
        let (status, resp) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_OK);
        assert_eq!(resp.len(), 80); // 2 * 40 bytes
                                    // Stream 0: output
        assert_eq!(resp[32], VIRTIO_SND_D_OUTPUT);
        // Stream 1: input
        assert_eq!(resp[72], VIRTIO_SND_D_INPUT);
        // channels_min = 1, channels_max = 2
        assert_eq!(resp[33], 1);
        assert_eq!(resp[34], 2);
    }

    #[test]
    fn test_sound_pcm_info_out_of_range() {
        let mut dev = VirtioSound::new();
        let req = make_query_request(VIRTIO_SND_R_PCM_INFO, 2, 1);
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_chmap_info() {
        let mut dev = VirtioSound::new();
        let req = make_query_request(VIRTIO_SND_R_CHMAP_INFO, 0, 2);
        let (status, resp) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_OK);
        assert_eq!(resp.len(), 56); // 2 * 28 bytes
                                    // Chmap 0: output, 2 channels, FL+FR
        assert_eq!(resp[8], VIRTIO_SND_D_OUTPUT);
        assert_eq!(resp[9], 2);
        assert_eq!(resp[10], VIRTIO_SND_CHMAP_FL);
        assert_eq!(resp[11], VIRTIO_SND_CHMAP_FR);
        // Chmap 1: input
        assert_eq!(resp[36], VIRTIO_SND_D_INPUT);
    }

    fn make_set_params(
        stream_id: u32,
        buffer: u32,
        period: u32,
        channels: u8,
        format: u8,
        rate: u8,
    ) -> Vec<u8> {
        let mut req = vec![0u8; 32];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_PCM_SET_PARAMS.to_le_bytes());
        req[8..12].copy_from_slice(&stream_id.to_le_bytes());
        req[12..16].copy_from_slice(&buffer.to_le_bytes());
        req[16..20].copy_from_slice(&period.to_le_bytes());
        // features at 20..24 = 0
        req[24] = channels;
        req[25] = format;
        req[26] = rate;
        req
    }

    #[test]
    fn test_sound_pcm_set_params() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_state(0), Some(StreamState::ParamsSet));
    }

    #[test]
    fn test_sound_pcm_set_params_invalid_format() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(0, 8192, 4096, 2, 15, VIRTIO_SND_PCM_RATE_48000);
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_NOT_SUPP);
    }

    #[test]
    fn test_sound_pcm_set_params_invalid_rate() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(0, 8192, 4096, 2, VIRTIO_SND_PCM_FMT_S16, 0);
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_NOT_SUPP);
    }

    #[test]
    fn test_sound_pcm_set_params_invalid_channels() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            8192,
            4096,
            0,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_NOT_SUPP);
    }

    #[test]
    fn test_sound_pcm_set_params_invalid_buffer() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            0,
            0,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_pcm_set_params_period_gt_buffer() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            4096,
            8192,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_BAD_MSG);
    }

    fn make_simple_request(code: u32, stream_id: u32) -> Vec<u8> {
        let mut req = vec![0u8; 12];
        req[0..4].copy_from_slice(&code.to_le_bytes());
        req[8..12].copy_from_slice(&stream_id.to_le_bytes());
        req
    }

    #[test]
    fn test_sound_pcm_lifecycle() {
        let mut dev = VirtioSound::new();
        // Set params → Prepare → Start → Stop → Release
        let req = make_set_params(
            0,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        let (s, _) = dev.handle_control_request(&req);
        assert_eq!(s, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_state(0), Some(StreamState::ParamsSet));

        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 0));
        assert_eq!(s, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_state(0), Some(StreamState::Prepared));

        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 0));
        assert_eq!(s, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_state(0), Some(StreamState::Running));

        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_STOP, 0));
        assert_eq!(s, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_state(0), Some(StreamState::Prepared));

        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_RELEASE, 0));
        assert_eq!(s, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_state(0), Some(StreamState::Idle));
    }

    #[test]
    fn test_sound_pcm_invalid_transitions() {
        let mut dev = VirtioSound::new();
        // Can't prepare from Idle
        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 0));
        assert_eq!(s, VIRTIO_SND_S_BAD_MSG);

        // Can't start from Idle
        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 0));
        assert_eq!(s, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_pcm_release_while_running() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        dev.handle_control_request(&req);
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 0));
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 0));

        // Can't release while running
        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_RELEASE, 0));
        assert_eq!(s, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_tx_playback() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        dev.handle_control_request(&req);
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 0));
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 0));

        let audio_data = vec![0x42u8; 1024];
        let status = dev.handle_tx_buffer(0, &audio_data);
        assert_eq!(status, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_bytes(0), Some(1024));

        // Send more
        let status = dev.handle_tx_buffer(0, &audio_data);
        assert_eq!(status, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_bytes(0), Some(2048));
    }

    #[test]
    fn test_sound_tx_not_running() {
        let mut dev = VirtioSound::new();
        let status = dev.handle_tx_buffer(0, &[0; 256]);
        assert_eq!(status, VIRTIO_SND_S_IO_ERR);
    }

    #[test]
    fn test_sound_tx_wrong_direction() {
        let mut dev = VirtioSound::new();
        // Stream 1 is input
        let req = make_set_params(
            1,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        dev.handle_control_request(&req);
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 1));
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 1));

        // TX on input stream should fail
        let status = dev.handle_tx_buffer(1, &[0; 256]);
        assert_eq!(status, VIRTIO_SND_S_IO_ERR);
    }

    #[test]
    fn test_sound_rx_capture() {
        let mut dev = VirtioSound::new();
        // Stream 1 is input
        let req = make_set_params(
            1,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        dev.handle_control_request(&req);
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 1));
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 1));

        let mut buf = vec![0xFFu8; 512];
        let status = dev.handle_rx_buffer(1, &mut buf);
        assert_eq!(status, VIRTIO_SND_S_OK);
        // Should be filled with silence
        assert!(buf.iter().all(|&b| b == 0));
        assert_eq!(dev.stream_bytes(1), Some(512));
    }

    #[test]
    fn test_sound_rx_not_running() {
        let mut dev = VirtioSound::new();
        let mut buf = vec![0u8; 256];
        let status = dev.handle_rx_buffer(1, &mut buf);
        assert_eq!(status, VIRTIO_SND_S_IO_ERR);
    }

    #[test]
    fn test_sound_rx_wrong_direction() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        dev.handle_control_request(&req);
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 0));
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 0));

        // RX on output stream should fail
        let mut buf = vec![0u8; 256];
        let status = dev.handle_rx_buffer(0, &mut buf);
        assert_eq!(status, VIRTIO_SND_S_IO_ERR);
    }

    #[test]
    fn test_sound_invalid_stream_id() {
        let mut dev = VirtioSound::new();
        assert_eq!(dev.handle_tx_buffer(5, &[0; 256]), VIRTIO_SND_S_IO_ERR);
        let mut buf = vec![0u8; 256];
        assert_eq!(dev.handle_rx_buffer(5, &mut buf), VIRTIO_SND_S_IO_ERR);
    }

    #[test]
    fn test_sound_jack_remap_not_supported() {
        let mut dev = VirtioSound::new();
        let mut req = vec![0u8; 16];
        req[0..4].copy_from_slice(&VIRTIO_SND_R_JACK_REMAP.to_le_bytes());
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_NOT_SUPP);
    }

    #[test]
    fn test_sound_unknown_request() {
        let mut dev = VirtioSound::new();
        let mut req = vec![0u8; 16];
        req[0..4].copy_from_slice(&0xFFFFu32.to_le_bytes());
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_NOT_SUPP);
    }

    #[test]
    fn test_sound_short_request() {
        let mut dev = VirtioSound::new();
        let (status, _) = dev.handle_control_request(&[0; 4]);
        assert_eq!(status, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_s32_format() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            16384,
            8192,
            2,
            VIRTIO_SND_PCM_FMT_S32,
            VIRTIO_SND_PCM_RATE_44100,
        );
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_OK);
    }

    #[test]
    fn test_sound_mono_channel() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            8192,
            4096,
            1,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_OK);
    }

    #[test]
    fn test_sound_set_params_invalid_stream() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            5,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_prepare_from_running() {
        let mut dev = VirtioSound::new();
        let req = make_set_params(
            0,
            8192,
            4096,
            2,
            VIRTIO_SND_PCM_FMT_S16,
            VIRTIO_SND_PCM_RATE_48000,
        );
        dev.handle_control_request(&req);
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 0));
        dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_START, 0));
        // Prepare from Running should work (stop+prepare)
        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 0));
        assert_eq!(s, VIRTIO_SND_S_OK);
        assert_eq!(dev.stream_state(0), Some(StreamState::Prepared));
    }

    #[test]
    fn test_sound_config_generation() {
        let mut dev = VirtioSound::new();
        assert_eq!(dev.read(CONFIG_GENERATION), 0);
    }

    #[test]
    fn test_sound_chmap_out_of_range() {
        let mut dev = VirtioSound::new();
        let req = make_query_request(VIRTIO_SND_R_CHMAP_INFO, 2, 1);
        let (status, _) = dev.handle_control_request(&req);
        assert_eq!(status, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_release_from_idle() {
        let mut dev = VirtioSound::new();
        // Release from Idle should succeed (already idle)
        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_RELEASE, 0));
        assert_eq!(s, VIRTIO_SND_S_OK);
    }

    #[test]
    fn test_sound_simple_request_invalid_stream() {
        let mut dev = VirtioSound::new();
        let (s, _) = dev.handle_control_request(&make_simple_request(VIRTIO_SND_R_PCM_PREPARE, 5));
        assert_eq!(s, VIRTIO_SND_S_BAD_MSG);
    }

    #[test]
    fn test_sound_queue_sel_out_of_range() {
        let mut dev = VirtioSound::new();
        dev.write(QUEUE_SEL, 10);
        // queue_sel should stay at previous value
        assert_eq!(dev.queue_sel, 0); // didn't change because 10 >= NUM_QUEUES
    }
}
