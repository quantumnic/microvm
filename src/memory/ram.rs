/// Simple RAM backed by a Vec<u8>
pub struct Ram {
    data: Vec<u8>,
}

impl Ram {
    pub fn new(size: u64) -> Self {
        Self {
            data: vec![0; size as usize],
        }
    }

    pub fn size(&self) -> u64 {
        self.data.len() as u64
    }

    pub fn read8(&self, offset: u64) -> u8 {
        let idx = offset as usize;
        if idx < self.data.len() {
            self.data[idx]
        } else {
            0
        }
    }

    #[allow(dead_code)]
    pub fn read16(&self, offset: u64) -> u16 {
        let idx = offset as usize;
        if idx + 1 < self.data.len() {
            u16::from_le_bytes([self.data[idx], self.data[idx + 1]])
        } else {
            0
        }
    }

    pub fn read32(&self, offset: u64) -> u32 {
        let idx = offset as usize;
        if idx + 3 < self.data.len() {
            u32::from_le_bytes([
                self.data[idx],
                self.data[idx + 1],
                self.data[idx + 2],
                self.data[idx + 3],
            ])
        } else {
            0
        }
    }

    pub fn read64(&self, offset: u64) -> u64 {
        let idx = offset as usize;
        if idx + 7 < self.data.len() {
            u64::from_le_bytes([
                self.data[idx],
                self.data[idx + 1],
                self.data[idx + 2],
                self.data[idx + 3],
                self.data[idx + 4],
                self.data[idx + 5],
                self.data[idx + 6],
                self.data[idx + 7],
            ])
        } else {
            0
        }
    }

    pub fn write8(&mut self, offset: u64, val: u8) {
        let idx = offset as usize;
        if idx < self.data.len() {
            self.data[idx] = val;
        }
    }

    #[allow(dead_code)]
    pub fn write16(&mut self, offset: u64, val: u16) {
        let idx = offset as usize;
        if idx + 1 < self.data.len() {
            let bytes = val.to_le_bytes();
            self.data[idx..idx + 2].copy_from_slice(&bytes);
        }
    }

    pub fn write32(&mut self, offset: u64, val: u32) {
        let idx = offset as usize;
        if idx + 3 < self.data.len() {
            let bytes = val.to_le_bytes();
            self.data[idx..idx + 4].copy_from_slice(&bytes);
        }
    }

    pub fn write64(&mut self, offset: u64, val: u64) {
        let idx = offset as usize;
        if idx + 7 < self.data.len() {
            let bytes = val.to_le_bytes();
            self.data[idx..idx + 8].copy_from_slice(&bytes);
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn load(&mut self, data: &[u8], offset: u64) {
        let start = offset as usize;
        let end = start + data.len();
        if end <= self.data.len() {
            self.data[start..end].copy_from_slice(data);
        }
    }
}
