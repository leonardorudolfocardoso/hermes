use std::io::Write;

use crate::OwnedPacket;

pub type WriteResult = std::io::Result<usize>;

#[derive(Debug)]
pub struct PacketWriter {
    inner: OwnedPacket,
}

impl PacketWriter {
    #[cfg(test)]
    pub fn get(&self) -> &OwnedPacket {
        &self.inner
    }

    pub fn into_inner(self) -> OwnedPacket {
        self.inner
    }

    pub fn new() -> Self {
        PacketWriter {
            inner: OwnedPacket::new(),
        }
    }

    pub fn write_u8(&mut self, value: u8) -> WriteResult {
        let buf = [value];
        self.inner.write(&buf)
    }

    pub fn write_u16(&mut self, value: u16) -> WriteResult {
        let buf = value.to_be_bytes();
        self.inner.write(&buf)
    }

    pub fn write_u32(&mut self, value: u32) -> WriteResult {
        let buf = value.to_be_bytes();
        self.inner.write(&buf)
    }

    pub fn write(&mut self, buf: &[u8]) -> WriteResult {
        self.inner.extend_from_slice(buf);
        Ok(buf.len())
    }
}

#[cfg(test)]
mod test {
    use crate::writer::PacketWriter;

    #[test]
    fn write_u8() {
        let mut writer = PacketWriter::new();
        let n = writer.write_u8(12).unwrap();
        assert_eq!(n, 1);
        assert_eq!(writer.inner, [0x0c]);
    }
    #[test]
    fn write_u16() {
        let mut writer = PacketWriter::new();
        let n = writer.write_u16(0x1234).unwrap();
        assert_eq!(n, 2);
        assert_eq!(writer.inner, [0x12, 0x34]);
    }
    #[test]
    fn write_u32() {
        let mut writer = PacketWriter::new();
        let n = writer.write_u32(0x12345678).unwrap();
        assert_eq!(n, 4);
        assert_eq!(writer.inner, [0x12, 0x34, 0x56, 0x78]);
    }
}
