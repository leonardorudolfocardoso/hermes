use std::io::Write;

use crate::OwnedPacket;

type WriteResult = std::io::Result<usize>;

#[derive(Debug)]
pub struct PacketWriter {
    inner: OwnedPacket,
}

impl PacketWriter {
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

    pub fn write_name(&mut self, name: &str) -> WriteResult {
        let labels = name.split(".");
        let mut n = 0;
        for label in labels {
            let size = label.len() as u8;
            n += self.write_u8(size)?;
            let text = label.as_bytes();
            n += self.inner.write(text)?;
        }
        n += self.write_u8(0)?;
        Ok(n)
    }
}

#[cfg(test)]
mod test {
    use crate::{name::Name, reader::PacketReader, writer::PacketWriter};

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
    #[test]
    fn write_name() {
        let mut writer = PacketWriter::new();
        let n = writer.write_name("google.com").unwrap();
        assert_eq!(n, 12);
        assert_eq!(
            writer.inner,
            [
                6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
            ]
        )
    }
    #[test]
    fn write_name_round_trip() {
        let mut writer = PacketWriter::new();
        let write = "google.com";
        let _ = writer.write_name(write).unwrap();
        let mut reader = PacketReader::new(&writer.inner);
        let read = Name::read(&mut reader).unwrap();
        assert_eq!(read, Name::from("google.com"));
    }
}
