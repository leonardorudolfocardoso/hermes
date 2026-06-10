use std::io::{Cursor, Read};

use crate::{Packet, Question, Record, RecordData};

pub struct PacketReader<'a> {
    inner: Cursor<Packet<'a>>,
}

impl<'a> PacketReader<'a> {
    pub fn new(packet: Packet<'a>) -> Self {
        PacketReader {
            inner: Cursor::new(packet),
        }
    }

    fn position(&self) -> u64 {
        self.inner.position()
    }

    fn set_position(&mut self, pos: u64) {
        self.inner.set_position(pos)
    }

    fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0_u8; 1];
        self.inner.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0_u8; 2];
        self.inner.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0_u8; 4];
        self.inner.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact(buf)
    }

    pub fn read_name(&mut self) -> std::io::Result<String> {
        let mut labels = vec![];

        loop {
            let first_byte = self.read_u8()? as usize;

            if first_byte & 0xC0 == 0xC0 {
                // name compressed at pointer
                let second_byte = self.read_u8()? as usize;
                let after_pointer_position = self.position();
                // jump to pointer
                let offset = ((first_byte & 0x3F) << 8) | second_byte;
                self.set_position(offset as u64);
                // read the name
                let name = self.read_name()?;
                // jump back to after pointer position
                self.set_position(after_pointer_position);
                labels.push(name);
                return Ok(labels.join("."));
            } else if first_byte == 0 {
                break;
            } else {
                let size = first_byte;
                let mut buf = vec![0; size];
                self.inner.read_exact(&mut buf)?;
                let label = String::from_utf8(buf).unwrap();
                labels.push(label);
            }
        }

        Ok(labels.join("."))
    }

    pub fn read_question(&mut self) -> std::io::Result<Question> {
        let name = self.read_name()?;
        let record_type = self.read_u16()?;
        let class = self.read_u16()?;

        Ok(Question {
            name,
            record_type,
            class,
        })
    }

    pub fn read_answer(&mut self) -> std::io::Result<Record> {
        let name = self.read_name()?;
        let record_type = self.read_u16()?;
        let class = self.read_u16()?;
        let ttl = self.read_u32()?;
        let data_length = self.read_u16()?;

        let data = match record_type {
            1 => RecordData::A(self.read_array()?),
            28 => RecordData::AAAA(self.read_array()?),
            _ => RecordData::Unknown(self.read_vec(data_length as usize)?),
        };

        Ok(Record {
            name,
            record_type,
            class,
            ttl,
            data_length,
            data,
        })
    }

    fn read_array<const N: usize>(&mut self) -> std::io::Result<[u8; N]> {
        let mut buf = [0; N];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    fn read_vec(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0; n];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }
}
#[cfg(test)]
mod test {
    use super::PacketReader;

    #[test]
    fn reads_uncompressed_name() {
        let packet = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let mut reader = PacketReader::new(&packet);

        let name = reader.read_name().unwrap();

        assert_eq!(name, "google.com");
    }
    #[test]
    fn reads_compressed_name() {
        let packet = [
            // fake 12 byte header
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // position 12
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // position 24
            0xC0, 0x0C,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = reader.read_name().unwrap();

        assert_eq!(name, "google.com");
    }
    #[test]
    fn compressed_name_restores_cursor_position() {
        let packet = [
            // 0-11
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 12
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // 24
            0xC0, 0x0C, // something after name
            0x12, 0x34,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = reader.read_name().unwrap();

        assert_eq!(name, "google.com");

        let next = reader.read_u16().unwrap();

        assert_eq!(next, 0x1234);
    }
    #[test]
    fn reads_partially_compressed_name() {
        let packet = [
            // fake header
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // position 12: google.com
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // position 24:
            3, b'w', b'w', b'w', 0xC0, 0x0C,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = reader.read_name().unwrap();

        assert_eq!(name, "www.google.com");
    }
}
