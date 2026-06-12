use std::io::Result;

use crate::{
    Decode, Encode,
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};

use super::name::Name;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Data {
    A([u8; 4]),
    Aaaa([u8; 16]),
    Unknown(Vec<u8>),
}

impl Encode for Data {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        match self {
            Self::A(buf) => writer.write(buf),
            Data::Aaaa(buf) => writer.write(buf),
            Data::Unknown(buf) => writer.write(buf),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WireRecord {
    name: Name,
    record_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    data: Data,
}

impl WireRecord {
    #[cfg(test)]
    pub fn new(
        name: Name,
        record_type: u16,
        class: u16,
        ttl: u32,
        data_length: u16,
        data: Data,
    ) -> WireRecord {
        WireRecord {
            name,
            record_type,
            class,
            ttl,
            data_length,
            data,
        }
    }
}

impl Decode for WireRecord {
    fn decode(reader: &mut PacketReader) -> Result<WireRecord> {
        let name = Name::decode(reader)?;
        let record_type = reader.read_u16()?;
        let class = reader.read_u16()?;
        let ttl = reader.read_u32()?;
        let data_length = reader.read_u16()?;

        let data = match record_type {
            1 => Data::A(reader.read_array()?),
            28 => Data::Aaaa(reader.read_array()?),
            _ => Data::Unknown(reader.read_vec(data_length as usize)?),
        };

        Ok(WireRecord {
            name,
            record_type,
            class,
            ttl,
            data_length,
            data,
        })
    }
}

impl Encode for WireRecord {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        let mut n = 0;
        n += self.name.encode(writer)?;
        n += writer.write_u16(self.record_type)?;
        n += writer.write_u16(self.class)?;
        n += writer.write_u32(self.ttl)?;
        n += writer.write_u16(self.data_length)?;
        n += self.data.encode(writer)?;

        Ok(n)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Decode, Encode,
        dns::{
            name::Name,
            record::{Data, WireRecord},
        },
        reader::PacketReader,
        writer::PacketWriter,
    };

    #[test]
    fn answer_encode_writes_correct_bytes() {
        let answer = WireRecord {
            name: Name::from("google.com"),
            record_type: 1,
            class: 1,
            ttl: 300,
            data_length: 4,
            data: Data::A([142, 250, 0, 1]),
        };

        let mut writer = PacketWriter::new();

        answer.encode(&mut writer).unwrap();

        assert_eq!(
            writer.get(),
            &[
                // google.com
                6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // TYPE A
                0x00, 0x01, // CLASS IN
                0x00, 0x01, // TTL 300
                0x00, 0x00, 0x01, 0x2c, // RDLENGTH
                0x00, 0x04, // IP 142.250.0.1
                142, 250, 0, 1,
            ]
        );
    }
    #[test]
    fn answer_round_trip() {
        let original = WireRecord {
            name: Name::from("google.com"),
            record_type: 1,
            class: 1,
            ttl: 300,
            data_length: 4,
            data: Data::A([142, 250, 0, 1]),
        };

        let mut writer = PacketWriter::new();

        original.encode(&mut writer).unwrap();

        let mut reader = PacketReader::new(writer.get());

        let decoded = WireRecord::decode(&mut reader).unwrap();

        assert_eq!(decoded, original);
    }
}
