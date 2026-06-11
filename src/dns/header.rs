use crate::{
    Decode, Encode,
    dns::flags::Flags,
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};
use std::io::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct Header {
    id: u16,
    flags: Flags,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl Header {
    pub fn new(
        id: u16,
        flags: Flags,
        question_count: u16,
        answer_count: u16,
        authority_count: u16,
        additional_count: u16,
    ) -> Self {
        Self {
            id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        }
    }
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn flags(&self) -> Flags {
        self.flags
    }
    pub fn question_count(&self) -> u16 {
        self.question_count
    }

    pub fn answer_count(&self) -> u16 {
        self.answer_count
    }
}

impl Decode for Header {
    fn decode(reader: &mut PacketReader) -> Result<Header> {
        let mut buf = [0_u8; 12];
        reader.read_exact(&mut buf)?;
        Ok(Header {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: Flags::from(u16::from_be_bytes([buf[2], buf[3]])),
            question_count: u16::from_be_bytes([buf[4], buf[5]]),
            answer_count: u16::from_be_bytes([buf[6], buf[7]]),
            authority_count: u16::from_be_bytes([buf[8], buf[9]]),
            additional_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

impl Encode for Header {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        let mut n = 0;
        n += writer.write_u16(self.id)?;
        n += self.flags.encode(writer)?;
        n += writer.write_u16(self.question_count)?;
        n += writer.write_u16(self.answer_count)?;
        n += writer.write_u16(self.authority_count)?;
        n += writer.write_u16(self.additional_count)?;
        Ok(n)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Decode, Encode,
        dns::{flags::Flags, header::Header},
        reader::PacketReader,
        writer::PacketWriter,
    };

    #[test]
    fn header_encode_has_12_bytes() {
        let header = Header {
            id: 0x1234,
            flags: Flags::from(0x8180),
            question_count: 1,
            answer_count: 2,
            authority_count: 3,
            additional_count: 4,
        };

        let mut writer = PacketWriter::new();

        header.encode(&mut writer).unwrap();

        assert_eq!(writer.get().len(), 12);
    }
    #[test]
    fn header_encode_writes_correct_bytes() {
        let header = Header {
            id: 0x1234,
            flags: Flags::from(0x8180),
            question_count: 1,
            answer_count: 2,
            authority_count: 3,
            additional_count: 4,
        };

        let mut writer = PacketWriter::new();

        header.encode(&mut writer).unwrap();

        assert_eq!(
            writer.get(),
            &[
                0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
            ]
        );
    }
    #[test]
    fn header_round_trip() {
        let original = Header {
            id: 0xABCD,
            flags: Flags::from(0x8180),
            question_count: 1,
            answer_count: 5,
            authority_count: 2,
            additional_count: 9,
        };

        let mut writer = PacketWriter::new();

        original.encode(&mut writer).unwrap();

        let mut reader = PacketReader::new(writer.get());

        let decoded = Header::decode(&mut reader).unwrap();

        assert_eq!(decoded, original);
    }
}
