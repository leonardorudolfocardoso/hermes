use crate::{
    Decode,
    dns::flags::{Flags, ResponseCode},
    reader::PacketReader,
};
use std::io::Result;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct WireHeader {
    id: u16,
    flags: Flags,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl WireHeader {
    pub fn question_count(&self) -> u16 {
        self.question_count
    }
    pub fn answer_count(&self) -> u16 {
        self.answer_count
    }
    pub fn authority_count(&self) -> u16 {
        self.authority_count
    }
    pub fn additional_count(&self) -> u16 {
        self.additional_count
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Header {
    id: u16,
    flags: Flags,
}
impl Header {
    pub fn new(id: u16, flags: Flags) -> Self {
        Self { id, flags }
    }
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn flags(&self) -> Flags {
        self.flags
    }
    pub fn with_recursion_available(self) -> Self {
        Self {
            flags: self.flags.with_recursion_available(),
            ..self
        }
    }

    pub fn into_response(self) -> Header {
        Self {
            flags: self.flags.into_response(),
            ..self
        }
    }

    pub fn with_response_code(self, code: ResponseCode) -> Header {
        Self {
            flags: self.flags.with_response_code(code),
            ..self
        }
    }
}

impl From<WireHeader> for Header {
    fn from(value: WireHeader) -> Self {
        Header {
            id: value.id,
            flags: value.flags,
        }
    }
}

impl Decode for WireHeader {
    fn decode(reader: &mut PacketReader) -> Result<WireHeader> {
        let mut buf = [0_u8; 12];
        reader.read_exact(&mut buf)?;
        Ok(WireHeader {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: Flags::from(u16::from_be_bytes([buf[2], buf[3]])),
            question_count: u16::from_be_bytes([buf[4], buf[5]]),
            answer_count: u16::from_be_bytes([buf[6], buf[7]]),
            authority_count: u16::from_be_bytes([buf[8], buf[9]]),
            additional_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}

#[cfg(test)]
mod test {
    use super::WireHeader;
    use crate::{Decode, reader::PacketReader};
    use std::io::ErrorKind;

    #[test]
    fn decode_truncated_header_returns_eof() {
        let packet = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00,
        ];

        let mut reader = PacketReader::new(&packet);

        let err = WireHeader::decode(&mut reader).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decode_header_reads_all_counts() {
        let packet = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
        ];

        let mut reader = PacketReader::new(&packet);

        let header = WireHeader::decode(&mut reader).unwrap();

        assert_eq!(header.question_count(), 1);
        assert_eq!(header.answer_count(), 2);
        assert_eq!(header.authority_count(), 3);
        assert_eq!(header.additional_count(), 4);
        assert_eq!(
            header,
            WireHeader::decode(&mut PacketReader::new(&packet)).unwrap()
        );
    }
}
