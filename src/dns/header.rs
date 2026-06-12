use crate::{Decode, dns::flags::Flags, reader::PacketReader};
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
    #[cfg(test)]
    pub fn new(id: u16, flags: Flags) -> Self {
        Self { id, flags }
    }
    pub fn with_flags(self, flags: Flags) -> Self {
        Self { flags, ..self }
    }
    pub fn id(&self) -> u16 {
        self.id
    }
    pub fn flags(&self) -> Flags {
        self.flags
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
