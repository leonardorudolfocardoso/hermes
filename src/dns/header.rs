use crate::{Decode, reader::PacketReader};
use std::io::Result;

#[derive(Debug)]
pub struct Header {
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl Header {
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
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            question_count: u16::from_be_bytes([buf[4], buf[5]]),
            answer_count: u16::from_be_bytes([buf[6], buf[7]]),
            authority_count: u16::from_be_bytes([buf[8], buf[9]]),
            additional_count: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }
}
