use crate::reader::PacketReader;
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
    pub fn read(reader: &mut PacketReader) -> Result<Header> {
        let mut buf = [0_u8; 12];
        reader.read_exact(&mut buf)?;
        Ok(Header::from_bytes(buf))
    }
    fn from_bytes(bytes: [u8; 12]) -> Header {
        Header {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            question_count: u16::from_be_bytes([bytes[4], bytes[5]]),
            answer_count: u16::from_be_bytes([bytes[6], bytes[7]]),
            authority_count: u16::from_be_bytes([bytes[8], bytes[9]]),
            additional_count: u16::from_be_bytes([bytes[10], bytes[11]]),
        }
    }

    pub fn answer_count(&self) -> u16 {
        self.answer_count
    }
}
