use std::io::Result;

use super::name::Name;
use crate::reader::PacketReader;

#[derive(Debug)]
pub struct Question {
    name: Name,
    record_type: u16,
    class: u16,
}

impl Question {
    pub fn read(reader: &mut PacketReader) -> Result<Question> {
        let name = Name::read(reader)?;
        let record_type = reader.read_u16()?;
        let class = reader.read_u16()?;

        Ok(Question {
            name,
            record_type,
            class,
        })
    }
}
