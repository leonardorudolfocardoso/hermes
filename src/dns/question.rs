use std::io::Result;

use super::name::Name;
use crate::{Decode, reader::PacketReader};

#[derive(Debug)]
pub struct Question {
    name: Name,
    record_type: u16,
    class: u16,
}

impl Decode for Question {
    fn decode(reader: &mut PacketReader) -> Result<Question> {
        let name = Name::decode(reader)?;
        let record_type = reader.read_u16()?;
        let class = reader.read_u16()?;

        Ok(Question {
            name,
            record_type,
            class,
        })
    }
}
