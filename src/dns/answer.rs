use std::io::Result;

use crate::reader::PacketReader;

use super::name::Name;

#[derive(Debug)]
pub enum Data {
    A([u8; 4]),
    AAAA([u8; 16]),
    Unknown(Vec<u8>),
}

#[derive(Debug)]
pub struct Answer {
    name: Name,
    record_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    data: Data,
}

impl Answer {
    pub fn read(reader: &mut PacketReader) -> Result<Answer> {
        let name = Name::read(reader)?;
        let record_type = reader.read_u16()?;
        let class = reader.read_u16()?;
        let ttl = reader.read_u32()?;
        let data_length = reader.read_u16()?;

        let data = match record_type {
            1 => Data::A(reader.read_array()?),
            28 => Data::AAAA(reader.read_array()?),
            _ => Data::Unknown(reader.read_vec(data_length as usize)?),
        };

        Ok(Answer {
            name,
            record_type,
            class,
            ttl,
            data_length,
            data,
        })
    }
}
