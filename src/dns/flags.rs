use crate::{
    Decode, Encode,
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Flags(u16);

impl Decode for Flags {
    fn decode(reader: &mut PacketReader) -> std::io::Result<Self> {
        reader.read_u16().map(Flags)
    }
}
impl Encode for Flags {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        writer.write_u16(self.0)
    }
}

impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Flags(value)
    }
}
