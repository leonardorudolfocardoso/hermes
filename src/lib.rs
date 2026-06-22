mod dns;
mod reader;
mod resolver;
mod writer;

pub use resolver::resolve;

type Packet<'a> = &'a [u8];
type OwnedPacket = Vec<u8>;

use crate::{
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};

trait Decode: Sized {
    fn decode(reader: &mut PacketReader) -> std::io::Result<Self>;
    fn decode_n(reader: &mut PacketReader, n: usize) -> std::io::Result<Vec<Self>> {
        (0..n).map(|_| Self::decode(reader)).collect()
    }
}
trait Encode: Sized {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult;
}
