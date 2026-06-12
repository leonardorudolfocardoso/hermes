mod dns;
mod reader;
mod writer;

type Packet<'a> = &'a [u8];
type OwnedPacket = Vec<u8>;

use std::{fmt::Display, net::UdpSocket};

use crate::{
    dns::{DnsError, Message},
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

#[derive(Debug)]
pub enum ResolveError {
    Io(std::io::Error),
    Dns(DnsError),
}
impl Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Dns(e) => write!(f, "ResolveError: {e}"),
            ResolveError::Io(e) => write!(f, "IoError: {e}"),
        }
    }
}
impl From<DnsError> for ResolveError {
    fn from(value: DnsError) -> Self {
        Self::Dns(value)
    }
}
impl From<std::io::Error> for ResolveError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
pub fn resolve(packet: Packet) -> Result<OwnedPacket, ResolveError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:53")?;
    socket.send(packet)?;
    let mut buf = vec![0; 4096];
    let size = socket.recv(&mut buf)?;
    let response: Message = buf[..size].try_into()?;

    response.try_into().map_err(ResolveError::Dns)
}
