use std::io::{Cursor, Read};

use crate::Packet;

pub struct PacketReader<'a> {
    inner: Cursor<Packet<'a>>,
}

impl<'a> PacketReader<'a> {
    pub fn new(packet: Packet<'a>) -> Self {
        PacketReader {
            inner: Cursor::new(packet),
        }
    }

    pub fn position(&self) -> u64 {
        self.inner.position()
    }

    pub fn set_position(&mut self, pos: u64) {
        self.inner.set_position(pos)
    }

    pub fn read_u8(&mut self) -> std::io::Result<u8> {
        let mut buf = [0_u8; 1];
        self.inner.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    pub fn read_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0_u8; 2];
        self.inner.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }

    pub fn read_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0_u8; 4];
        self.inner.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        self.inner.read_exact(buf)
    }

    pub fn read_array<const N: usize>(&mut self) -> std::io::Result<[u8; N]> {
        let mut buf = [0; N];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }

    pub fn read_vec(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0; n];
        self.inner.read_exact(&mut buf)?;
        Ok(buf)
    }
}
