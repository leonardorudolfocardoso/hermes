use std::{
    fmt::Display,
    net::{SocketAddr, UdpSocket},
    time::Duration,
};

use crate::{
    OwnedPacket,
    dns::{DnsError, Message},
};

pub trait DnsClient {
    type Error;
    fn exchange(&self, server: SocketAddr, request: &Message) -> Result<Message, Self::Error>;
}

pub struct UdpDnsClient {
    timeout: Duration,
}

impl UdpDnsClient {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }
}

#[derive(Debug)]
pub enum UdpDnsClientError {
    Io(std::io::Error),
    Dns(DnsError),
}

impl Display for UdpDnsClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpDnsClientError::Io(io) => write!(f, "UdpDnsClientError: {io}"),
            UdpDnsClientError::Dns(dns_error) => write!(f, "UdpDnsClientError: {dns_error}"),
        }
    }
}
impl std::error::Error for UdpDnsClientError {}
impl From<std::io::Error> for UdpDnsClientError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<DnsError> for UdpDnsClientError {
    fn from(value: DnsError) -> Self {
        UdpDnsClientError::Dns(value)
    }
}

impl DnsClient for UdpDnsClient {
    type Error = UdpDnsClientError;

    fn exchange(&self, server: SocketAddr, request: &Message) -> Result<Message, Self::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(self.timeout))?;
        socket.set_write_timeout(Some(self.timeout))?;
        socket.connect(server)?;

        let packet: OwnedPacket = request.clone().try_into()?;
        socket.send(&packet)?;

        let mut buf = vec![0; 4096];
        let size = socket.recv(&mut buf)?;
        buf.truncate(size);
        Ok(Message::try_from(buf.as_slice())?)
    }
}
