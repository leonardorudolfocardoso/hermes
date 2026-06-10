mod dns;
mod reader;
mod writer;

type Packet<'a> = &'a [u8];
type OwnedPacket = Vec<u8>;

use std::net::UdpSocket;

use crate::dns::{Dns, DnsError};

pub fn resolve(packet: Packet) -> Result<OwnedPacket, DnsError> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:53")?;
    socket.send(packet)?;
    let mut buf = vec![0; 4096];
    let size = socket.recv(&mut buf)?;
    let response = &buf[..size];
    println!("{:?}", &buf[..size]);

    let dns_packet: Dns = buf[..size].try_into()?;

    dbg!(&dns_packet);

    Ok(response.to_owned())
}
