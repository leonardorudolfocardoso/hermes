use std::{error::Error, net::UdpSocket};

use hermes::resolve;

fn main() -> Result<(), Box<dyn Error>> {
    let socket = UdpSocket::bind("127.0.0.1:8080")?;
    let mut buf = [0; 512];
    loop {
        let (n, addr) = socket.recv_from(&mut buf)?;
        if n != 0 {
            let filled = &buf[..n];

            if let Err(e) = resolve(filled).map(|packet| socket.send_to(&packet, addr)) {
                eprintln!("{e}");
            }
        }
    }
}
