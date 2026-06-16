use std::{env::args, error::Error, net::UdpSocket};

use hermes::resolve;

fn main() -> Result<(), Box<dyn Error>> {
    let addr = args().nth(1).expect("missing addr.\nusage: hermes <addr>");
    let socket = UdpSocket::bind(addr)?;
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
