mod reader;

type Packet<'a> = &'a [u8];
type OwnedPacket = Vec<u8>;

use std::fmt::Display;
use std::net::UdpSocket;

use crate::reader::PacketReader;

#[derive(Debug)]
pub enum DnsError {
    IO(std::io::Error),
}
impl From<std::io::Error> for DnsError {
    fn from(value: std::io::Error) -> Self {
        DnsError::IO(value)
    }
}

impl Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IO(io) => write!(f, "IO error: {io}"),
        }
    }
}

pub type DnsResult<T> = Result<T, DnsError>;

#[derive(Debug)]
struct Header {
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl Header {
    fn from_bytes(bytes: [u8; 12]) -> Header {
        Header {
            id: u16::from_be_bytes([bytes[0], bytes[1]]),
            flags: u16::from_be_bytes([bytes[2], bytes[3]]),
            question_count: u16::from_be_bytes([bytes[4], bytes[5]]),
            answer_count: u16::from_be_bytes([bytes[6], bytes[7]]),
            authority_count: u16::from_be_bytes([bytes[8], bytes[9]]),
            additional_count: u16::from_be_bytes([bytes[10], bytes[11]]),
        }
    }
}

#[derive(Debug)]
struct Question {
    name: String,
    record_type: u16,
    class: u16,
}

#[derive(Debug)]
enum RecordData {
    A([u8; 4]),
    AAAA([u8; 16]),
    Unknown(Vec<u8>),
}

#[derive(Debug)]
struct Record {
    name: String,
    record_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    data: RecordData,
}

#[derive(Debug)]
struct Dns {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    // authorities: Vec<Record>,
    // additional: Vec<Record>,
}

impl<'a> TryFrom<Packet<'a>> for Dns {
    type Error = DnsError;

    fn try_from(value: Packet) -> Result<Self, Self::Error> {
        let mut reader = PacketReader::new(value);
        let header = reader.read_header()?;
        let mut questions = Vec::new();
        for _ in 0..header.question_count {
            questions.push(reader.read_question()?);
        }
        let mut answers = vec![];
        for _ in 0..header.answer_count {
            answers.push(reader.read_answer()?);
        }

        Ok(Dns {
            header,
            questions,
            answers,
        })
    }
}

pub fn resolve(packet: Packet) -> DnsResult<OwnedPacket> {
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

#[cfg(test)]
mod test {
    use super::{Dns, Packet};

    #[test]
    fn dns_from_packet() {
        let packet: Packet = &[
            5, 159, 129, 128, 0, 1, 0, 1, 0, 0, 0, 1, 6, 103, 111, 111, 103, 108, 101, 3, 99, 111,
            109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 0, 41, 0, 4, 172, 217, 29, 238, 0, 0,
            41, 2, 0, 0, 0, 0, 0, 0, 0,
        ];

        let packet: Dns = packet.try_into().unwrap();

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.answers.len(), 1);

        assert_eq!(packet.questions[0].name, "google.com");

        assert_eq!(packet.answers[0].name, "google.com");
    }
}
