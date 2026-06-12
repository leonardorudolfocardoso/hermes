use std::fmt::Display;

use crate::{
    Decode, Encode, OwnedPacket, Packet,
    dns::{
        answer::Answer,
        header::{Header, WireHeader},
        question::Question,
    },
    reader::PacketReader,
    writer::PacketWriter,
};

pub mod answer;
pub mod flags;
pub mod header;
pub mod name;
pub mod question;

#[derive(Debug)]
pub enum DnsError {
    IO(std::io::Error),
    TryFromIntError(std::num::TryFromIntError),
}
impl From<std::io::Error> for DnsError {
    fn from(value: std::io::Error) -> Self {
        DnsError::IO(value)
    }
}
impl From<std::num::TryFromIntError> for DnsError {
    fn from(value: std::num::TryFromIntError) -> Self {
        DnsError::TryFromIntError(value)
    }
}

impl Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::IO(io) => write!(f, "DnsError: {io}"),
            DnsError::TryFromIntError(e) => write!(f, "DnsError: {e}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dns {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Answer>,
    authorities: Vec<Answer>,
    additionals: Vec<Answer>,
}

impl<'a> TryFrom<Packet<'a>> for Dns {
    type Error = DnsError;

    fn try_from(value: Packet) -> Result<Self, Self::Error> {
        let mut reader = PacketReader::new(value);
        let header = WireHeader::decode(&mut reader)?;
        let mut questions = Vec::new();
        for _ in 0..header.question_count() {
            let question = Question::decode(&mut reader)?;
            questions.push(question);
        }
        let mut answers = vec![];
        for _ in 0..header.answer_count() {
            let answer = Answer::decode(&mut reader)?;
            answers.push(answer);
        }

        Ok(Dns {
            header: header.into(),
            questions,
            answers,
            authorities: vec![],
            additionals: vec![],
        })
    }
}

impl TryInto<OwnedPacket> for Dns {
    type Error = DnsError;

    fn try_into(self) -> Result<OwnedPacket, Self::Error> {
        let mut writer = PacketWriter::new();
        writer.write_u16(self.header.id())?;
        self.header.flags().encode(&mut writer)?;
        writer.write_u16(self.questions.len().try_into()?)?;
        writer.write_u16(self.answers.len().try_into()?)?;
        writer.write_u16(self.authorities.len().try_into()?)?;
        writer.write_u16(self.additionals.len().try_into()?)?;

        for question in &self.questions {
            question.encode(&mut writer)?;
        }
        for answer in &self.answers {
            answer.encode(&mut writer)?;
        }

        Ok(writer.into_inner())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        OwnedPacket,
        dns::{
            answer::{Answer, Data},
            flags::Flags,
            header::Header,
            name::Name,
            question::Question,
        },
    };

    use super::{Dns, Packet};

    #[test]
    fn dns_encode_empty_packet() {
        let dns = Dns {
            header: Header::new(0x1234, Flags::from(0x8180)),
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let bytes: OwnedPacket = dns.try_into().unwrap();

        assert_eq!(
            bytes,
            vec![
                0x12, 0x34, // id
                0x81, 0x80, // flags
                0x00, 0x00, // questions
                0x00, 0x00, // answers
                0x00, 0x00, // authorities
                0x00, 0x00, // additional
            ]
        );
    }
    #[test]
    fn dns_round_trip() {
        let original = Dns {
            header: Header::new(0x1234, Flags::from(0x8180)),
            questions: vec![Question {
                name: Name::from("google.com"),
                record_type: 1,
                class: 1,
            }],
            answers: vec![Answer {
                name: Name::from("google.com"),
                record_type: 1,
                class: 1,
                ttl: 300,
                data_length: 4,
                data: Data::A([142, 250, 0, 1]),
            }],
            authorities: vec![],
            additionals: vec![],
        };

        let bytes: OwnedPacket = original.clone().try_into().unwrap();

        let decoded = Dns::try_from(bytes.as_slice()).unwrap();

        assert_eq!(decoded, original);
    }
    #[test]
    fn dns_encode_writes_sections_in_order() {
        let dns = Dns {
            header: Header::new(1, Flags::from(0x8180)),
            questions: vec![Question {
                name: Name::from("google.com"),
                record_type: 1,
                class: 1,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let bytes: OwnedPacket = dns.try_into().unwrap();

        assert_eq!(
            bytes,
            vec![
                // header
                0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                // question
                6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
                0x01,
            ]
        );
    }
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
    }
}
