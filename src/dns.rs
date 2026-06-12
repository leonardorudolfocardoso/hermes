use std::fmt::Display;

use crate::{
    Decode, Encode, OwnedPacket, Packet,
    dns::{
        flags::{Flags, QueryOrResponse},
        header::{Header, WireHeader},
        question::Question,
        record::{Additional, Answer, Authority, WireRecord},
    },
    reader::PacketReader,
    writer::PacketWriter,
};

pub mod flags;
pub mod header;
pub mod name;
pub mod question;
pub mod record;

#[derive(Debug)]
pub enum DnsError {
    IO(std::io::Error),
    TryFromIntError(std::num::TryFromIntError),
    MessageIsAlreadyAResponse,
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
            DnsError::MessageIsAlreadyAResponse => todo!(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<WireRecord>,
    authorities: Vec<WireRecord>,
    additionals: Vec<WireRecord>,
}

impl Message {
    pub fn new(
        header: Header,
        questions: Vec<Question>,
        answers: Vec<WireRecord>,
        authorities: Vec<WireRecord>,
        additionals: Vec<WireRecord>,
    ) -> Self {
        Self {
            header,
            questions,
            answers,
            authorities,
            additionals,
        }
    }

    pub fn id(&self) -> u16 {
        self.header.id()
    }

    pub fn flags(&self) -> Flags {
        self.header.flags()
    }

    pub fn try_into_response(self) -> Result<Self, DnsError> {
        match self.header.flags().query_or_response() {
            QueryOrResponse::Query => Ok(Self {
                header: self.header.with_flags(self.flags().into_response()),
                ..self
            }),
            QueryOrResponse::Response => Err(DnsError::MessageIsAlreadyAResponse),
        }
    }
}

impl<'a> TryFrom<Packet<'a>> for Message {
    type Error = DnsError;

    fn try_from(value: Packet) -> Result<Self, Self::Error> {
        let mut reader = PacketReader::new(value);
        let header = WireHeader::decode(&mut reader)?;
        let questions = Question::decode_n(&mut reader, header.question_count().into())?;
        let answers = Answer::decode_n(&mut reader, header.answer_count().into())?;
        let authorities = Authority::decode_n(&mut reader, header.authority_count().into())?;
        let additionals = Additional::decode_n(&mut reader, header.additional_count().into())?;

        Ok(Message {
            header: header.into(),
            questions,
            answers,
            authorities,
            additionals,
        })
    }
}

impl TryInto<OwnedPacket> for Message {
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
        for authority in &self.authorities {
            authority.encode(&mut writer)?;
        }
        for additional in &self.additionals {
            additional.encode(&mut writer)?;
        }

        Ok(writer.into_inner())
    }
}

#[cfg(test)]
mod test {
    use crate::{
        OwnedPacket,
        dns::{
            flags::Flags,
            header::Header,
            name::Name,
            question::Question,
            record::{Data, WireRecord},
        },
    };

    use super::{Message, Packet};

    #[test]
    fn dns_encode_empty_packet() {
        let dns = Message {
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
        let original = Message {
            header: Header::new(0x1234, Flags::from(0x8180)),
            questions: vec![Question {
                name: Name::from("google.com"),
                record_type: 1,
                class: 1,
            }],
            answers: vec![WireRecord::new(
                Name::from("google.com"),
                1,
                1,
                300,
                4,
                Data::A([142, 250, 0, 1]),
            )],
            authorities: vec![],
            additionals: vec![],
        };

        let bytes: OwnedPacket = original.clone().try_into().unwrap();

        let decoded = Message::try_from(bytes.as_slice()).unwrap();

        assert_eq!(decoded, original);
    }
    #[test]
    fn dns_encode_writes_sections_in_order() {
        let dns = Message {
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

        let packet: Message = packet.try_into().unwrap();

        assert_eq!(packet.questions.len(), 1);
        assert_eq!(packet.answers.len(), 1);
    }
}
