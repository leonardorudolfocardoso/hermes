use std::fmt::Display;

use crate::{
    Decode, Encode, OwnedPacket, Packet,
    dns::{
        flags::{Flags, ResponseCode},
        header::{Header, WireHeader},
        question::Question,
        record::{Record, RecordError, WireAdditional, WireAnswer, WireAuthority, WireRecord},
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
    RecordError(RecordError),
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
impl From<RecordError> for DnsError {
    fn from(value: RecordError) -> Self {
        Self::RecordError(value)
    }
}

impl Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::IO(io) => write!(f, "DnsError: {io}"),
            DnsError::TryFromIntError(e) => write!(f, "DnsError: {e}"),
            DnsError::RecordError(e) => write!(f, "DnsError: {e}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
}

impl Message {
    pub fn flags(&self) -> Flags {
        self.header.flags()
    }

    pub fn questions(&self) -> &[Question] {
        &self.questions
    }

    pub fn answers(&self) -> &[Record] {
        &self.answers
    }

    pub fn authorities(&self) -> &[Record] {
        &self.authorities
    }

    pub fn additionals(&self) -> &[Record] {
        &self.additionals
    }

    pub fn into_response(self) -> Self {
        Self {
            header: self.header.into_response(),
            ..self
        }
    }
    pub fn with_recursion_available(self) -> Self {
        Self {
            header: self.header.with_recursion_available(),
            ..self
        }
    }
    pub fn with_response_code(self, code: ResponseCode) -> Self {
        Self {
            header: self.header.with_response_code(code),
            ..self
        }
    }
}

impl<'a> TryFrom<Packet<'a>> for Message {
    type Error = DnsError;

    fn try_from(value: Packet) -> Result<Self, Self::Error> {
        let mut reader = PacketReader::new(value);
        let header = WireHeader::decode(&mut reader)?;
        let questions = Question::decode_n(&mut reader, header.question_count().into())
            .collect::<std::io::Result<Vec<_>>>()?;
        let answers = WireAnswer::decode_n(&mut reader, header.answer_count().into())
            .map(|ar| ar?.try_into().map_err(Self::Error::from))
            .collect::<Result<Vec<_>, Self::Error>>()?;
        let authorities = WireAuthority::decode_n(&mut reader, header.authority_count().into())
            .map(|ar| ar?.try_into().map_err(Self::Error::from))
            .collect::<Result<Vec<_>, Self::Error>>()?;
        let additionals = WireAdditional::decode_n(&mut reader, header.additional_count().into())
            .map(|ar| ar?.try_into().map_err(Self::Error::from))
            .collect::<Result<Vec<_>, Self::Error>>()?;

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
            record::{Data, Record},
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
            answers: vec![Record::new(
                Name::from("google.com"),
                1,
                300,
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
    fn dns_round_trip_preserves_fields() {
        let packet: Packet = &[
            // header: id, flags, qd=1, an=1, ns=1, ar=1
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01,
            // question: example.com A IN
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01, // answer: example.com A IN 300 93.184.216.34
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
            0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 93, 184, 216, 34,
            // authority: example.com NS IN 300 ns1.example.com
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x02, 0x00,
            0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x11, 3, b'n', b's', b'1', 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            // additional: ns1.example.com A IN 300 192.0.2.1
            3, b'n', b's', b'1', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm',
            0, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 192, 0, 2, 1,
        ];

        let decoded = Message::try_from(packet).unwrap();

        let expected = Message {
            header: Header::new(0x1234, Flags::from(0x8180)),
            questions: vec![Question {
                name: Name::from("example.com"),
                record_type: 1,
                class: 1,
            }],
            answers: vec![Record::new(
                Name::from("example.com"),
                1,
                300,
                Data::A([93, 184, 216, 34]),
            )],
            authorities: vec![Record::new(
                Name::from("example.com"),
                2,
                300,
                Data::Ns(Name::from("ns1.example.com")),
            )],
            additionals: vec![Record::new(
                Name::from("ns1.example.com"),
                1,
                300,
                Data::A([192, 0, 2, 1]),
            )],
        };

        assert_eq!(decoded, expected);

        let encoded: OwnedPacket = decoded.try_into().unwrap();
        assert_eq!(encoded.as_slice(), packet);

        let decoded_again = Message::try_from(encoded.as_slice()).unwrap();

        assert_eq!(decoded_again, expected);
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
