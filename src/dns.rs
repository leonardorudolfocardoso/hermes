use std::{
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::{
    Decode, Encode, OwnedPacket, Packet,
    dns::{
        flags::{Flags, ResponseCode},
        header::{Header, WireHeader},
        name::Name,
        question::Question,
        record::{Data, Record, RecordError, WireRecord},
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
pub struct ReferralServer<'a> {
    name: &'a Name,
    addrs: Vec<SocketAddr>,
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

    pub fn referral_servers(&self) -> impl Iterator<Item = ReferralServer> {
        self.authorities.iter().filter_map(|authority| {
            let name = match authority.as_ns() {
                Some(name) => name,
                None => return None,
            };

            let addrs: Vec<_> = self
                .additionals
                .iter()
                .filter_map(move |additional| {
                    if additional.name() != name {
                        return None;
                    }

                    match additional.data() {
                        Data::A(ip) => Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(*ip)), 53)),
                        Data::Aaaa(ip) => {
                            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(*ip)), 53))
                        }
                        _ => None,
                    }
                })
                .collect();

            if addrs.is_empty() {
                None
            } else {
                Some(ReferralServer { name, addrs })
            }
        })
    }
}

impl<'a> TryFrom<Packet<'a>> for Message {
    type Error = DnsError;

    fn try_from(value: Packet) -> Result<Self, Self::Error> {
        let mut reader = PacketReader::new(value);
        let header = WireHeader::decode(&mut reader)?;
        let questions = Question::decode_n(&mut reader, header.question_count().into())?;
        let answers = WireRecord::decode_n(&mut reader, header.answer_count().into())?
            .into_iter()
            .map(Record::try_from)
            .collect::<Result<Vec<_>, RecordError>>()?;
        let authorities = WireRecord::decode_n(&mut reader, header.authority_count().into())?
            .into_iter()
            .map(Record::try_from)
            .collect::<Result<Vec<_>, RecordError>>()?;
        let additionals = WireRecord::decode_n(&mut reader, header.additional_count().into())?
            .into_iter()
            .map(Record::try_from)
            .collect::<Result<Vec<_>, RecordError>>()?;

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
            ReferralServer,
            flags::{Flags, ResponseCode},
            header::Header,
            name::Name,
            question::Question,
            record::{Data, Record},
        },
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    use super::{Message, Packet};
    use pretty_assertions::assert_eq;

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
                name: Name::from_labels(&["google", "com"]),
                record_type: 1,
                class: 1,
            }],
            answers: vec![Record::new(
                Name::from_labels(&["google", "com"]),
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
    fn into_response_sets_only_the_response_bit() {
        let message = Message {
            header: Header::new(0x1234, Flags::from(0b0000_0001_0000_0000)),
            questions: vec![Question {
                name: Name::from_labels(&["google", "com"]),
                record_type: 1,
                class: 1,
            }],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let response = message.clone().into_response();

        assert_eq!(
            response.flags().query_or_response(),
            Flags::from(0b1000_0001_0000_0000).query_or_response()
        );
        assert_eq!(response.questions(), message.questions());
        assert_eq!(response.answers(), message.answers());
        assert_eq!(response.authorities(), message.authorities());
        assert_eq!(response.additionals(), message.additionals());
    }

    #[test]
    fn with_recursion_available_sets_only_the_ra_bit() {
        let message = Message {
            header: Header::new(0x1234, Flags::from(0b0000_0001_0000_0000)),
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let updated = message.with_recursion_available();

        assert_eq!(updated.flags(), Flags::from(0b0000_0001_1000_0000));
    }

    #[test]
    fn with_response_code_updates_the_low_four_bits() {
        let message = Message {
            header: Header::new(0x1234, Flags::from(0b1000_0001_1000_0000)),
            questions: vec![],
            answers: vec![],
            authorities: vec![],
            additionals: vec![],
        };

        let updated = message.with_response_code(ResponseCode::Refused);

        assert_eq!(updated.flags(), Flags::from(0b1000_0001_1000_0101));
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
                name: Name::from_labels(&["example", "com"]),
                record_type: 1,
                class: 1,
            }],
            answers: vec![Record::new(
                Name::from_labels(&["example", "com"]),
                1,
                300,
                Data::A([93, 184, 216, 34]),
            )],
            authorities: vec![Record::new(
                Name::from_labels(&["example", "com"]),
                1,
                300,
                Data::Ns(Name::from_labels(&["ns1", "example", "com"])),
            )],
            additionals: vec![Record::new(
                Name::from_labels(&["ns1", "example", "com"]),
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
                name: Name::from_labels(&["google", "com"]),
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

    #[test]
    fn referral_servers_extracts_matching_glue_records() {
        let name = Name::from_labels(&["ns1", "example", "com"]);
        let message = Message {
            header: Header::new(0x1234, Flags::from(0x8180)),
            questions: vec![],
            answers: vec![],
            authorities: vec![Record::new(
                Name::from_labels(&["example", "com"]),
                1,
                300,
                Data::Ns(Name::from_labels(&["ns1", "example", "com"])),
            )],
            additionals: vec![
                Record::new(name.clone(), 1, 300, Data::A([192, 0, 2, 1])),
                Record::new(
                    name.clone(),
                    1,
                    300,
                    Data::Aaaa([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                ),
            ],
        };

        let referral_servers: Vec<_> = message.referral_servers().collect();

        assert_eq!(
            referral_servers,
            vec![ReferralServer {
                name: &name,
                addrs: vec![
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 53),
                    SocketAddr::new(
                        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
                        53
                    )
                ],
            }]
        );
    }

    #[test]
    fn referral_servers_ignores_non_glue_records() {
        let message = Message {
            header: Header::new(0x1234, Flags::from(0x8180)),
            questions: vec![],
            answers: vec![],
            authorities: vec![Record::new(
                Name::from_labels(&["example", "com"]),
                1,
                300,
                Data::Ns(Name::from_labels(&["ns1", "example", "com"])),
            )],
            additionals: vec![Record::new(
                Name::from_labels(&["ns2", "example", "com"]),
                1,
                300,
                Data::A([192, 0, 2, 2]),
            )],
        };

        let referral_servers: Vec<_> = message.referral_servers().collect();

        dbg!(&referral_servers);

        assert!(referral_servers.is_empty());
    }
}
