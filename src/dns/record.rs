use std::{fmt::Display, io::Result as IoResult};

use crate::{
    Decode, Encode,
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};

use super::name::Name;

/// A data enum used by [[`Record`]]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Data {
    /// A host IpV4 address.
    A([u8; 4]),
    /// A host IpV6 address.
    Aaaa([u8; 16]),
    /// An authoritative name server.
    Ns(Name),
    /// An unknown data
    Unknown { _type: u16, value: Vec<u8> },
}

impl Encode for Data {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        match self {
            Self::A(buf) => writer.write(buf),
            Data::Aaaa(buf) => writer.write(buf),
            Data::Ns(name) => name.encode(writer),
            Data::Unknown {
                _type: _,
                value: buf,
            } => writer.write(buf),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct WireRecord {
    name: Name,
    record_type: u16,
    class: u16,
    ttl: u32,
    data_length: u16,
    data: Data,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RecordError {
    InconsistentDataLength,
    InconsistentRecordType,
}
impl Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordError::InconsistentDataLength => {
                write!(f, "InconsistentDataLength: data length is inconsistent")
            }
            RecordError::InconsistentRecordType => {
                write!(f, "InconsistentRecordType: record type is inconsistent")
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Record {
    name: Name,
    class: u16,
    ttl: u32,
    data: Data,
}
impl Record {
    #[cfg(test)]
    pub fn new(name: Name, class: u16, ttl: u32, data: Data) -> Self {
        Self {
            name,
            class,
            ttl,
            data,
        }
    }
}
impl TryFrom<WireRecord> for Record {
    type Error = RecordError;
    fn try_from(value: WireRecord) -> Result<Self, Self::Error> {
        let (data_length, data_type) = match &value.data {
            Data::A(bytes) => (bytes.len(), 1),
            Data::Aaaa(bytes) => (bytes.len(), 28),
            Data::Ns(name) => (name.wire_length(), 2),
            Data::Unknown { _type, value } => (value.len(), *_type),
        };

        if data_length as u16 != value.data_length {
            Err(RecordError::InconsistentDataLength)
        } else if data_type != value.record_type {
            Err(RecordError::InconsistentRecordType)
        } else {
            Ok(Self {
                name: value.name,
                class: value.class,
                ttl: value.ttl,
                data: value.data,
            })
        }
    }
}

impl Decode for WireRecord {
    fn decode(reader: &mut PacketReader) -> IoResult<WireRecord> {
        let name = Name::decode(reader)?;
        let record_type = reader.read_u16()?;
        let class = reader.read_u16()?;
        let ttl = reader.read_u32()?;
        let data_length = reader.read_u16()?;

        let data = match record_type {
            1 => Data::A(reader.read_array()?),
            2 => Data::Ns(Name::decode(reader)?),
            28 => Data::Aaaa(reader.read_array()?),
            _type => Data::Unknown {
                _type,
                value: reader.read_vec(data_length.into())?,
            },
        };

        Ok(WireRecord {
            name,
            record_type,
            class,
            ttl,
            data_length,
            data,
        })
    }
}

impl Encode for Record {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        let mut data_writer = PacketWriter::new();
        self.data.encode(&mut data_writer)?;
        let data = data_writer.into_inner();

        let mut n = 0;
        n += self.name.encode(writer)?;
        n += writer.write_u16(match self.data {
            Data::A(_) => 1,
            Data::Ns(_) => 2,
            Data::Aaaa(_) => 28,
            Data::Unknown { _type, .. } => _type,
        })?;
        n += writer.write_u16(self.class)?;
        n += writer.write_u32(self.ttl)?;
        n += writer.write_u16(data.len().try_into().unwrap())?;
        n += writer.write(&data)?;

        Ok(n)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Decode, Encode,
        dns::{
            name::Name,
            record::{Data, Record, RecordError, WireRecord},
        },
        reader::PacketReader,
        writer::PacketWriter,
    };
    use pretty_assertions::assert_eq;
    use std::io::ErrorKind;

    #[test]
    fn answer_encode_writes_correct_bytes() {
        let answer = Record {
            name: Name::from_labels(&["google", "com"]),
            class: 1,
            ttl: 300,
            data: Data::A([142, 250, 0, 1]),
        };

        let mut writer = PacketWriter::new();

        answer.encode(&mut writer).unwrap();

        assert_eq!(
            writer.get(),
            &[
                // google.com
                6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // TYPE A
                0x00, 0x01, // CLASS IN
                0x00, 0x01, // TTL 300
                0x00, 0x00, 0x01, 0x2c, // RDLENGTH
                0x00, 0x04, // IP 142.250.0.1
                142, 250, 0, 1,
            ]
        );
    }
    #[test]
    fn answer_round_trip() {
        let name = Name::from_labels(&["google", "com"]);
        let class = 1;
        let ttl = 300;
        let data = Data::A([142, 250, 0, 1]);

        let original = Record {
            name: name.clone(),
            class,
            ttl,
            data: data.clone(),
        };

        let mut writer = PacketWriter::new();

        original.encode(&mut writer).unwrap();

        let mut reader = PacketReader::new(writer.get());

        let decoded = WireRecord::decode(&mut reader).unwrap();

        let expected = WireRecord {
            name,
            record_type: 1,
            class,
            ttl,
            data_length: 4,
            data,
        };

        assert_eq!(decoded, expected);
    }

    #[test]
    fn aaaa_record_round_trip() {
        let name = Name::from_labels(&["google", "com"]);
        let class = 1;
        let ttl = 300;
        let data = Data::Aaaa([
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ]);
        let original = Record {
            name: name.clone(),
            class,
            ttl,
            data: data.clone(),
        };

        let mut writer = PacketWriter::new();

        original.encode(&mut writer).unwrap();

        let mut reader = PacketReader::new(writer.get());

        let decoded = WireRecord::decode(&mut reader).unwrap();

        let expected = WireRecord {
            name,
            record_type: 28,
            class,
            ttl,
            data_length: 16,
            data,
        };

        assert_eq!(decoded, expected);
    }

    #[test]
    fn ns_record_round_trip() {
        let name = Name::from_labels(&["google", "com"]);
        let class = 1;
        let ttl = 300;
        let data = Data::Ns(Name::from_labels(&["ns1", "example", "com"]));

        let original = Record {
            name: name.clone(),
            class,
            ttl,
            data: data.clone(),
        };

        let mut writer = PacketWriter::new();

        original.encode(&mut writer).unwrap();

        let mut reader = PacketReader::new(writer.get());

        let decoded = WireRecord::decode(&mut reader).unwrap();

        let expected = WireRecord {
            name,
            record_type: 2,
            class,
            ttl,
            data_length: 17,
            data,
        };

        assert_eq!(decoded, expected);
    }

    #[test]
    fn unknown_record_round_trip_preserves_bytes() {
        let name = Name::from_labels(&["example", "com"]);
        let class = 1;
        let ttl = 60;
        let data = Data::Unknown {
            _type: 99,
            value: vec![1, 2, 3, 4],
        };
        let original = Record {
            name: name.clone(),
            class,
            ttl,
            data: data.clone(),
        };

        let mut writer = PacketWriter::new();

        original.encode(&mut writer).unwrap();

        let mut reader = PacketReader::new(writer.get());

        let decoded = WireRecord::decode(&mut reader).unwrap();

        let expected = WireRecord {
            name,
            record_type: 99, // unknown
            class,
            ttl,
            data_length: 4,
            data,
        };

        assert_eq!(decoded, expected);
    }

    #[test]
    fn wire_record_try_from_rejects_inconsistent_data_length() {
        let wire = WireRecord {
            name: Name::from_labels(&["example", "com"]),
            record_type: 1,
            class: 1,
            ttl: 60,
            data_length: 999,
            data: Data::A([93, 184, 216, 34]),
        };

        let err = Record::try_from(wire).unwrap_err();

        assert_eq!(err, RecordError::InconsistentDataLength);
    }

    #[test]
    fn decode_truncated_record_returns_eof() {
        let packet = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // name
            0x00, 0x01, // type
            0x00, 0x01, // class
            0x00, 0x00, 0x01, 0x2c, // ttl
            0x00, 0x04, // rdlength
            142, 250, 0, // truncated A record
        ];

        let mut reader = PacketReader::new(&packet);

        let err = WireRecord::decode(&mut reader).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }
}
