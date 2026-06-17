use std::io::Result;

use super::name::Name;
use crate::{
    Decode, Encode,
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Question {
    pub name: Name,
    pub record_type: u16,
    pub class: u16,
}

impl Decode for Question {
    fn decode(reader: &mut PacketReader) -> Result<Question> {
        let name = Name::decode(reader)?;
        let record_type = reader.read_u16()?;
        let class = reader.read_u16()?;

        Ok(Question {
            name,
            record_type,
            class,
        })
    }
}

impl Encode for Question {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        let mut n = 0;
        n += self.name.encode(writer)?;
        n += writer.write_u16(self.record_type)?;
        n += writer.write_u16(self.class)?;
        Ok(n)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        Decode, Encode,
        dns::{name::Name, question::Question},
        reader::PacketReader,
        writer::PacketWriter,
    };
    use std::io::ErrorKind;

    #[test]
    fn question_encode_writes_correct_bytes() {
        let question = Question {
            name: Name::from_labels(&["google", "com"]),
            record_type: 1,
            class: 1,
        };

        let mut writer = PacketWriter::new();

        question.encode(&mut writer).unwrap();

        assert_eq!(
            writer.get(),
            &[
                6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00,
                0x01,
            ]
        );
    }
    #[test]
    fn question_round_trip() {
        let original = Question {
            name: Name::from_labels(&["google", "com"]),
            record_type: 1,
            class: 1,
        };

        let mut writer = PacketWriter::new();

        original.encode(&mut writer).unwrap();

        let mut reader = PacketReader::new(writer.get());

        let decoded = Question::decode(&mut reader).unwrap();

        assert_eq!(decoded, original);
    }

    #[test]
    fn question_decode_returns_eof_when_truncated_after_name() {
        let packet = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00,
        ];

        let mut reader = PacketReader::new(&packet);

        let err = Question::decode(&mut reader).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }
}
