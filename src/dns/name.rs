use crate::{
    Decode, Encode,
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};
use std::io::Result;
use std::{fmt::Display, ops::AddAssign};

pub type Label = String;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Name(Vec<Label>);

impl Name {
    pub fn new() -> Self {
        Name(vec![])
    }

    #[cfg(test)]
    pub(crate) fn from_labels(labels: &[&str]) -> Self {
        Self(labels.iter().map(|label| (*label).to_string()).collect())
    }

    pub fn wire_length(&self) -> usize {
        self.0.iter().fold(0, |acc, e| acc + 1 + e.len()) + 1
    }
    pub fn push(&mut self, label: Label) {
        self.0.push(label)
    }
}

impl IntoIterator for Name {
    type Item = Label;

    type IntoIter = std::vec::IntoIter<Label>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl AddAssign for Name {
    fn add_assign(&mut self, rhs: Self) {
        self.0.extend(rhs);
    }
}

impl Decode for Name {
    fn decode(reader: &mut PacketReader) -> Result<Name> {
        let mut name = Name::new();

        loop {
            let first_byte = reader.read_u8()? as usize;

            if first_byte & 0xC0 == 0xC0 {
                // name compressed at pointer
                let second_byte = reader.read_u8()? as usize;
                let after_pointer_position = reader.position();
                // jump to pointer
                let offset = ((first_byte & 0x3F) << 8) | second_byte;
                reader.set_position(offset as u64);
                // add the name to the main
                name += Self::decode(reader)?;
                // jump back to after pointer position
                reader.set_position(after_pointer_position);

                return Ok(name);
            } else if first_byte == 0 {
                break;
            } else {
                let size = first_byte;
                let mut buf = vec![0; size];
                reader.read_exact(&mut buf)?;
                let label = Label::from_utf8(buf).unwrap();
                name.push(label);
            }
        }

        Ok(name)
    }
}

impl Encode for Name {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        if self.0.is_empty() {
            return writer.write_u8(0);
        }

        let mut n = 0;
        for label in &self.0 {
            let size = label.len() as u8;
            n += writer.write_u8(size)?;
            let text = label.as_bytes();
            n += writer.write(text)?;
        }
        n += writer.write_u8(0)?;
        Ok(n)
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.join("."))
    }
}

#[cfg(test)]
mod test {
    use crate::{Decode, Encode, reader::PacketReader, writer::PacketWriter};
    use std::io::ErrorKind;

    use super::Name;

    #[test]
    fn decodes_uncompressed_name() {
        let packet = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let mut reader = PacketReader::new(&packet);

        let name = Name::decode(&mut reader).unwrap();

        assert_eq!(name, Name::from_labels(&["google", "com"]));
    }
    #[test]
    fn decodes_compressed_name() {
        let packet = [
            // fake 12 byte header
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // position 12
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // position 24
            0xC0, 0x0C,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = Name::decode(&mut reader).unwrap();

        assert_eq!(name, Name::from_labels(&["google", "com"]));
    }
    #[test]
    fn decodes_a_compressed_name_restores_cursor_position() {
        let packet = [
            // 0-11
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 12
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // 24
            0xC0, 0x0C, // something after name
            0x12, 0x34,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = Name::decode(&mut reader).unwrap();

        assert_eq!(name, Name::from_labels(&["google", "com"]));

        let next = reader.read_u16().unwrap();

        assert_eq!(next, 0x1234);
    }
    #[test]
    fn decodes_partially_compressed_name() {
        let packet = [
            // fake header
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // position 12: google.com
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // position 24:
            3, b'w', b'w', b'w', 0xC0, 0x0C,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = Name::decode(&mut reader).unwrap();

        assert_eq!(name, Name::from_labels(&["www", "google", "com"]));
    }
    #[test]
    fn encode() {
        let mut writer = PacketWriter::new();
        let name = Name::from_labels(&["google", "com"]);
        let n = name.encode(&mut writer).unwrap();
        assert_eq!(n, 12);
        assert_eq!(
            writer.get(),
            &[
                6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
            ]
        )
    }
    #[test]
    fn encode_round_trip() {
        let mut writer = PacketWriter::new();
        let name = Name::from_labels(&["google", "com"]);
        let _ = name.encode(&mut writer).unwrap();
        let mut reader = PacketReader::new(writer.get());
        let read = Name::decode(&mut reader).unwrap();
        assert_eq!(read, Name::from_labels(&["google", "com"]));
    }

    #[test]
    fn decode_root_label() {
        let packet = [0];

        let mut reader = PacketReader::new(&packet);

        let name = Name::decode(&mut reader).unwrap();

        assert_eq!(name, Name::new());
    }

    #[test]
    fn encode_root_label() {
        let mut writer = PacketWriter::new();
        let name = Name::new();

        let n = name.encode(&mut writer).unwrap();

        assert_eq!(n, 1);
        assert_eq!(writer.get(), &[0]);
    }

    #[test]
    fn decode_truncated_label_returns_eof() {
        let packet = [3, b'w', b'w'];

        let mut reader = PacketReader::new(&packet);

        let err = Name::decode(&mut reader).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn decode_pointer_past_packet_returns_eof() {
        let packet = [0xC0, 0x04];

        let mut reader = PacketReader::new(&packet);

        let err = Name::decode(&mut reader).unwrap_err();

        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }
}
