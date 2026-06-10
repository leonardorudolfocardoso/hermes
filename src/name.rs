use crate::reader::PacketReader;
use std::io::Result;

#[derive(Debug, PartialEq, Eq)]
pub struct Name(String);

impl Name {
    pub fn read(reader: &mut PacketReader) -> Result<Name> {
        let mut labels = vec![];

        loop {
            let first_byte = reader.read_u8()? as usize;

            if first_byte & 0xC0 == 0xC0 {
                // name compressed at pointer
                let second_byte = reader.read_u8()? as usize;
                let after_pointer_position = reader.position();
                // jump to pointer
                let offset = ((first_byte & 0x3F) << 8) | second_byte;
                reader.set_position(offset as u64);
                // read the name
                let name = Self::read(reader)?;
                // jump back to after pointer position
                reader.set_position(after_pointer_position);

                labels.push(name.0);

                let name: Name = labels.join(".").as_str().into();
                return Ok(name);
            } else if first_byte == 0 {
                break;
            } else {
                let size = first_byte;
                let mut buf = vec![0; size];
                reader.read_exact(&mut buf)?;
                let label = String::from_utf8(buf).unwrap();
                labels.push(label);
            }
        }

        let name = labels.join(".").as_str().into();
        Ok(name)
    }
}

impl From<&str> for Name {
    fn from(value: &str) -> Self {
        Name(value.to_owned())
    }
}

#[cfg(test)]
mod test {
    use crate::{name::Name, reader::PacketReader};

    #[test]
    fn reads_uncompressed_name() {
        let packet = [
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0,
        ];

        let mut reader = PacketReader::new(&packet);

        let name = Name::read(&mut reader).unwrap();

        assert_eq!(name, Name::from("google.com"));
    }
    #[test]
    fn reads_compressed_name() {
        let packet = [
            // fake 12 byte header
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // position 12
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // position 24
            0xC0, 0x0C,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = Name::read(&mut reader).unwrap();

        assert_eq!(name, Name::from("google.com"));
    }
    #[test]
    fn compressed_name_restores_cursor_position() {
        let packet = [
            // 0-11
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 12
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // 24
            0xC0, 0x0C, // something after name
            0x12, 0x34,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = Name::read(&mut reader).unwrap();

        assert_eq!(name, Name::from("google.com"));

        let next = reader.read_u16().unwrap();

        assert_eq!(next, 0x1234);
    }
    #[test]
    fn reads_partially_compressed_name() {
        let packet = [
            // fake header
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // position 12: google.com
            6, b'g', b'o', b'o', b'g', b'l', b'e', 3, b'c', b'o', b'm', 0, // position 24:
            3, b'w', b'w', b'w', 0xC0, 0x0C,
        ];

        let mut reader = PacketReader::new(&packet);

        reader.set_position(24);

        let name = Name::read(&mut reader).unwrap();

        assert_eq!(name, Name::from("www.google.com"));
    }
}
