use crate::{
    Decode, Encode,
    reader::PacketReader,
    writer::{PacketWriter, WriteResult},
};

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub struct Flags(u16);

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum QueryOrResponse {
    Query,
    Response,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum Opcode {
    Query,
    IQuery,
    Status,
    Unknown(u8),
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NameError,
    NotImplemented,
    Refused,
    Unknown(u8),
}

impl From<ResponseCode> for u16 {
    fn from(val: ResponseCode) -> Self {
        match val {
            ResponseCode::NoError => 0,
            ResponseCode::FormatError => 1,
            ResponseCode::ServerFailure => 2,
            ResponseCode::NameError => 3,
            ResponseCode::NotImplemented => 4,
            ResponseCode::Refused => 5,
            ResponseCode::Unknown(u) => u.into(),
        }
    }
}

impl Flags {
    const RESPONSE_MASK: u16 = 1 << 15;
    const RECURSION_AVAILABLE_MASK: u16 = 1 << 7;

    pub fn new() -> Self {
        Flags(0)
    }

    pub fn into_response(self) -> Self {
        Self(self.0 | Self::RESPONSE_MASK)
    }

    pub fn with_recursion_available(self) -> Self {
        Self(self.0 | Self::RECURSION_AVAILABLE_MASK)
    }

    pub fn with_response_code(self, code: ResponseCode) -> Flags {
        let cleared = self.0 & !0x000f;
        let mask: u16 = code.into();
        Self(cleared | mask)
    }

    pub fn query_or_response(&self) -> QueryOrResponse {
        if self.0 & (1 << 15) == 0 {
            QueryOrResponse::Query
        } else {
            QueryOrResponse::Response
        }
    }

    pub fn opcode(&self) -> Opcode {
        match ((self.0 >> 11) & 0b1111) as u8 {
            0 => Opcode::Query,
            1 => Opcode::IQuery,
            2 => Opcode::Status,
            u => Opcode::Unknown(u),
        }
    }

    pub fn authoritative_answer(&self) -> bool {
        self.0 & (1 << 10) != 0
    }

    pub fn truncation(&self) -> bool {
        self.0 & (1 << 9) != 0
    }

    pub fn recursion_desired(&self) -> bool {
        self.0 & (1 << 8) != 0
    }

    pub fn recursion_available(&self) -> bool {
        self.0 & (1 << 7) != 0
    }

    pub fn response_code(&self) -> ResponseCode {
        match (self.0 & 0b1111) as u8 {
            0 => ResponseCode::NoError,
            1 => ResponseCode::FormatError,
            2 => ResponseCode::ServerFailure,
            3 => ResponseCode::NameError,
            4 => ResponseCode::NotImplemented,
            5 => ResponseCode::Refused,
            other => ResponseCode::Unknown(other),
        }
    }
}

impl Decode for Flags {
    fn decode(reader: &mut PacketReader) -> std::io::Result<Self> {
        reader.read_u16().map(Flags)
    }
}
impl Encode for Flags {
    fn encode(&self, writer: &mut PacketWriter) -> WriteResult {
        writer.write_u16(self.0)
    }
}

impl From<u16> for Flags {
    fn from(value: u16) -> Self {
        Flags(value)
    }
}

#[cfg(test)]
mod test {
    use super::{Flags, Opcode, QueryOrResponse, ResponseCode};

    #[test]
    fn query_or_response_uses_most_significant_bit() {
        assert_eq!(
            Flags::from(0b0000_0000_0000_0000).query_or_response(),
            QueryOrResponse::Query
        );
        assert_eq!(
            Flags::from(0b1000_0000_0000_0000).query_or_response(),
            QueryOrResponse::Response
        );
    }

    #[test]
    fn opcode_extracts_the_opcode_bits() {
        assert_eq!(Flags::from(0b0000_0000_0000_0000).opcode(), Opcode::Query);
        assert_eq!(Flags::from(0b0000_1000_0000_0000).opcode(), Opcode::IQuery);
        assert_eq!(Flags::from(0b0001_0000_0000_0000).opcode(), Opcode::Status);
        assert_eq!(
            Flags::from(0b0111_1000_0000_0000).opcode(),
            Opcode::Unknown(15)
        );
    }

    #[test]
    fn response_code_maps_the_low_four_bits() {
        assert_eq!(
            Flags::from(0b0000_0000_0000_0000).response_code(),
            ResponseCode::NoError
        );
        assert_eq!(
            Flags::from(0b0000_0000_0000_0001).response_code(),
            ResponseCode::FormatError
        );
        assert_eq!(
            Flags::from(0b0000_0000_0000_0010).response_code(),
            ResponseCode::ServerFailure
        );
        assert_eq!(
            Flags::from(0b0000_0000_0000_0011).response_code(),
            ResponseCode::NameError
        );
        assert_eq!(
            Flags::from(0b0000_0000_0000_0100).response_code(),
            ResponseCode::NotImplemented
        );
        assert_eq!(
            Flags::from(0b0000_0000_0000_0101).response_code(),
            ResponseCode::Refused
        );
        assert_eq!(
            Flags::from(0b0000_0000_0000_1111).response_code(),
            ResponseCode::Unknown(15)
        );
    }

    #[test]
    fn flag_helpers_preserve_unrelated_bits() {
        let flags = Flags::from(0b0000_0001_0010_0011);

        assert_eq!(flags.into_response(), Flags::from(0b1000_0001_0010_0011));
        assert_eq!(
            flags.with_recursion_available(),
            Flags::from(0b0000_0001_1010_0011)
        );
        assert_eq!(
            flags.with_response_code(ResponseCode::Refused),
            Flags::from(0b0000_0001_0010_0101)
        );
    }
}
