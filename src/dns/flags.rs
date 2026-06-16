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
