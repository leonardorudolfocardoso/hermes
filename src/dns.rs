use std::fmt::Display;

use crate::{
    Packet,
    dns::{answer::Answer, header::Header, question::Question},
    reader::PacketReader,
};

pub mod answer;
pub mod header;
pub mod name;
pub mod question;

#[derive(Debug)]
pub enum DnsError {
    IO(std::io::Error),
}
impl From<std::io::Error> for DnsError {
    fn from(value: std::io::Error) -> Self {
        DnsError::IO(value)
    }
}

impl Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IO(io) => write!(f, "IO error: {io}"),
        }
    }
}

#[derive(Debug)]
pub struct Dns {
    header: Header,
    questions: Vec<Question>,
    answers: Vec<Answer>,
    // authorities: Vec<Record>,
    // additional: Vec<Record>,
}

impl<'a> TryFrom<Packet<'a>> for Dns {
    type Error = DnsError;

    fn try_from(value: Packet) -> Result<Self, Self::Error> {
        let mut reader = PacketReader::new(value);
        let header = Header::read(&mut reader)?;
        let mut questions = Vec::new();
        for _ in 0..header.question_count() {
            let question = Question::read(&mut reader)?;
            questions.push(question);
        }
        let mut answers = vec![];
        for _ in 0..header.answer_count() {
            let answer = Answer::read(&mut reader)?;
            answers.push(answer);
        }

        Ok(Dns {
            header,
            questions,
            answers,
        })
    }
}
#[cfg(test)]
mod test {
    use super::{Dns, Packet};

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
