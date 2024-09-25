use std::io::{self, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub type SessionId = [u8; 10];
pub type SequenceNumber = u64;
pub type MessageCount = u16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub session: SessionId,
    // the sequence number of the first message in the packet
    pub sequence_number: SequenceNumber,
    pub packet_type: PacketType,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    // the count of messages contained in this packet
    Messages(MessageCount),
    Heartbeat,
    EndOfSession,
}
const HEADER_SIZE: usize = 20;
pub fn decode_header(buf: [u8; HEADER_SIZE]) -> Header {
    let mut rdr = io::Cursor::new(&buf[..]);
    let mut session = SessionId::default();
    rdr.read_exact(&mut session).unwrap();
    let sequence_number = rdr.read_u64::<BigEndian>().unwrap();
    let packet_type = rdr.read_u16::<BigEndian>().unwrap();
    let packet_type = match packet_type {
        0 => PacketType::Heartbeat,
        u16::MAX => PacketType::EndOfSession,
        x => PacketType::Messages(x),
    };
    Header {
        session,
        sequence_number,
        packet_type,
    }
}
pub fn encode_header(header: Header) -> io::Result<[u8; HEADER_SIZE]> {
    let mut buf = [0; HEADER_SIZE];
    let mut wtr = io::Cursor::new(&mut buf[..]);
    wtr.write_all(&header.session).unwrap();
    wtr.write_u64::<BigEndian>(header.sequence_number).unwrap();
    let packet_type = match header.packet_type {
        PacketType::Messages(x) => {
            if matches!(x, 0 | u16::MAX) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "message count"));
            }
            x
        }
        PacketType::Heartbeat => 0,
        PacketType::EndOfSession => u16::MAX,
    };
    wtr.write_u16::<BigEndian>(packet_type).unwrap();
    Ok(buf)
}

pub fn decode_message_length<R>(rdr: &mut R) -> u16
where
    R: Read,
{
    rdr.read_u16::<BigEndian>().unwrap()
}
pub fn encode_message<W>(wtr: &mut W, message: &[u8]) -> io::Result<()>
where
    W: Write,
{
    let length =
        u16::try_from(message.len()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    wtr.write_u16::<BigEndian>(length)?;
    wtr.write_all(message)?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub session: SessionId,
    /// first requested sequence number
    pub sequence_number: SequenceNumber,
    /// the number of messages requested for retransmission
    pub message_count: MessageCount,
}
const REQUEST_SIZE: usize = 20;
pub fn decode_request(buf: [u8; REQUEST_SIZE]) -> Request {
    let mut rdr = io::Cursor::new(&buf[..]);
    let mut session = SessionId::default();
    rdr.read_exact(&mut session).unwrap();
    let sequence_number = rdr.read_u64::<BigEndian>().unwrap();
    let message_count = rdr.read_u16::<BigEndian>().unwrap();
    Request {
        session,
        sequence_number,
        message_count,
    }
}
pub fn encode_request(request: Request) -> [u8; REQUEST_SIZE] {
    let mut buf = [0; REQUEST_SIZE];
    let mut wtr = io::Cursor::new(&mut buf[..]);
    wtr.write_all(&request.session).unwrap();
    wtr.write_u64::<BigEndian>(request.sequence_number).unwrap();
    wtr.write_u16::<BigEndian>(request.message_count).unwrap();
    buf
}
