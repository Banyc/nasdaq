use std::io::{self, Read};

use byteorder::BigEndian;
use tokio::io::{AsyncRead, AsyncWrite};

const FRAME_TYPE_DEBUG: u8 = b'+';
const FRAME_TYPE_LOGIN_ACCEPTED: u8 = b'A';
const FRAME_TYPE_LOGIN_REJECTED: u8 = b'J';
const FRAME_TYPE_SEQUENCED_DATA: u8 = b'S';
const FRAME_TYPE_SERVER_HEARTBEAT: u8 = b'H';
const FRAME_TYPE_END_OF_SESSION: u8 = b'Z';
const FRAME_TYPE_LOGIN_REQUEST: u8 = b'L';
const FRAME_TYPE_UNSEQUENCED_DATA: u8 = b'U';
const FRAME_TYPE_CLIENT_HEARTHEAT: u8 = b'R';
const FRAME_TYPE_LOGOUT_REQUEST: u8 = b'O';
const SEQUENCE_NUMBER_LENGTH: usize = 20;

pub type SessionId = [u8; 10];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZeroMessageFrame {
    ServerHeartbeat,
    ClientHeartbeat,
    EndOfSession,
    LogoutRequest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFrameType {
    Sequenced,
    Unsequenced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Debug,
    LoginAccepted,
    LoginRejected,
    LoginRequest,
    Data(DataFrameType),
    ZeroMessage(ZeroMessageFrame),
}
impl FrameType {
    pub fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            FRAME_TYPE_DEBUG => Self::Debug,
            FRAME_TYPE_LOGIN_ACCEPTED => Self::LoginAccepted,
            FRAME_TYPE_LOGIN_REJECTED => Self::LoginRejected,
            FRAME_TYPE_SEQUENCED_DATA => Self::Data(DataFrameType::Sequenced),
            FRAME_TYPE_SERVER_HEARTBEAT => Self::ZeroMessage(ZeroMessageFrame::ServerHeartbeat),
            FRAME_TYPE_END_OF_SESSION => Self::ZeroMessage(ZeroMessageFrame::EndOfSession),
            FRAME_TYPE_LOGIN_REQUEST => Self::LoginRequest,
            FRAME_TYPE_UNSEQUENCED_DATA => Self::Data(DataFrameType::Unsequenced),
            FRAME_TYPE_CLIENT_HEARTHEAT => Self::ZeroMessage(ZeroMessageFrame::ClientHeartbeat),
            FRAME_TYPE_LOGOUT_REQUEST => Self::ZeroMessage(ZeroMessageFrame::LogoutRequest),
            _ => return None,
        })
    }
    pub fn as_u8(&self) -> u8 {
        match self {
            FrameType::Debug => FRAME_TYPE_DEBUG,
            FrameType::LoginAccepted => FRAME_TYPE_LOGIN_ACCEPTED,
            FrameType::LoginRejected => FRAME_TYPE_LOGIN_REJECTED,
            FrameType::Data(DataFrameType::Sequenced) => FRAME_TYPE_SEQUENCED_DATA,
            FrameType::LoginRequest => FRAME_TYPE_LOGIN_REQUEST,
            FrameType::Data(DataFrameType::Unsequenced) => FRAME_TYPE_UNSEQUENCED_DATA,
            FrameType::ZeroMessage(x) => match x {
                ZeroMessageFrame::ServerHeartbeat => FRAME_TYPE_SERVER_HEARTBEAT,
                ZeroMessageFrame::ClientHeartbeat => FRAME_TYPE_CLIENT_HEARTHEAT,
                ZeroMessageFrame::EndOfSession => FRAME_TYPE_END_OF_SESSION,
                ZeroMessageFrame::LogoutRequest => FRAME_TYPE_LOGOUT_REQUEST,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub enum DecodedControl {
    Debug(String),
    LoginAccepted(LoginAccepted),
    LoginRejected(LoginRejectReason),
    LoginRequest(LoginRequest),
    Data { ty: DataFrameType, length: usize },
    ZeroMessage(ZeroMessageFrame),
}

/// dispatcher
pub async fn decode_frame<R>(rdr: &mut R) -> io::Result<DecodedControl>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut header = [0; HEADER_SIZE];
    rdr.read_exact(&mut header).await?;
    let (frame_type, message_length) = decode_header(header)?;
    Ok(match frame_type {
        FrameType::Debug => DecodedControl::Debug(decode_debug(rdr, message_length).await?),
        FrameType::LoginAccepted => {
            DecodedControl::LoginAccepted(decode_login_accepted(rdr, message_length).await?)
        }
        FrameType::LoginRejected => {
            DecodedControl::LoginRejected(decode_login_rejected(rdr, message_length).await?)
        }
        FrameType::Data(ty) => DecodedControl::Data {
            ty,
            length: message_length,
        },
        FrameType::ZeroMessage(x) => DecodedControl::ZeroMessage(x),
        FrameType::LoginRequest => {
            DecodedControl::LoginRequest(decode_login_request(rdr, message_length).await?)
        }
    })
}
const HEADER_SIZE: usize = 3;
fn decode_header(buf: [u8; HEADER_SIZE]) -> io::Result<(FrameType, usize)> {
    use byteorder::ReadBytesExt;
    let mut rdr = io::Cursor::new(&buf[..]);
    let frame_length = rdr.read_u16::<BigEndian>()?;
    let frame_type = rdr.read_u8()?;
    let frame_type = FrameType::from_u8(frame_type)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "frame type"))?;
    let message_length = (frame_length - 1) as usize;
    Ok((frame_type, message_length))
}
fn encode_header(frame_type: FrameType, message_length: usize) -> io::Result<[u8; HEADER_SIZE]> {
    use byteorder::WriteBytesExt;
    let mut buf = [0; HEADER_SIZE];
    let mut wtr = io::Cursor::new(&mut buf[..]);
    let frame_length = u16::try_from(message_length + 1)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    wtr.write_u16::<BigEndian>(frame_length)?;
    wtr.write_u8(frame_type.as_u8())?;
    Ok(buf)
}

async fn decode_debug<R>(rdr: &mut R, message_length: usize) -> io::Result<String>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(message_length);
    rdr.read_exact(&mut buf).await?;
    String::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}
pub async fn encode_debug<W>(wtr: &mut W, text: String) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let header = encode_header(FrameType::Debug, text.len())?;
    wtr.write_all(&header).await?;
    wtr.write_all(text.as_bytes()).await?;
    Ok(())
}

fn decode_sequence_number(buf: [u8; SEQUENCE_NUMBER_LENGTH]) -> io::Result<usize> {
    let mut sum = 0;
    let mut mag = 1;
    for &byte in buf.iter().rev() {
        if byte == b' ' {
            break;
        }
        if byte < b'0' {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ASCII digit below zero",
            ));
        }
        let digit = byte - b'0';
        if 9 < digit {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ASCII digit above nine",
            ));
        }
        sum += usize::from(digit) * mag;
        mag *= 10;
    }
    Ok(sum)
}
fn encode_sequence_number(sequence_number: usize) -> io::Result<[u8; SEQUENCE_NUMBER_LENGTH]> {
    let mut remaining = sequence_number;
    let mut buf = [0; SEQUENCE_NUMBER_LENGTH];
    for (i, byte) in buf.iter_mut().rev().enumerate() {
        if remaining == 0 && i != 0 {
            *byte = b' ';
            continue;
        }
        let digit = u8::try_from(remaining % 10).unwrap();
        remaining /= 10;
        *byte = b'0' + digit;
    }
    if remaining != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, ""));
    }
    Ok(buf)
}
#[cfg(test)]
#[tokio::test]
async fn test_sequence_number() {
    let n = [12345, 1, 0];
    for n in n {
        let buf = encode_sequence_number(n).unwrap();
        let o = decode_sequence_number(buf).unwrap();
        assert_eq!(n, o);
    }
}

const LOGIN_ACCEPTED_SIZE: usize = 30;
#[derive(Debug, Clone, Copy)]
pub struct LoginAccepted {
    pub session: SessionId,
    pub sequence_number: usize,
}
async fn decode_login_accepted<R>(rdr: &mut R, message_length: usize) -> io::Result<LoginAccepted>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0; LOGIN_ACCEPTED_SIZE];
    if message_length != LOGIN_ACCEPTED_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message length"));
    }
    {
        use tokio::io::AsyncReadExt;
        rdr.read_exact(&mut buf).await?;
    }
    let mut rdr = io::Cursor::new(&buf[..]);
    let mut session = SessionId::default();
    rdr.read_exact(&mut session).unwrap();
    let mut sequence_number = [0; SEQUENCE_NUMBER_LENGTH];
    rdr.read_exact(&mut sequence_number).unwrap();
    let sequence_number = decode_sequence_number(sequence_number)?;
    Ok(LoginAccepted {
        session,
        sequence_number,
    })
}
pub async fn encode_login_accepted<W>(wtr: &mut W, message: LoginAccepted) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let mut buf = [0; LOGIN_ACCEPTED_SIZE + HEADER_SIZE];
    {
        let header = encode_header(FrameType::LoginAccepted, LOGIN_ACCEPTED_SIZE).unwrap();
        let mut wtr = io::Cursor::new(&mut buf[..]);
        wtr.write_all(&header).await.unwrap();
        wtr.write_all(&message.session).await.unwrap();
        let sequence_number = encode_sequence_number(message.sequence_number)?;
        wtr.write_all(&sequence_number).await.unwrap();
    }
    wtr.write_all(&buf).await?;
    Ok(())
}

const LOGIN_REJECTED_SIZE: usize = 1;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginRejectReason {
    /// There was an invalid username and password combination in the Login Request Message.
    NotAuthorized,
    /// The Requested Session in the Login Request Packet was either invalid or not available.
    SessionNotAvailable,
}
async fn decode_login_rejected<R>(
    rdr: &mut R,
    message_length: usize,
) -> io::Result<LoginRejectReason>
where
    R: AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    if message_length != LOGIN_REJECTED_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message length"));
    }
    let reason = rdr.read_u8().await?;
    Ok(match reason {
        b'A' => LoginRejectReason::NotAuthorized,
        b'S' => LoginRejectReason::SessionNotAvailable,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "login reject reason",
            ))
        }
    })
}
pub async fn encode_login_rejected<W>(wtr: &mut W, message: LoginRejectReason) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0; LOGIN_REJECTED_SIZE + HEADER_SIZE];
    {
        use byteorder::WriteBytesExt;
        use std::io::Write;
        let mut wtr = io::Cursor::new(&mut buf[..]);
        let header = encode_header(FrameType::LoginRejected, LOGIN_REJECTED_SIZE).unwrap();
        let reason = match message {
            LoginRejectReason::NotAuthorized => b'A',
            LoginRejectReason::SessionNotAvailable => b'S',
        };
        wtr.write_all(&header).unwrap();
        wtr.write_u8(reason).unwrap();
    }
    {
        use tokio::io::AsyncWriteExt;
        wtr.write_all(&buf).await?;
    }
    Ok(())
}
#[cfg(test)]
#[tokio::test]
async fn test_login_rejected() {
    let m = [
        LoginRejectReason::NotAuthorized,
        LoginRejectReason::SessionNotAvailable,
    ];
    for m in m {
        let mut buf = [0; LOGIN_REJECTED_SIZE + HEADER_SIZE];
        let mut wtr = io::Cursor::new(&mut buf[..]);
        encode_login_rejected(&mut wtr, m).await.unwrap();
        let mut rdr = io::Cursor::new(&buf);
        let o = decode_frame(&mut rdr).await.unwrap();
        let DecodedControl::LoginRejected(o) = o else {
            panic!()
        };
        assert_eq!(o, m);
    }
}

pub async fn encode_data<W>(wtr: &mut W, ty: DataFrameType, message: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let header = encode_header(FrameType::Data(ty), message.len())?;
    wtr.write_all(&header).await?;
    wtr.write_all(message).await?;
    Ok(())
}
#[cfg(test)]
#[tokio::test]
async fn test_data() {
    let ty = [DataFrameType::Sequenced, DataFrameType::Unsequenced];
    let m = [vec![], vec![1], vec![1, 2]];
    for ty in ty {
        for m in &m {
            let mut buf = vec![0; 128];
            let mut wtr = io::Cursor::new(&mut buf[..]);
            encode_data(&mut wtr, ty, m).await.unwrap();
            let mut rdr = io::Cursor::new(&buf);
            let o = decode_frame(&mut rdr).await.unwrap();
            let DecodedControl::Data { ty: o_ty, length } = o else {
                panic!()
            };
            assert_eq!(ty, o_ty);
            let mut o_m = vec![0; length];
            rdr.read_exact(&mut o_m).unwrap();
            assert_eq!(*m, o_m);
        }
    }
}

pub async fn encode_zero_message<W>(wtr: &mut W, message: ZeroMessageFrame) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;
    let header = encode_header(FrameType::ZeroMessage(message), 0).unwrap();
    wtr.write_all(&header).await?;
    Ok(())
}
#[cfg(test)]
#[tokio::test]
async fn test_zero_message() {
    let m = [
        ZeroMessageFrame::ServerHeartbeat,
        ZeroMessageFrame::LogoutRequest,
    ];
    for m in m {
        let mut buf = vec![0; HEADER_SIZE];
        let mut wtr = io::Cursor::new(&mut buf[..]);
        encode_zero_message(&mut wtr, m).await.unwrap();
        let mut rdr = io::Cursor::new(&buf);
        let o = decode_frame(&mut rdr).await.unwrap();
        let DecodedControl::ZeroMessage(o) = o else {
            panic!()
        };
        assert_eq!(m, o);
    }
}

const LOGIN_REQUEST_SIZE: usize = 46;
/// Simple authentication is to prevent a client from inadvertently connecting to the wrong server
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginRequest {
    pub username: [u8; 6],
    pub password: [u8; 10],
    pub session: SessionId,
    pub sequence_number: usize,
}
async fn decode_login_request<R>(rdr: &mut R, message_length: usize) -> io::Result<LoginRequest>
where
    R: AsyncRead + Unpin,
{
    let mut buf = [0; LOGIN_REQUEST_SIZE];
    if message_length != LOGIN_REQUEST_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "message length"));
    }
    {
        use tokio::io::AsyncReadExt;
        rdr.read_exact(&mut buf).await?;
    }
    let mut rdr = io::Cursor::new(&buf[..]);
    let mut username = [0; 6];
    rdr.read_exact(&mut username).unwrap();
    let mut password = [0; 10];
    rdr.read_exact(&mut password).unwrap();
    let mut session = SessionId::default();
    rdr.read_exact(&mut session).unwrap();
    let mut seq = [0; SEQUENCE_NUMBER_LENGTH];
    rdr.read_exact(&mut seq).unwrap();
    let seq = decode_sequence_number(seq)?;
    Ok(LoginRequest {
        username,
        password,
        session,
        sequence_number: seq,
    })
}
pub async fn encode_login_request<W>(wtr: &mut W, message: LoginRequest) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buf = [0; LOGIN_REQUEST_SIZE + HEADER_SIZE];
    {
        use std::io::Write;
        let mut wtr = io::Cursor::new(&mut buf[..]);
        let header = encode_header(FrameType::LoginRequest, LOGIN_REQUEST_SIZE)?;
        wtr.write_all(&header).unwrap();
        wtr.write_all(&message.username).unwrap();
        wtr.write_all(&message.password).unwrap();
        wtr.write_all(&message.session).unwrap();
        let seq = encode_sequence_number(message.sequence_number)?;
        wtr.write_all(&seq).unwrap();
    }
    {
        use tokio::io::AsyncWriteExt;
        wtr.write_all(&buf).await?;
    }
    Ok(())
}
#[cfg(test)]
#[tokio::test]
async fn test_login_request() {
    let m = [LoginRequest {
        username: [1; 6],
        password: [2; 10],
        session: [3; 10],
        sequence_number: 12345,
    }];
    for m in m {
        let mut buf = [0; LOGIN_REQUEST_SIZE + HEADER_SIZE];
        let mut wtr = io::Cursor::new(&mut buf[..]);
        encode_login_request(&mut wtr, m).await.unwrap();
        let mut rdr = io::Cursor::new(&buf);
        let o = decode_frame(&mut rdr).await.unwrap();
        let DecodedControl::LoginRequest(o) = o else {
            panic!()
        };
        assert_eq!(o, m);
    }
}
