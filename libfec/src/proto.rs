use thiserror::Error;

pub const MAGIC: u32 = 0x5553_5032; // "USP2"
pub const VERSION: u8 = 1;
pub const FLAG_CONTROL: u8 = 0b0000_0001;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub payload_len: u16,
}

impl Header {
    pub const SIZE: usize = 4;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("buffer too short")]
    TooShort,
    #[error("invalid magic")]
    InvalidMagic,
    #[error("unsupported version: {0}")]
    UnsupportedVersion(u8),
    #[error("payload length mismatch")]
    PayloadLengthMismatch,
    #[error("payload too large")]
    PayloadTooLarge,
}

pub fn encode_packet(flags: u8, payload: &[u8]) -> Result<Vec<u8>, ProtoError> {
    if payload.len() > u16::MAX as usize {
        return Err(ProtoError::PayloadTooLarge);
    }

    let mut out = Vec::with_capacity(4 + Header::SIZE + payload.len());
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.push(VERSION);
    out.push(flags);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_packet(buf: &[u8]) -> Result<Packet, ProtoError> {
    let min_len = 4 + Header::SIZE;
    if buf.len() < min_len {
        return Err(ProtoError::TooShort);
    }

    let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != MAGIC {
        return Err(ProtoError::InvalidMagic);
    }

    let version = buf[4];
    if version != VERSION {
        return Err(ProtoError::UnsupportedVersion(version));
    }

    let flags = buf[5];
    let payload_len = u16::from_be_bytes([buf[6], buf[7]]);

    let actual_payload = &buf[min_len..];
    if actual_payload.len() != payload_len as usize {
        return Err(ProtoError::PayloadLengthMismatch);
    }

    Ok(Packet {
        header: Header {
            version,
            flags,
            payload_len,
        },
        payload: actual_payload.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = b"hello world";
        let encoded = encode_packet(0b0000_0011, payload).expect("encode should succeed");
        let decoded = decode_packet(&encoded).expect("decode should succeed");
        assert_eq!(decoded.header.flags, 0b0000_0011);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn control_flag_constant_is_single_bit() {
        assert_eq!(FLAG_CONTROL, 0b0000_0001);
    }
}
