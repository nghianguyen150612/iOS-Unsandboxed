pub const VERSION: u16 = 1;
pub const HEADER: usize = 20;
pub const MAX_PAYLOAD: usize = 512;
pub const MAGIC: &[u8; 4] = b"IUIP";
pub const PING: u16 = 1;
pub const GET_STATUS: u16 = 2;
pub const GET_PREFLIGHT: u16 = 3;
pub const RESPONSE: u16 = 0x8000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    Success = 0,
    UnsupportedVersion = 1,
    InvalidRequest = 2,
    PermissionDenied = 3,
    NotImplemented = 4,
    ServiceUnavailable = 5,
    PreflightUnverified = 6,
    UnsupportedPlatform = 7,
    InternalError = 8,
    Timeout = 9,
}

impl TryFrom<u32> for ErrorCode {
    type Error = ();
    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Success),
            1 => Ok(Self::UnsupportedVersion),
            2 => Ok(Self::InvalidRequest),
            3 => Ok(Self::PermissionDenied),
            4 => Ok(Self::NotImplemented),
            5 => Ok(Self::ServiceUnavailable),
            6 => Ok(Self::PreflightUnverified),
            7 => Ok(Self::UnsupportedPlatform),
            8 => Ok(Self::InternalError),
            9 => Ok(Self::Timeout),
            _ => Err(()),
        }
    }
}

pub fn request_frame(ty: u16, id: u32) -> [u8; HEADER] {
    let mut h = [0; HEADER];
    h[..4].copy_from_slice(MAGIC);
    h[4..6].copy_from_slice(&VERSION.to_be_bytes());
    h[6..8].copy_from_slice(&ty.to_be_bytes());
    h[8..12].copy_from_slice(&id.to_be_bytes());
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_header_has_fixed_offsets_and_big_endian_values() {
        let h = request_frame(GET_STATUS, 0x1234_5678);
        assert_eq!(&h[..4], b"IUIP");
        assert_eq!(&h[4..8], &[0, 1, 0, 2]);
        assert_eq!(&h[8..12], &[0x12, 0x34, 0x56, 0x78]);
        assert!(h[12..].iter().all(|b| *b == 0));
    }
    #[test]
    fn every_protocol_error_value_is_stable() {
        for n in 0..=9 {
            assert_eq!(ErrorCode::try_from(n).unwrap() as u32, n);
        }
        assert!(ErrorCode::try_from(10).is_err());
    }
}
