use super::protocol::{self, ErrorCode};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const SOCKET: &str = "/var/run/ios-unsandboxedd.sock";
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub struct IpcError(pub String);
impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for IpcError {}

#[derive(Debug)]
pub struct Status {
    pub compatibility: u32,
    pub daemon_running: bool,
    pub activation: bool,
    pub interception: bool,
    pub device_verified: bool,
    pub lifecycle: Option<LifecycleStatus>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateFileStatus {
    DirectoryMissing,
    FileMissing,
    Valid,
    Unsafe,
    UnsupportedSchema,
    Corrupt,
    IoError,
}
#[derive(Debug, Clone, Copy)]
pub struct LifecycleStatus {
    pub state_file: StateFileStatus,
    pub schema_version: u32,
    pub schema_supported: bool,
    pub service_installed: bool,
    pub peer_uid: u32,
    pub peer_gid: u32,
}
#[derive(Debug)]
pub struct TestSocketCheck {
    pub status: Status,
    pub preflight: Preflight,
}
#[derive(Debug)]
pub struct Preflight {
    pub compatibility: u32,
    pub family: u32,
    pub architecture: u32,
    pub device_match: u32,
    pub os_match: u32,
}

fn request(path: &Path, ty: u16) -> Result<(ErrorCode, Vec<u8>), IpcError> {
    let mut stream = UnixStream::connect(path).map_err(|e| IpcError(e.to_string()))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .map_err(|e| IpcError(e.to_string()))?;
    stream
        .set_write_timeout(Some(TIMEOUT))
        .map_err(|e| IpcError(e.to_string()))?;
    let id = 1u32;
    stream
        .write_all(&protocol::request_frame(ty, id))
        .map_err(|e| IpcError(e.to_string()))?;
    let mut h = [0u8; protocol::HEADER];
    stream
        .read_exact(&mut h)
        .map_err(|e| IpcError(e.to_string()))?;
    if &h[..4] != protocol::MAGIC {
        return Err(IpcError("invalid response magic".into()));
    }
    if u16::from_be_bytes([h[4], h[5]]) != protocol::VERSION {
        return Err(IpcError("unsupported response version".into()));
    }
    if u16::from_be_bytes([h[6], h[7]]) != (ty | protocol::RESPONSE) {
        return Err(IpcError("unexpected response type".into()));
    }
    if u32::from_be_bytes(h[8..12].try_into().unwrap()) != id {
        return Err(IpcError("response request ID mismatch".into()));
    }
    let n = u32::from_be_bytes(h[12..16].try_into().unwrap()) as usize;
    if n > protocol::MAX_PAYLOAD {
        return Err(IpcError("oversized response payload".into()));
    }
    let status = ErrorCode::try_from(u32::from_be_bytes(h[16..20].try_into().unwrap()))
        .map_err(|_| IpcError("invalid response status".into()))?;
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .map_err(|e| IpcError(e.to_string()))?;
    if status != ErrorCode::Success
        && !(ty == protocol::GET_PREFLIGHT
            && (status == ErrorCode::PreflightUnverified
                || status == ErrorCode::UnsupportedPlatform))
        && !(ty == protocol::GET_LIFECYCLE_STATUS && status == ErrorCode::NotImplemented)
    {
        return Err(IpcError(format!("daemon returned {status:?}")));
    }
    Ok((status, body))
}

pub fn ping() -> Result<(), IpcError> {
    ping_at(Path::new(SOCKET))
}
fn ping_at(path: &Path) -> Result<(), IpcError> {
    let (_, body) = request(path, protocol::PING)?;
    if body.len() < 2
        || body[0] as usize != body.len() - 1
        || std::str::from_utf8(&body[1..]).is_err()
    {
        return Err(IpcError("invalid PING response".into()));
    }
    Ok(())
}
pub fn get_status() -> Result<Status, IpcError> {
    status_at(Path::new(SOCKET))
}
pub fn get_status_test_socket(path: &Path) -> Result<Status, IpcError> {
    status_at(path)
}
pub fn test_socket_check(path: &Path) -> Result<TestSocketCheck, IpcError> {
    ping_at(path)?;
    let legacy = legacy_status_at(path)?;
    let preflight = preflight_at(path)?;
    let status = status_at(path)?;
    if legacy.compatibility != preflight.compatibility
        || status.compatibility != preflight.compatibility
    {
        return Err(IpcError("daemon status and preflight disagree".into()));
    }
    Ok(TestSocketCheck { status, preflight })
}
fn status_at(path: &Path) -> Result<Status, IpcError> {
    let lifecycle_response = request(path, protocol::GET_LIFECYCLE_STATUS)?;
    if lifecycle_response.0 == ErrorCode::NotImplemented {
        return legacy_status_at(path);
    }
    let (_, b) = lifecycle_response;
    if b.len() != 22 || b[0] != 1 || b[1] > 6 || b[2] > 1 || b[3] != 0 || b[4] > 1 || b[5] != 0 {
        return Err(IpcError("invalid lifecycle status response".into()));
    }
    let state_file = match b[1] {
        0 => StateFileStatus::DirectoryMissing,
        1 => StateFileStatus::FileMissing,
        2 => StateFileStatus::Valid,
        3 => StateFileStatus::Unsafe,
        4 => StateFileStatus::UnsupportedSchema,
        5 => StateFileStatus::Corrupt,
        6 => StateFileStatus::IoError,
        _ => unreachable!(),
    };
    let schema_version = u32::from_be_bytes(b[6..10].try_into().unwrap());
    let compatibility = u32::from_be_bytes(b[10..14].try_into().unwrap());
    let peer_uid = u32::from_be_bytes(b[14..18].try_into().unwrap());
    let peer_gid = u32::from_be_bytes(b[18..22].try_into().unwrap());
    if (state_file == StateFileStatus::Valid) != (b[2] == 1) {
        return Err(IpcError("inconsistent lifecycle state schema".into()));
    }
    if (state_file == StateFileStatus::Valid) != (b[4] == 1)
        || (state_file == StateFileStatus::Valid && schema_version != 1)
        || (state_file == StateFileStatus::UnsupportedSchema && schema_version == 1)
    {
        return Err(IpcError("inconsistent lifecycle state metadata".into()));
    }
    Ok(Status {
        daemon_running: true,
        compatibility,
        activation: false,
        interception: false,
        device_verified: false,
        lifecycle: Some(LifecycleStatus {
            state_file,
            schema_version,
            schema_supported: b[2] != 0,
            service_installed: b[4] != 0,
            peer_uid,
            peer_gid,
        }),
    })
}
fn legacy_status_at(path: &Path) -> Result<Status, IpcError> {
    let (_, b) = request(path, protocol::GET_STATUS)?;
    if b.len() != 8 || b[0] != 1 || b[5..].iter().any(|v| *v > 1) {
        return Err(IpcError("invalid status response".into()));
    }
    Ok(Status {
        daemon_running: true,
        compatibility: u32::from_be_bytes(b[1..5].try_into().unwrap()),
        activation: b[5] != 0,
        interception: b[6] != 0,
        device_verified: b[7] != 0,
        lifecycle: None,
    })
}
pub fn get_preflight() -> Result<Preflight, IpcError> {
    preflight_at(Path::new(SOCKET))
}
fn preflight_at(path: &Path) -> Result<Preflight, IpcError> {
    let (_, b) = request(path, protocol::GET_PREFLIGHT)?;
    if b.len() < 24 {
        return Err(IpcError("truncated preflight response".into()));
    }
    let mut values = [0u32; 5];
    for (i, v) in values.iter_mut().enumerate() {
        let p = 4 * i;
        *v = u32::from_be_bytes(b[p..p + 4].try_into().unwrap());
    }
    let mut pos = 20;
    for _ in 0..4 {
        if pos >= b.len() {
            return Err(IpcError("truncated preflight text".into()));
        }
        let n = b[pos] as usize;
        pos += 1;
        if pos + n > b.len() || std::str::from_utf8(&b[pos..pos + n]).is_err() {
            return Err(IpcError("invalid preflight text".into()));
        }
        pos += n;
    }
    if pos != b.len() {
        return Err(IpcError("trailing preflight data".into()));
    }
    Ok(Preflight {
        compatibility: values[0],
        family: values[1],
        architecture: values[2],
        device_match: values[3],
        os_match: values[4],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixListener, thread};
    fn fixture(response_type: u16, id: u32, status: u32, body: &[u8]) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "iu-ipc-client-{}-{}-{}.sock",
            std::process::id(),
            response_type,
            id
        ));
        let _ = std::fs::remove_file(&p);
        let l = UnixListener::bind(&p).unwrap();
        let body = body.to_vec();
        thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut req = [0; protocol::HEADER];
            s.read_exact(&mut req).unwrap();
            let mut h = [0; protocol::HEADER];
            h[..4].copy_from_slice(protocol::MAGIC);
            h[4..6].copy_from_slice(&1u16.to_be_bytes());
            h[6..8].copy_from_slice(&response_type.to_be_bytes());
            h[8..12].copy_from_slice(&id.to_be_bytes());
            h[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
            h[16..20].copy_from_slice(&status.to_be_bytes());
            s.write_all(&h).unwrap();
            s.write_all(&body).unwrap();
        });
        p
    }
    fn sequence_fixture(responses: Vec<(u16, u32, Vec<u8>)>) -> std::path::PathBuf {
        let p =
            std::env::temp_dir().join(format!("iu-ipc-client-{}-legacy.sock", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let listener = UnixListener::bind(&p).unwrap();
        thread::spawn(move || {
            for (request_type, status, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0; protocol::HEADER];
                stream.read_exact(&mut request).unwrap();
                assert_eq!(u16::from_be_bytes([request[6], request[7]]), request_type);
                let mut response = [0; protocol::HEADER];
                response[..4].copy_from_slice(protocol::MAGIC);
                response[4..6].copy_from_slice(&protocol::VERSION.to_be_bytes());
                response[6..8].copy_from_slice(&(request_type | protocol::RESPONSE).to_be_bytes());
                response[8..12].copy_from_slice(&request[8..12]);
                response[12..16].copy_from_slice(&(body.len() as u32).to_be_bytes());
                response[16..20].copy_from_slice(&status.to_be_bytes());
                stream.write_all(&response).unwrap();
                stream.write_all(&body).unwrap();
            }
        });
        p
    }
    #[test]
    fn ping_response_and_request_id_are_checked() {
        let p = fixture(
            protocol::PING | protocol::RESPONSE,
            1,
            0,
            &[5, b'0', b'.', b'1', b'.', b'0'],
        );
        assert!(ping_at(&p).is_ok());
        let _ = std::fs::remove_file(p);
    }
    #[test]
    fn unexpected_response_id_and_type_are_rejected() {
        let p = fixture(protocol::PING | protocol::RESPONSE, 2, 0, &[0]);
        assert!(ping_at(&p).is_err());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn lifecycle_status_reports_disabled_state_and_install_record() {
        let mut body = vec![1, 2, 1, 0, 1, 0];
        body.extend_from_slice(&1u32.to_be_bytes());
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        let p = fixture(
            protocol::GET_LIFECYCLE_STATUS | protocol::RESPONSE,
            1,
            0,
            &body,
        );
        let status = status_at(&p).unwrap();
        assert!(!status.activation);
        let lifecycle = status.lifecycle.unwrap();
        assert_eq!(lifecycle.state_file, StateFileStatus::Valid);
        assert!(lifecycle.schema_supported);
        assert_eq!(lifecycle.schema_version, 1);
        assert!(lifecycle.service_installed);
        assert_eq!(lifecycle.peer_uid, 1000);
        assert_eq!(lifecycle.peer_gid, 1000);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn lifecycle_request_falls_back_to_unchanged_p004_status() {
        let path = sequence_fixture(vec![
            (
                protocol::GET_LIFECYCLE_STATUS,
                ErrorCode::NotImplemented as u32,
                Vec::new(),
            ),
            (
                protocol::GET_STATUS,
                ErrorCode::Success as u32,
                vec![1, 0, 0, 0, 4, 0, 0, 0],
            ),
        ]);
        let status = status_at(&path).unwrap();
        assert_eq!(status.compatibility, 4);
        assert!(!status.activation);
        assert!(status.lifecycle.is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn lifecycle_status_cannot_claim_device_acceptance_in_p005() {
        let mut body = vec![1, 0, 0, 0, 0, 1];
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&4u32.to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        body.extend_from_slice(&1000u32.to_be_bytes());
        let path = fixture(
            protocol::GET_LIFECYCLE_STATUS | protocol::RESPONSE,
            9,
            0,
            &body,
        );
        assert!(status_at(&path).is_err());
        let _ = std::fs::remove_file(path);
    }
}
