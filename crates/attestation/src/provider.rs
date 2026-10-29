//! Attestation provider service over Unix domain sockets
use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

use parity_scale_codec::{Decode, Encode};

use crate::{AttestationError, AttestationExchangeMessage};

/// Maximum encoded result size, including SCALE discriminants.
pub const MAX_RESPONSE_SIZE: usize = 256 * 1024;
/// Wire errors deliberately exclude internal diagnostic details.
#[derive(Debug, Encode, Decode)]
pub enum ProviderError {
    #[codec(index = 0)]
    InvalidRequest,
    #[codec(index = 1)]
    GenerationFailed,
}
pub type ProviderResponse = Result<AttestationExchangeMessage, ProviderError>;

pub(crate) fn validate_path(path: &Path) -> Result<(), AttestationError> {
    if !path.is_absolute() {
        return Err(AttestationError::AttestationProviderPath(
            "Expected an absolute filesystem path".into(),
        ));
    }
    Ok(())
}

/// Send 64 bytes and a write-half EOF. Receive a length-prefixed SCALE
/// result. This blocks for at most one second and requires no async
/// runtime.
pub fn request_attestation(
    path: &Path,
    input: [u8; 64],
) -> Result<AttestationExchangeMessage, AttestationError> {
    validate_path(path)?;
    request_unix(path, input).map_err(|e| AttestationError::AttestationProvider(e.to_string()))
}

/// Request an attestation over a unix socket
fn request_unix(path: &Path, input: [u8; 64]) -> std::io::Result<AttestationExchangeMessage> {
    let deadline = Instant::now() + Duration::from_secs(1);
    let remaining = || {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Provider deadline exceeded"))
    };

    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.connect_timeout(&socket2::SockAddr::unix(path)?, remaining()?)?;

    let mut stream = UnixStream::from(socket);
    let mut pending = &input[..];

    while !pending.is_empty() {
        stream.set_write_timeout(Some(remaining()?))?;
        let n = stream.write(pending)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        pending = &pending[n..];
    }

    stream.shutdown(Shutdown::Write)?;

    let mut read_exact = |mut buf: &mut [u8]| -> io::Result<()> {
        while !buf.is_empty() {
            stream.set_read_timeout(Some(remaining()?))?;
            let n = stream.read(buf)?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            buf = &mut buf[n..];
        }
        Ok(())
    };

    let mut header = [0; 4];
    read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;

    if len == 0 || len > MAX_RESPONSE_SIZE {
        return Err(invalid("Invalid provider response length"));
    }

    let mut body = vec![0; len];
    read_exact(&mut body)?;
    stream.set_read_timeout(Some(remaining()?))?;

    if stream.read(&mut [0])? != 0 {
        return Err(invalid("Trailing provider response bytes"));
    }

    let mut bytes = &body[..];
    let result = ProviderResponse::decode(&mut bytes).map_err(|e| invalid(e.to_string()))?;

    if !bytes.is_empty() {
        return Err(invalid("Trailing SCALE data"));
    }

    result.map_err(|e| invalid(format!("Provider returned {e:?}")))
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
