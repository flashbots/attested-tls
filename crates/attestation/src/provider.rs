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
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    socket.connect_timeout(&socket2::SockAddr::unix(path)?, remaining(deadline)?)?;

    let mut stream = UnixStream::from(socket);
    let mut pending = &input[..];

    while !pending.is_empty() {
        let n = io_with_deadline(deadline, |left| {
            stream.set_write_timeout(Some(left))?;
            stream.write(pending)
        })?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        pending = &pending[n..];
    }

    stream.shutdown(Shutdown::Write)?;

    let mut read_exact = |mut buf: &mut [u8]| -> io::Result<()> {
        while !buf.is_empty() {
            let n = io_with_deadline(deadline, |left| {
                stream.set_read_timeout(Some(left))?;
                stream.read(buf)
            })?;
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
    let trailing = io_with_deadline(deadline, |left| {
        stream.set_read_timeout(Some(left))?;
        stream.read(&mut [0])
    })?;
    if trailing != 0 {
        return Err(invalid("Trailing provider response bytes"));
    }

    let mut bytes = &body[..];
    let result = ProviderResponse::decode(&mut bytes).map_err(|e| invalid(e.to_string()))?;

    if !bytes.is_empty() {
        return Err(invalid("Trailing SCALE data"));
    }

    result.map_err(|e| invalid(format!("Provider returned {e:?}")))
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "Provider deadline exceeded"))
}

/// Retry interrupted I/O with the remaining budget, never a fresh timeout.
fn io_with_deadline<T>(
    deadline: Instant,
    mut operation: impl FnMut(Duration) -> io::Result<T>,
) -> io::Result<T> {
    loop {
        match operation(remaining(deadline)?) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => return result,
        }
    }
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_io_retries_then_returns_the_result() {
        let mut attempts = 0;
        let result = io_with_deadline(Instant::now() + Duration::from_secs(1), |_| {
            attempts += 1;
            if attempts < 3 { Err(io::ErrorKind::Interrupted.into()) } else { Ok(42) }
        });
        assert_eq!(result.unwrap(), 42);
        assert_eq!(attempts, 3);

        let error = io_with_deadline::<()>(Instant::now() + Duration::from_secs(1), |_| {
            Err(io::ErrorKind::ConnectionReset.into())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    }

    #[test]
    fn repeated_interruptions_cannot_extend_the_deadline() {
        let deadline = Instant::now() + Duration::from_millis(20);
        let mut previous = Duration::from_secs(1);
        let error = io_with_deadline::<()>(deadline, |left| {
            assert!(left <= previous);
            previous = left;
            std::thread::sleep(Duration::from_millis(5));
            Err(io::ErrorKind::Interrupted.into())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    }
}
