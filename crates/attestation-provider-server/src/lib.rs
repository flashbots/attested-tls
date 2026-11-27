//! Attestation generation through a group-accessible filesystem Unix
//! socket.
use std::{
    fs::{File, OpenOptions},
    io,
    os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
    time::Duration,
};

mod generator;

use attestation::{
    AttestationExchangeMessage,
    AttestationGeneratorClient,
    AttestationVerifier,
    Encode,
    provider::{MAX_RESPONSE_SIZE, ProviderError, ProviderResponse},
};
pub use generator::AttestationGenerator;
use nix::fcntl::{Flock, FlockArg, OFlag};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixSocket, UnixStream},
    time::timeout,
};

/// How long to wait before retrying on a recoverable accept error
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// The underlying unix socket for the service
pub struct ProviderSocket {
    pub listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
    // Fields drop after our Drop implementation, so cleanup runs while
    // locked.
    _lock: Flock<File>,
}

impl ProviderSocket {
    /// Remove stale service-owned sockets at startup; preserve active
    /// sockets and all other existing paths.
    pub fn bind(path: &Path) -> anyhow::Result<Self> {
        validate_socket_path(path)?;
        let lock = lock_socket(path)?;
        remove_stale_socket(path)?;
        let socket = UnixSocket::new_stream()?;
        socket.bind(path)?;
        let metadata = std::fs::symlink_metadata(path)?;
        // Establish the cleanup guard before any subsequent fallible
        // operation.
        let mut cleanup = SocketCleanup {
            path: path.into(),
            device: metadata.dev(),
            inode: metadata.ino(),
            armed: true,
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
        let listener = socket.listen(128)?;
        let result = Self {
            listener,
            path: cleanup.path.clone(),
            device: cleanup.device,
            inode: cleanup.inode,
            _lock: lock,
        };
        cleanup.armed = false;
        Ok(result)
    }
}

fn lock_socket(path: &Path) -> anyhow::Result<Flock<File>> {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    // Keep this file permanently: unlinking it would allow two instances to
    // lock different inodes. O_NONBLOCK also prevents a FIFO from hanging
    // open.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(Path::new(&lock_path))?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.uid() == nix::unistd::geteuid().as_raw(),
        "Lock file {} must be a service-owned regular file",
        Path::new(&lock_path).display()
    );
    Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, error)| {
        if error == nix::errno::Errno::EWOULDBLOCK {
            anyhow::anyhow!("Provider already running for {}", path.display())
        } else {
            error.into()
        }
    })
}

fn remove_stale_socket(path: &Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    anyhow::ensure!(
        metadata.file_type().is_socket() && metadata.uid() == nix::unistd::geteuid().as_raw(),
        "Existing socket path {} must be a service-owned socket",
        path.display()
    );

    // A nonblocking probe cannot hang if a live listener's backlog is full.
    // Only connection refusal proves that the socket has no listener.
    let probe = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)?;
    probe.set_nonblocking(true)?;
    match probe.connect(&socket2::SockAddr::unix(path)?) {
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {}
        Err(error) => return Err(error.into()),
        Ok(()) => anyhow::bail!("Socket {} is already in use", path.display()),
    }

    let current = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(
        current.dev() == metadata.dev() && current.ino() == metadata.ino(),
        "Socket {} changed during stale socket cleanup",
        path.display()
    );
    std::fs::remove_file(path)?;
    Ok(())
}

/// Walk from the root so each directory is protected against replacement
/// before looking up its child. Only root and the service uid are trusted
/// to change these directories. This keeps subsequent path-based
/// bind/chmod/unlink calls from being redirected by another user.
fn validate_socket_path(path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(path.is_absolute(), "Expected an absolute socket path");
    anyhow::ensure!(
        !path.components().any(|component| matches!(component, Component::ParentDir)),
        "Socket path must not contain '..'"
    );
    anyhow::ensure!(path.file_name().is_some(), "Missing socket filename");
    let parent = path.parent().ok_or_else(|| anyhow::anyhow!("Missing parent"))?;
    let uid = nix::unistd::geteuid().as_raw();
    let mut directory = PathBuf::new();
    for component in parent.components() {
        directory.push(component);
        let metadata = std::fs::symlink_metadata(&directory)?;
        anyhow::ensure!(
            metadata.is_dir() && (metadata.uid() == 0 || metadata.uid() == uid),
            "Socket directory {} must be a service/root-owned directory, not a symlink",
            directory.display()
        );
        // A trusted sticky ancestor (e.g. /tmp) protects its trusted-owned
        // children from replacement. The immediate parent must additionally
        // prevent other users from creating entries, including the socket.
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0 || (directory != parent && metadata.mode() & 0o1000 != 0),
            "Socket directory {} must not be group/other writable (except sticky ancestors)",
            directory.display()
        );
    }
    Ok(())
}

struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
    armed: bool,
}

fn cleanup(path: &Path, device: u64, inode: u64) {
    if let Ok(metadata) = std::fs::symlink_metadata(path) &&
        metadata.dev() == device &&
        metadata.ino() == inode
    {
        let _ = std::fs::remove_file(path);
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if self.armed {
            cleanup(&self.path, self.device, self.inode);
        }
    }
}

impl Drop for ProviderSocket {
    fn drop(&mut self) {
        cleanup(&self.path, self.device, self.inode);
    }
}

/// Serve an already-bound listener. The caller controls permissions and
/// path cleanup.
pub async fn attestation_provider_server(
    listener: &UnixListener,
    generator: AttestationGenerator,
) -> anyhow::Result<()> {
    loop {
        let (stream, _) = accept_with_retry(|| listener.accept()).await?;
        let generator = generator.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, generator).await {
                tracing::debug!(%error, "Provider connection failed");
            }
        });
    }
}

/// Retry connection failures and resource exhaustion without spinning.
/// Errors indicating a broken listener still propagate to the caller.
async fn accept_with_retry<T, F, Fut>(mut accept: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = io::Result<T>>,
{
    loop {
        match accept().await {
            Ok(connection) => return Ok(connection),
            Err(error) if retryable_accept_error(&error) => {
                tracing::warn!(%error, "Temporary accept failure; retrying in 100ms");
                tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn retryable_accept_error(error: &io::Error) -> bool {
    use nix::errno::Errno;

    matches!(
        error.kind(),
        io::ErrorKind::Interrupted |
            io::ErrorKind::WouldBlock |
            io::ErrorKind::ConnectionAborted |
            io::ErrorKind::ConnectionReset |
            io::ErrorKind::TimedOut
    ) || matches!(
        error.raw_os_error().map(Errno::from_raw),
        Some(Errno::EMFILE | Errno::ENFILE | Errno::ENOBUFS | Errno::ENOMEM)
    )
}

async fn serve_connection(
    mut stream: UnixStream,
    generator: AttestationGenerator,
) -> anyhow::Result<()> {
    let request = timeout(Duration::from_secs(1), async {
        let mut input = [0; 64];
        stream.read_exact(&mut input).await?;
        if stream.read(&mut [0]).await? != 0 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        Ok::<_, std::io::Error>(input)
    })
    .await?;

    let result: ProviderResponse = match request {
        Err(_) => Err(ProviderError::InvalidRequest),
        Ok(input) => generator
            .generate_attestation(input)
            .map(AttestationExchangeMessage::from)
            .map_err(|error| {
                tracing::error!(%error, "Attestation generation failed");
                ProviderError::GenerationFailed
            }),
    };

    let mut body = result.encode();
    if body.len() > MAX_RESPONSE_SIZE {
        tracing::error!("Generated evidence exceeds provider size limit");
        body = ProviderResponse::Err(ProviderError::GenerationFailed).encode();
    }

    timeout(Duration::from_secs(1), async {
        stream.write_all(&(body.len() as u32).to_be_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await
    })
    .await??;

    Ok(())
}

/// Request evidence and verify it using the supplied policy.
pub async fn attestation_provider_client(
    path: PathBuf,
    verifier: AttestationVerifier,
) -> anyhow::Result<AttestationExchangeMessage> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = AttestationGeneratorClient::new(path)?;
    let message =
        tokio::task::spawn_blocking(move || client.generate_attestation([0; 64])).await??;
    verifier.verify_attestation(message.clone(), [0; 64]).await?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use attestation::{AttestationType, Decode, provider::request_attestation};

    use super::*;

    #[tokio::test]
    async fn accept_recovers_after_resource_exhaustion_with_backoff() {
        use nix::errno::Errno;

        let mut errors = [Errno::EMFILE, Errno::ENFILE, Errno::ENOBUFS, Errno::ENOMEM].into_iter();
        let start = tokio::time::Instant::now();
        let connection = accept_with_retry(|| {
            std::future::ready(match errors.next() {
                Some(error) => Err(io::Error::from_raw_os_error(error as i32)),
                None => Ok(42),
            })
        })
        .await
        .unwrap();
        assert_eq!(connection, 42);
        assert!(start.elapsed() >= ACCEPT_RETRY_DELAY * 4);
    }

    #[tokio::test]
    async fn accept_propagates_broken_listener_errors_without_retrying() {
        use nix::errno::Errno;

        for error in [Errno::EBADF, Errno::EINVAL, Errno::ENOTSOCK, Errno::EACCES] {
            let mut attempts = 0;
            let result = accept_with_retry(|| {
                attempts += 1;
                assert_eq!(attempts, 1, "permanent errors must not be retried");
                std::future::ready(Err::<(), _>(io::Error::from_raw_os_error(error as i32)))
            })
            .await;
            assert_eq!(result.unwrap_err().raw_os_error(), Some(error as i32));
        }
    }

    #[tokio::test]
    async fn rejects_replaceable_ancestors() {
        let dir = tempfile::tempdir().unwrap();
        let ancestor = dir.path().join("ancestor");
        let parent = ancestor.join("service");
        std::fs::create_dir_all(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750)).unwrap();
        let path = parent.join("provider.sock");
        for mode in [0o777, 0o770] {
            std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(mode)).unwrap();
            assert!(ProviderSocket::bind(&path).is_err());
            assert!(!path.exists());
        }
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o1777)).unwrap();
        drop(ProviderSocket::bind(&path).unwrap());
        assert!(validate_socket_path(&ancestor.join("provider.sock")).is_err());
        std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o750)).unwrap();
        drop(ProviderSocket::bind(&path).unwrap());

        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&ancestor, &alias).unwrap();
        assert!(validate_socket_path(&alias.join("service/provider.sock")).is_err());
        assert!(validate_socket_path(&parent.join("../provider.sock")).is_err());
    }

    #[tokio::test]
    async fn lock_protects_socket_before_listen_and_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sock");
        let lock_path = dir.path().join("provider.sock.lock");
        let lock = lock_socket(&path).unwrap();
        let lock_inode = std::fs::metadata(&lock_path).unwrap().ino();
        let pending = UnixSocket::new_stream().unwrap();
        pending.bind(&path).unwrap();
        let socket_inode = std::fs::metadata(&path).unwrap().ino();

        let error = ProviderSocket::bind(&path).err().unwrap();
        assert!(error.to_string().contains("Provider already running"));
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), socket_inode);
        drop(pending);
        drop(lock);

        let socket = ProviderSocket::bind(&path).unwrap();
        assert!(ProviderSocket::bind(&path).is_err());
        drop(socket);
        assert!(!path.exists());
        assert_eq!(std::fs::metadata(&lock_path).unwrap().ino(), lock_inode);
        drop(ProviderSocket::bind(&path).unwrap());
        assert_eq!(std::fs::metadata(&lock_path).unwrap().ino(), lock_inode);
    }

    #[tokio::test]
    async fn rejects_symlink_and_nonregular_lock_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sock");
        let lock_path = dir.path().join("provider.sock.lock");
        let target = dir.path().join("target");
        std::fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &lock_path).unwrap();
        assert!(ProviderSocket::bind(&path).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"keep");
        assert!(!path.exists());
        std::fs::remove_file(&lock_path).unwrap();
        nix::unistd::mkfifo(
            &lock_path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(ProviderSocket::bind(&path).is_err());
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn replaces_stale_socket_after_listener_closes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sock");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(ProviderSocket::bind(&path).is_err());
        drop(listener);
        assert!(path.exists());

        let socket = ProviderSocket::bind(&path).unwrap();
        assert!(path.exists());
        drop(socket);
        assert!(!path.exists());
    }

    #[test]
    fn generator_requires_a_quote_type() {
        assert!(AttestationGenerator::new(AttestationType::None).is_err());
    }

    #[tokio::test]
    async fn unix_generator_round_trip_and_lifecycle() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sock");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o2750)).unwrap();
        let socket = ProviderSocket::bind(&path).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o660);
        assert_eq!(metadata.gid(), std::fs::metadata(dir.path()).unwrap().gid());
        assert!(ProviderSocket::bind(&path).is_err());
        let client = AttestationGeneratorClient::new(path.clone()).unwrap();
        let client =
            tokio::task::spawn_blocking(move || client.generate_attestation([42; 64]).unwrap());
        let (stream, _) = socket.listener.accept().await.unwrap();
        serve_connection(stream, AttestationGenerator::mock()).await.unwrap();
        let message = client.await.unwrap();
        let verifier = AttestationVerifier::mock();
        assert!(verifier.verify_attestation(message, [42; 64]).await.unwrap().is_some());
        drop(socket);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn invalid_requests_never_generate() {
        for input in [vec![1; 63], vec![1; 65]] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let worker = tokio::spawn(serve_connection(server, AttestationGenerator::mock()));
            client.write_all(&input).await.unwrap();
            client.shutdown().await.unwrap();
            let len = client.read_u32().await.unwrap();
            let mut body = vec![0; len as usize];
            client.read_exact(&mut body).await.unwrap();
            assert!(matches!(
                ProviderResponse::decode(&mut &body[..]).unwrap(),
                Err(ProviderError::InvalidRequest)
            ));
            worker.await.unwrap().unwrap();
        }
    }

    #[tokio::test]
    async fn rejects_unsafe_parent_and_preserves_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sock");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(ProviderSocket::bind(&path).is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&path, b"keep").unwrap();
        assert!(ProviderSocket::bind(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"keep");
        std::fs::remove_file(&path).unwrap();
        let target = dir.path().join("target");
        std::fs::write(&target, b"target").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(ProviderSocket::bind(&path).is_err());
        assert_eq!(std::fs::read_link(&path).unwrap(), target);
        std::fs::remove_file(&path).unwrap();
        let socket = ProviderSocket::bind(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        drop(socket);
        assert_eq!(std::fs::read(&path).unwrap(), b"replacement");
    }

    #[test]
    fn client_rejects_invalid_frames() {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixListener,
        };
        let valid = ProviderResponse::Ok(
            AttestationGenerator::mock().generate_attestation([42; 64]).unwrap().into(),
        )
        .encode();
        let mut frames =
            vec![vec![], vec![0; 4], ((MAX_RESPONSE_SIZE + 1) as u32).to_be_bytes().to_vec()];
        for body in [
            ProviderResponse::Ok(AttestationExchangeMessage::without_attestation()).encode(),
            vec![99],
            ProviderResponse::Err(ProviderError::GenerationFailed).encode(),
            [valid.clone(), vec![99]].concat(),
        ] {
            frames.push([(body.len() as u32).to_be_bytes().to_vec(), body].concat());
        }
        frames.push([10u32.to_be_bytes().to_vec(), valid.clone()].concat());
        frames.push([(valid.len() as u32).to_be_bytes().to_vec(), valid, vec![99]].concat());
        for frame in frames {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("test.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                assert_eq!(request, [42; 64]);
                for byte in frame {
                    if stream.write_all(&[byte]).is_err() {
                        break;
                    }
                }
            });
            assert!(request_attestation(&path, [42; 64]).is_err());
            server.join().unwrap();
        }
    }

    #[tokio::test]
    async fn cli_helper_verifies_over_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("provider.sock");
        let socket = ProviderSocket::bind(&path).unwrap();
        let client = tokio::spawn(attestation_provider_client(path, AttestationVerifier::mock()));
        let (stream, _) = socket.listener.accept().await.unwrap();
        serve_connection(stream, AttestationGenerator::mock()).await.unwrap();
        assert!(client.await.unwrap().unwrap().attestation_evidence.is_some());
    }

    #[tokio::test]
    async fn missing_request_eof_times_out() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&[42; 64]).await.unwrap();
        let result = serve_connection(server, AttestationGenerator::mock()).await;
        assert!(result.is_err());
    }

    #[test]
    fn successful_fragmented_evidence_and_stalled_response() {
        use std::{
            io::{Read, Write},
            os::unix::net::UnixListener,
        };
        for stalled in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("provider.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                assert_eq!(request, [42; 64]);
                if stalled {
                    std::thread::sleep(Duration::from_millis(1200));
                    return;
                }
                let evidence = attestation::AttestationEvidence {
                    quote: request,
                    platform: attestation::PlatformMetadata {
                        attestation_type: attestation::AttestationType::DcapTdx.try_into().unwrap(),
                        ram_bytes: 1234,
                        num_disks: 2,
                        acpi: None,
                        smbios_handoff: None,
                        dm_verity_boot: true,
                    },
                };
                let body = ProviderResponse::Ok(evidence.into()).encode();
                for byte in [(body.len() as u32).to_be_bytes().to_vec(), body].concat() {
                    stream.write_all(&[byte]).unwrap();
                }
            });
            let result = attestation::provider::request_attestation(&path, [42; 64]);
            if stalled {
                assert!(result.is_err());
            } else {
                let evidence = result.unwrap().attestation_evidence.unwrap();
                assert_eq!(evidence.quote, [42; 64]);
                assert_eq!(evidence.platform.ram_bytes, 1234);
                assert_eq!(evidence.platform.num_disks, 2);
                assert!(evidence.platform.dm_verity_boot);
            }
            server.join().unwrap();
        }
    }
}
