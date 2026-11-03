//! Attestation generation through a group-accessible filesystem Unix
//! socket.
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

pub use attestation::AttestationGenerator;
use attestation::{
    AttestationExchangeMessage,
    AttestationVerifier,
    Encode,
    provider::{MAX_RESPONSE_SIZE, ProviderError, ProviderResponse},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixSocket, UnixStream},
    time::timeout,
};

/// The underlying unix socket for the service
pub struct ProviderSocket {
    pub listener: UnixListener,
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl ProviderSocket {
    /// Existing paths are never removed at startup.
    pub fn bind(path: &Path) -> anyhow::Result<Self> {
        anyhow::ensure!(path.is_absolute(), "Expected an absolute socket path");
        let parent = std::fs::symlink_metadata(
            path.parent().ok_or_else(|| anyhow::anyhow!("Missing parent"))?,
        )?;
        let uid = nix::unistd::geteuid().as_raw();
        anyhow::ensure!(
            parent.is_dir() &&
                (parent.uid() == 0 || parent.uid() == uid) &&
                parent.mode() & 0o022 == 0,
            "Socket parent must be service/root-owned and not group/other writable"
        );
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
        };
        cleanup.armed = false;
        Ok(result)
    }
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
    listener: UnixListener,
    generator: AttestationGenerator,
) -> anyhow::Result<()> {
    loop {
        let (stream, _) = listener.accept().await?;
        let generator = generator.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, generator).await {
                tracing::debug!(%error, "Provider connection failed");
            }
        });
    }
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
        Ok(input) => generator.generate_attestation(input).map_err(|error| {
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
    let message = tokio::task::spawn_blocking(move || {
        attestation::provider::request_attestation(&path, [0; 64])
    })
    .await??;
    verifier.verify_attestation(message.clone(), [0; 64]).await?;
    Ok(message)
}

#[cfg(test)]
mod tests {
    use attestation::{AttestationType, Decode, provider::request_attestation};

    use super::*;

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
        let client_path = path.clone();
        let client = tokio::task::spawn_blocking(move || {
            let generator =
                AttestationGenerator::new(AttestationType::DcapTdx, Some(client_path)).unwrap();
            generator.generate_attestation([42; 64]).unwrap()
        });
        let (stream, _) = socket.listener.accept().await.unwrap();
        serve_connection(stream, AttestationGenerator::with_no_attestation()).await.unwrap();
        assert!(client.await.unwrap().attestation_evidence.is_none());
        drop(socket);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn invalid_requests_never_generate() {
        for input in [vec![1; 63], vec![1; 65]] {
            let (mut client, server) = UnixStream::pair().unwrap();
            let worker =
                tokio::spawn(serve_connection(server, AttestationGenerator::with_no_attestation()));
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
        let valid =
            ProviderResponse::Ok(AttestationExchangeMessage::without_attestation()).encode();
        let mut frames =
            vec![vec![], vec![0; 4], ((MAX_RESPONSE_SIZE + 1) as u32).to_be_bytes().to_vec()];
        for body in [
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
        let client =
            tokio::spawn(attestation_provider_client(path, AttestationVerifier::expect_none()));
        let (stream, _) = socket.listener.accept().await.unwrap();
        serve_connection(stream, AttestationGenerator::with_no_attestation()).await.unwrap();
        assert!(client.await.unwrap().unwrap().attestation_evidence.is_none());
    }

    #[tokio::test]
    async fn missing_request_eof_times_out() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(&[42; 64]).await.unwrap();
        let result = serve_connection(server, AttestationGenerator::with_no_attestation()).await;
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
