//! Integration test for the rustls-backed `SessionExporter`.
//!
//! Drives a rustls client + server handshake in-memory (no tokio, no
//! sockets), then asserts that both sides emit byte-identical output when
//! calling `export_keying_material` with the same (label, context, len).
//! This is the cryptographic property consumers rely on when binding
//! attestation to a TLS session.

#![cfg(feature = "rustls-exporter")]

use std::{io::Cursor, sync::Arc};

use attestation::session_exporter::{RustlsExporter, SessionExporter};
use rcgen::{CertificateParams, KeyPair};
use rustls::{
    ClientConfig,
    ClientConnection,
    DigitallySignedStruct,
    Error as RustlsError,
    ServerConfig,
    ServerConnection,
    SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
};

/// Permissive verifier — the test cert is self-signed and we don't care
/// about trust, only that the exporter produces matching bytes on both
/// sides.
#[derive(Debug)]
struct AcceptAnyCert;

impl ServerCertVerifier for AcceptAnyCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ED25519,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn generate_self_signed() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
    let key_pair = KeyPair::generate().unwrap();
    let params = CertificateParams::new(vec!["exporter-loopback.test".to_string()]).unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der = PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap();
    (cert_der, key_der)
}

fn transfer_client_to_server(client: &mut ClientConnection, server: &mut ServerConnection) {
    let mut buf = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut buf).unwrap();
    }
    if buf.is_empty() {
        return;
    }
    server.read_tls(&mut Cursor::new(buf)).unwrap();
    server.process_new_packets().unwrap();
}

fn transfer_server_to_client(server: &mut ServerConnection, client: &mut ClientConnection) {
    let mut buf = Vec::new();
    while server.wants_write() {
        server.write_tls(&mut buf).unwrap();
    }
    if buf.is_empty() {
        return;
    }
    client.read_tls(&mut Cursor::new(buf)).unwrap();
    client.process_new_packets().unwrap();
}

fn install_default_provider() {
    // rustls 0.23 requires a process-global CryptoProvider. Install once
    // across all integration tests in this binary; ignore the error if
    // another test already installed it.
    let _ = CryptoProvider::install_default(aws_lc_rs::default_provider());
}

fn drive_handshake() -> (ClientConnection, ServerConnection) {
    install_default_provider();
    let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();

    let (cert_der, key_der) = generate_self_signed();
    let server_config = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key_der)
        .unwrap();
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();

    let mut client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("exporter-loopback.test").unwrap(),
    )
    .unwrap();
    let mut server = ServerConnection::new(Arc::new(server_config)).unwrap();

    while client.is_handshaking() || server.is_handshaking() {
        transfer_client_to_server(&mut client, &mut server);
        transfer_server_to_client(&mut server, &mut client);
    }
    (client, server)
}

#[test]
fn client_and_server_observe_identical_exporter_bytes() {
    let (client, server) = drive_handshake();

    let label = b"attested-oss/v1/session";
    let mut client_out = [0u8; 32];
    let mut server_out = [0u8; 32];

    RustlsExporter::new(&client).export_keying_material(label, None, &mut client_out).unwrap();
    RustlsExporter::new(&server).export_keying_material(label, None, &mut server_out).unwrap();

    assert_eq!(
        client_out, server_out,
        "RFC 5705 exporter output must match on both ends of the session"
    );
    assert_ne!(
        client_out, [0u8; 32],
        "exporter output should not be all-zero (handshake not driven?)"
    );
}

#[test]
fn exporter_before_handshake_returns_handshake_incomplete() {
    install_default_provider();
    let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
    let client_config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCert))
        .with_no_client_auth();
    let client = ClientConnection::new(
        Arc::new(client_config),
        ServerName::try_from("exporter-loopback.test").unwrap(),
    )
    .unwrap();

    let mut out = [0u8; 32];
    let err = RustlsExporter::new(&client)
        .export_keying_material(b"label", None, &mut out)
        .expect_err("exporter must fail before handshake");
    assert!(
        matches!(err, attestation::session_exporter::ExportError::HandshakeIncomplete),
        "expected HandshakeIncomplete, got {err:?}"
    );
}

#[test]
fn distinct_labels_produce_distinct_exporter_output() {
    let (client, _server) = drive_handshake();

    let mut out_a = [0u8; 32];
    let mut out_b = [0u8; 32];
    RustlsExporter::new(&client).export_keying_material(b"label-a", None, &mut out_a).unwrap();
    RustlsExporter::new(&client).export_keying_material(b"label-b", None, &mut out_b).unwrap();

    assert_ne!(out_a, out_b, "distinct labels must yield distinct EKM bytes");
}
