//! Provides a test demonstrating using nested-tls and attested-tls together
use std::sync::Arc;

use attestation::{AttestationGenerator, AttestationType, AttestationVerifier};
use attested_tls::{AttestedCertificateResolver, AttestedCertificateVerifier};
use nested_tls::{client::NestingTlsConnector, server::NestingTlsAcceptor};
use ra_tls::rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{
    ClientConfig,
    RootCertStore,
    ServerConfig,
    crypto::{CryptoProvider, aws_lc_rs},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

#[tokio::test(flavor = "multi_thread")]
async fn nested_tls_uses_attested_tls_for_inner_session() {
    let provider: Arc<CryptoProvider> = aws_lc_rs::default_provider().into();
    let (outer_server, outer_client) = plain_tls_config_pair(provider.clone());
    let inner_server = attested_server_config("localhost", provider.clone()).await;
    let inner_client = attested_client_config(provider.clone());

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));

    let (client_io, server_io) = duplex(16 * 1024);

    let server = tokio::spawn(async move {
        let mut stream = acceptor.accept(server_io).await.unwrap();

        let mut req = [0_u8; 5];
        stream.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"hello");

        stream.write_all(b"world").await.unwrap();
        stream.flush().await.unwrap();
    });

    let domain = ServerName::try_from("localhost").unwrap();
    let mut stream = connector.connect(domain, client_io).await.unwrap();

    stream.write_all(b"hello").await.unwrap();
    stream.flush().await.unwrap();

    let mut resp = [0_u8; 5];
    stream.read_exact(&mut resp).await.unwrap();
    assert_eq!(&resp, b"world");

    server.await.unwrap();
}

/// Create vanilla TLS server and client config for outer session
fn plain_tls_config_pair(provider: Arc<CryptoProvider>) -> (ServerConfig, ClientConfig) {
    let subject_name = "localhost";
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = ra_tls::rcgen::CertificateParams::new(vec![subject_name.to_string()]).unwrap();
    params
        .subject_alt_names
        .push(ra_tls::rcgen::SanType::DnsName(subject_name.try_into().unwrap()));
    let cert = params.self_signed(&key).unwrap();
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();

    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();

    (server, client)
}

/// Create attested server TLS config with mock DCAP attestation and
/// self-signed certs
async fn attested_server_config(server_name: &str, provider: Arc<CryptoProvider>) -> ServerConfig {
    let resolver = AttestedCertificateResolver::new_with_provider(
        AttestationGenerator::new(AttestationType::DcapTdx, None).unwrap(),
        None,
        server_name.to_string(),
        vec![],
        provider.clone(),
    )
    .await
    .unwrap();

    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver))
}

/// Create client TLS config with attestation verification
fn attested_client_config(provider: Arc<CryptoProvider>) -> ClientConfig {
    let verifier = AttestedCertificateVerifier::new_with_provider(
        None,
        AttestationVerifier::mock(),
        provider.clone(),
    )
    .unwrap();

    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}
