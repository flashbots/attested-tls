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
        let mut stream = acceptor.accept(server_io).await.expect("nested accept should succeed");

        let mut req = [0_u8; 5];
        stream.read_exact(&mut req).await.expect("server read should succeed");
        assert_eq!(&req, b"hello");

        stream.write_all(b"world").await.expect("server write should succeed");
        stream.flush().await.expect("server flush should succeed");
    });

    let domain = ServerName::try_from("localhost").expect("domain should be valid");
    let mut stream =
        connector.connect(domain, client_io).await.expect("nested connect should succeed");

    stream.write_all(b"hello").await.expect("client write should succeed");
    stream.flush().await.expect("client flush should succeed");

    let mut resp = [0_u8; 5];
    stream.read_exact(&mut resp).await.expect("client read should succeed");
    assert_eq!(&resp, b"world");

    server.await.expect("server task should complete");
}

fn plain_tls_config_pair(provider: Arc<CryptoProvider>) -> (ServerConfig, ClientConfig) {
    let subject_name = "localhost";
    let key =
        KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("test key generation should succeed");
    let mut params = ra_tls::rcgen::CertificateParams::new(vec![subject_name.to_string()])
        .expect("test certificate params should be created");
    params
        .subject_alt_names
        .push(ra_tls::rcgen::SanType::DnsName(subject_name.try_into().expect("valid dns name")));
    let cert = params.self_signed(&key).expect("test certificate should be self-signed");
    let cert_der: CertificateDer<'static> = cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));

    let server = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("server config should support default protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .expect("server config should be created");

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).expect("client roots should trust server certificate");

    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client config should support default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();

    (server, client)
}

async fn attested_server_config(server_name: &str, provider: Arc<CryptoProvider>) -> ServerConfig {
    let resolver = AttestedCertificateResolver::new_with_provider(
        AttestationGenerator::new(AttestationType::DcapTdx, None)
            .expect("mock generator construction should succeed"),
        None,
        server_name.to_string(),
        vec![],
        provider.clone(),
    )
    .await
    .expect("resolver construction should succeed");

    ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("server config should support default protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver))
}

fn attested_client_config(provider: Arc<CryptoProvider>) -> ClientConfig {
    let verifier = AttestedCertificateVerifier::new_with_provider(
        None,
        AttestationVerifier::mock(),
        provider.clone(),
    )
    .expect("verifier construction should succeed");

    ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client config should support default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth()
}
