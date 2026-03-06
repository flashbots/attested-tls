use std::sync::{Arc, OnceLock};

use rustls::{
    ClientConfig,
    RootCertStore,
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use crate::{client::NestingTlsConnector, server::NestingTlsAcceptor};

fn ensure_crypto_provider_installed() {
    static PROVIDER: OnceLock<()> = OnceLock::new();
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn test_tls_config_pair() -> (ServerConfig, ClientConfig) {
    ensure_crypto_provider_installed();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_der: CertificateDer<'static> = cert.cert.der().clone();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();

    let mut roots = RootCertStore::empty();
    roots.add(cert_der).unwrap();

    let client = ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();

    (server, client)
}

#[tokio::test]
async fn establishes_end_to_end_nested_tls_connection() {
    let (outer_server, outer_client) = test_tls_config_pair();
    let (inner_server, inner_client) = test_tls_config_pair();

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
