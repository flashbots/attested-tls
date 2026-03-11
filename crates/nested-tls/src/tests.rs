use std::{
    panic::AssertUnwindSafe,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Waker},
};

use rustls::{
    ClientConfig,
    RootCertStore,
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

use crate::{client::NestingTlsConnector, server::NestingTlsAcceptor};

// helpers -------------------------------------------------------------

static PROVIDER: OnceLock<()> = OnceLock::new();

fn install_crypto_provider() {
    PROVIDER.get_or_init(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

fn config_pair() -> (ServerConfig, ClientConfig) {
    install_crypto_provider();

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

// tests ---------------------------------------------------------------

#[tokio::test]
async fn establishes_end_to_end_nested_tls_connection() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

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

#[tokio::test]
async fn fails_when_outer_handshake_domain_does_not_match() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));

    let (client_io, server_io) = duplex(16 * 1024);
    let server = tokio::spawn(async move { acceptor.accept(server_io).await });

    let wrong_domain = ServerName::try_from("not-localhost.example").unwrap();
    let client_result = connector.connect(wrong_domain, client_io).await;
    assert!(client_result.is_err());

    let server_result = server.await.unwrap();
    assert!(server_result.is_err());
}

#[tokio::test]
async fn fails_when_inner_handshake_cert_validation_fails() {
    let (outer_server, outer_client) = config_pair();

    let (inner_server, _) = config_pair();
    let (_, different_inner_client) = config_pair();

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector =
        NestingTlsConnector::new(Arc::new(outer_client), Arc::new(different_inner_client));

    let (client_io, server_io) = duplex(16 * 1024);
    let server = tokio::spawn(async move { acceptor.accept(server_io).await });

    let domain = ServerName::try_from("localhost").unwrap();
    let client_result = connector.connect(domain, client_io).await;
    assert!(client_result.is_err());

    let server_result = server.await.unwrap();
    assert!(server_result.is_err());
}

#[tokio::test]
async fn server_accept_fails_on_non_tls_bytes_then_eof() {
    let (outer_server, _) = config_pair();
    let (inner_server, _) = config_pair();

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let (mut client_io, server_io) = duplex(128);

    let server = tokio::spawn(async move { acceptor.accept(server_io).await });

    client_io.write_all(b"this is not tls").await.unwrap();
    client_io.shutdown().await.unwrap();

    let server_result = server.await.unwrap();
    assert!(server_result.is_err());
}

#[tokio::test]
async fn handles_many_concurrent_nested_tls_connections() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));

    let num_connections = 1024_usize;
    let mut tasks = Vec::with_capacity(num_connections);

    for i in 0..num_connections {
        let acceptor = acceptor.clone();
        let connector = connector.clone();

        tasks.push(tokio::spawn(async move {
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

            i
        }));
    }

    for task in tasks {
        task.await.unwrap();
    }
}

#[tokio::test]
async fn client_connect_future_panics_if_polled_after_completion() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));

    let (client_io, server_io) = duplex(16 * 1024);
    let server = tokio::spawn(async move { acceptor.accept(server_io).await.unwrap() });

    let domain = ServerName::try_from("localhost").unwrap();
    let mut fut = Box::pin(connector.connect(domain, client_io));
    let _stream = (&mut fut).await.unwrap();
    let _server_stream = server.await.unwrap();

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let repoll = std::panic::catch_unwind(AssertUnwindSafe(|| Pin::as_mut(&mut fut).poll(&mut cx)));
    assert!(repoll.is_err());
}

#[tokio::test]
async fn server_accept_future_panics_if_polled_after_completion() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));

    let (client_io, server_io) = duplex(16 * 1024);
    let domain = ServerName::try_from("localhost").unwrap();

    let client = tokio::spawn(async move { connector.connect(domain, client_io).await.unwrap() });

    let mut fut = Box::pin(acceptor.accept(server_io));
    let _stream = (&mut fut).await.unwrap();
    let _client_stream = client.await.unwrap();

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let repoll = std::panic::catch_unwind(AssertUnwindSafe(|| Pin::as_mut(&mut fut).poll(&mut cx)));
    assert!(repoll.is_err());
}
