use std::{
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll, Waker},
};

use actix_http::Uri;
use actix_rt::net::{ActixStream, Ready};
use actix_service::Service;
use actix_tls::connect::{ConnectError, ConnectInfo};
use rustls::{
    ClientConfig,
    RootCertStore,
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf, duplex};

use super::*;
use crate::server::NestingTlsAcceptor;

// ActixDuplexStream ---------------------------------------------------

struct ActixDuplexStream(DuplexStream);

impl AsyncRead for ActixDuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ActixDuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl ActixStream for ActixDuplexStream {
    fn poll_read_ready(&self, _cx: &mut Context<'_>) -> Poll<std::io::Result<Ready>> {
        Poll::Ready(Ok(Ready::READABLE))
    }

    fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<std::io::Result<Ready>> {
        Poll::Ready(Ok(Ready::WRITABLE))
    }
}

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

#[actix_rt::test]
async fn call_maps_tcp_connect_errors_to_resolver_error() {
    let (_, outer_client) = config_pair();
    let (_, inner_client) = config_pair();

    let service =
        ActixNestingTlsConnectorService::new(Arc::new(outer_client), Arc::new(inner_client));

    let uri = Uri::from_static("https://localhost:443");
    let bad_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let req = ConnectInfo::with_addr(uri, bad_addr);

    let result = service.call(req).await;
    assert!(matches!(result, Err(ConnectError::Resolver(_))));
}

#[actix_rt::test]
async fn poll_ready_matches_underlying_tcp_connector() {
    let (_, outer_client) = config_pair();
    let (_, inner_client) = config_pair();

    let service =
        ActixNestingTlsConnectorService::new(Arc::new(outer_client), Arc::new(inner_client));

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    assert!(matches!(
        <ActixNestingTlsConnectorService as Service<ConnectInfo<Uri>>>::poll_ready(
            &service, &mut cx
        ),
        Poll::Ready(Ok(()))
    ));
}

#[actix_rt::test]
async fn actix_nesting_tls_stream_delegates_readiness_to_underlying_io() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

    let acceptor = NestingTlsAcceptor::new(Arc::new(outer_server), Arc::new(inner_server));
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));

    let (client_io, server_io) = duplex(16 * 1024);

    // prepare server
    let server_fut = async move { acceptor.accept(ActixDuplexStream(server_io)).await.unwrap() };

    // prepare client
    let client_fut = async move {
        let domain = ServerName::try_from("localhost").unwrap();
        connector.connect(domain, ActixDuplexStream(client_io)).await.unwrap()
    };

    // handshake
    let (_, client_stream) = tokio::join!(server_fut, client_fut);

    let actix_stream = ActixNestingTlsStream::from(client_stream);

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    // check that client r/w is ready
    assert!(matches!(
        <ActixNestingTlsStream<ActixDuplexStream> as ActixStream>::poll_read_ready(
            &actix_stream,
            &mut cx
        ),
        Poll::Ready(Ok(_))
    ));
    assert!(matches!(
        <ActixNestingTlsStream<ActixDuplexStream> as ActixStream>::poll_write_ready(
            &actix_stream,
            &mut cx
        ),
        Poll::Ready(Ok(_))
    ));
}
