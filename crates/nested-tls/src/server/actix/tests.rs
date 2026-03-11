use std::{sync::OnceLock, task::Waker};

use rustls::{
    ClientConfig,
    RootCertStore,
    ServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio::io::{DuplexStream, ReadBuf, duplex};

use super::*;
use crate::client::NestingTlsConnector;

// PendingIo -----------------------------------------------------------

#[derive(Default)]
struct PendingIo;

impl AsyncRead for PendingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl ActixStream for PendingIo {
    fn poll_read_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<Ready>> {
        Poll::Pending
    }

    fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<Ready>> {
        Poll::Pending
    }
}

// ActixDuplexStream ---------------------------------------------------

struct ActixDuplexStream(DuplexStream);

impl AsyncRead for ActixDuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for ActixDuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl ActixStream for ActixDuplexStream {
    fn poll_read_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<Ready>> {
        Poll::Ready(Ok(Ready::READABLE))
    }

    fn poll_write_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<Ready>> {
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

fn server_config() -> ServerConfig {
    install_crypto_provider();

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key_der)
        .unwrap()
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

// tests ===============================================================

#[actix_rt::test]
async fn set_handshake_timeout_propagates_to_service() {
    let mut acceptor = ActixNestingTlsAcceptor::new(server_config(), server_config());
    let timeout = Duration::from_millis(42);

    acceptor.set_handshake_timeout(timeout);
    let service =
        <ActixNestingTlsAcceptor as ServiceFactory<PendingIo>>::new_service(&acceptor, None)
            .await
            .unwrap();

    assert_eq!(service.config.handshake_timeout, timeout);
}

#[actix_rt::test]
async fn nested_tls_handshake_times_out_when_stream_never_progresses() {
    let mut acceptor = ActixNestingTlsAcceptor::new(server_config(), server_config());
    acceptor.set_handshake_timeout(Duration::from_millis(100));
    let service =
        <ActixNestingTlsAcceptor as ServiceFactory<PendingIo>>::new_service(&acceptor, None)
            .await
            .unwrap();

    let result = service.call(PendingIo).await;
    assert!(matches!(result, Err(TlsError::Timeout)));
}

#[actix_rt::test]
async fn nested_tls_handshake_returns_timeout_when_deadline_is_expired() {
    let mut acceptor = ActixNestingTlsAcceptor::new(server_config(), server_config());
    acceptor.set_handshake_timeout(Duration::from_millis(0));
    let service =
        <ActixNestingTlsAcceptor as ServiceFactory<PendingIo>>::new_service(&acceptor, None)
            .await
            .unwrap();

    let result = service.call(PendingIo).await;
    assert!(matches!(result, Err(TlsError::Timeout)));
}

#[actix_rt::test]
async fn poll_ready_reflects_connection_counter_capacity() {
    let service = ActixNestingTlsAcceptorService {
        acceptor: (Arc::new(server_config()), Arc::new(server_config())).into(),
        config: ActixNestingTlsAcceptorConfig { handshake_timeout: Duration::from_millis(100) },
        conns: Counter::new(1),
    };

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Ready(Ok(()))
    ));
    let fut = service.call(PendingIo);
    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Pending
    ));
    drop(fut);
    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Ready(Ok(()))
    ));
}

#[actix_rt::test]
async fn nested_tls_handshake_succeeds_before_generous_timeout() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

    let mut acceptor = ActixNestingTlsAcceptor::new(outer_server, inner_server);
    acceptor.set_handshake_timeout(Duration::from_secs(100));
    let service = <ActixNestingTlsAcceptor as ServiceFactory<ActixDuplexStream>>::new_service(
        &acceptor, None,
    )
    .await
    .unwrap();

    let (client_io, server_io) = duplex(16 * 1024);

    let server_fut = async {
        <ActixNestingTlsAcceptorService as Service<ActixDuplexStream>>::call(
            &service,
            ActixDuplexStream(server_io),
        )
        .await
    };

    let client_fut = async move {
        let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));
        let domain = ServerName::try_from("localhost").unwrap();
        connector.connect(domain, client_io).await
    };

    let (server_result, client_result) = tokio::join!(server_fut, client_fut);
    assert!(client_result.is_ok());
    assert!(server_result.is_ok());
}

#[actix_rt::test]
async fn poll_ready_tracks_multiple_in_flight_connections() {
    let service = ActixNestingTlsAcceptorService {
        acceptor: (Arc::new(server_config()), Arc::new(server_config())).into(),
        config: ActixNestingTlsAcceptorConfig { handshake_timeout: Duration::from_millis(100) },
        conns: Counter::new(2),
    };

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Ready(Ok(()))
    ));

    let fut1 = service.call(PendingIo);
    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Ready(Ok(()))
    ));

    let fut2 = service.call(PendingIo);
    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Pending
    ));

    drop(fut1);
    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Ready(Ok(()))
    ));

    drop(fut2);
    assert!(matches!(
        <ActixNestingTlsAcceptorService as Service<PendingIo>>::poll_ready(&service, &mut cx),
        Poll::Ready(Ok(()))
    ));
}

#[actix_rt::test]
async fn call_returns_error_when_max_connections_exceeded() {
    let service = ActixNestingTlsAcceptorService {
        acceptor: (Arc::new(server_config()), Arc::new(server_config())).into(),
        config: ActixNestingTlsAcceptorConfig { handshake_timeout: Duration::from_millis(100) },
        conns: Counter::new(1),
    };

    let in_flight = service.call(PendingIo);

    match service.call(PendingIo).await {
        Err(TlsError::Tls(err)) => {
            assert_eq!(err.kind(), io::ErrorKind::Other);
            assert!(err.to_string().contains("maximum concurrent nested TLS connections"));
        }
        _ => panic!("expected capacity overflow to return TlsError::Tls"),
    }

    if let Err(err) = in_flight.await &&
        err.to_string().contains("maximum concurrent nested TLS connections")
    {
        panic!("unexpected error: {err}");
    }
}

#[actix_rt::test]
async fn actix_nesting_tls_stream_delegates_readiness_to_underlying_io() {
    let (outer_server, outer_client) = config_pair();
    let (inner_server, inner_client) = config_pair();

    let mut acceptor = ActixNestingTlsAcceptor::new(outer_server, inner_server);
    acceptor.set_handshake_timeout(Duration::from_secs(100));
    let service = <ActixNestingTlsAcceptor as ServiceFactory<ActixDuplexStream>>::new_service(
        &acceptor, None,
    )
    .await
    .unwrap();
    let connector = NestingTlsConnector::new(Arc::new(outer_client), Arc::new(inner_client));

    let (client_io, server_io) = duplex(16 * 1024);

    // prepare server
    let server_fut = async {
        <ActixNestingTlsAcceptorService as Service<ActixDuplexStream>>::call(
            &service,
            ActixDuplexStream(server_io),
        )
        .await
        .unwrap()
    };

    // prepare client
    let client_fut = async move {
        let domain = ServerName::try_from("localhost").unwrap();
        connector.connect(domain, client_io).await.unwrap()
    };

    // handshake
    let (server_stream, _) = tokio::join!(server_fut, client_fut);

    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);

    // check that server r/w is ready
    assert!(matches!(
        <ActixNestingTlsStream<ActixDuplexStream> as ActixStream>::poll_read_ready(
            &server_stream,
            &mut cx
        ),
        Poll::Ready(Ok(_))
    ));
    assert!(matches!(
        <ActixNestingTlsStream<ActixDuplexStream> as ActixStream>::poll_write_ready(
            &server_stream,
            &mut cx
        ),
        Poll::Ready(Ok(_))
    ));
}
