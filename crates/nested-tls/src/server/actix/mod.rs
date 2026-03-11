#![cfg(feature = "actix")]

// ---------------------------------------------------------------------

use std::{
    convert::Infallible,
    io::{self, IoSlice},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use actix_rt::{
    net::{ActixStream, Ready},
    time::{Sleep, sleep},
};
use actix_service::{Service, ServiceFactory};
use actix_tls::accept::TlsError;
use actix_utils::{
    counter::{Counter, CounterGuard},
    future::{Ready as FutReady, ready},
};
use pin_project_lite::pin_project;
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::server::{NestingTlsAccept, NestingTlsAcceptor, NestingTlsStream};

// ---------------------------------------------------------------------

#[cfg(test)]
mod tests;

// ---------------------------------------------------------------------

static ACTIX_MAX_CONN: AtomicUsize = AtomicUsize::new(256);

const ACTIX_DEFAULT_TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

thread_local! {
    static ACTIX_MAX_CONN_COUNTER: Counter = Counter::new(ACTIX_MAX_CONN.load(Ordering::Relaxed));
}

// ActixNestingTlsStream -----------------------------------------------

// A wrapper around [`crate::server::NestingTlsStream`] that implements
// `actix_rt::net::ActixStream` trait.
pub struct ActixNestingTlsStream<IO>(pub NestingTlsStream<IO>);

impl_more::impl_from!(<IO> in NestingTlsStream<IO> => ActixNestingTlsStream<IO>);
impl_more::impl_deref_and_mut!(<IO> in ActixNestingTlsStream<IO> => NestingTlsStream<IO> );

impl<IO: ActixStream> AsyncRead for ActixNestingTlsStream<IO> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_read(cx, buf)
    }
}

impl<IO: ActixStream> AsyncWrite for ActixNestingTlsStream<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self.get_mut()).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut **self.get_mut()).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut **self.get_mut()).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        (**self).is_write_vectored()
    }
}

impl<IO: ActixStream> ActixStream for ActixNestingTlsStream<IO> {
    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<Ready>> {
        IO::poll_read_ready((**self).get_ref().0.get_ref().0, cx)
    }

    fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<Ready>> {
        IO::poll_write_ready((**self).get_ref().0.get_ref().0, cx)
    }
}

// ActixNestingTlsAcceptor ---------------------------------------------

/// Actix service factory that accepts connections using nested TLS.
#[derive(Clone)]
pub struct ActixNestingTlsAcceptor {
    config: ActixNestingTlsAcceptorConfig,

    outer: Arc<ServerConfig>,
    inner: Arc<ServerConfig>,
}

impl ActixNestingTlsAcceptor {
    /// Creates an Actix nested TLS acceptor from outer and inner server
    /// configs.
    pub fn new(outer: ServerConfig, inner: ServerConfig) -> Self {
        Self {
            outer: Arc::new(outer),
            inner: Arc::new(inner),

            config: ActixNestingTlsAcceptorConfig {
                handshake_timeout: ACTIX_DEFAULT_TLS_HANDSHAKE_TIMEOUT,
            },
        }
    }

    /// Sets the handshake timeout used by services produced from this
    /// factory.
    pub fn set_handshake_timeout(&mut self, handshake_timeout: Duration) -> &mut Self {
        self.config.handshake_timeout = handshake_timeout;
        self
    }
}

impl<IO: ActixStream> ServiceFactory<IO> for ActixNestingTlsAcceptor {
    type Response = ActixNestingTlsStream<IO>;
    type Error = TlsError<io::Error, Infallible>;
    type Config = Option<ActixNestingTlsAcceptorConfig>;
    type Service = ActixNestingTlsAcceptorService;
    type InitError = ();
    type Future = FutReady<Result<Self::Service, Self::InitError>>;

    fn new_service(&self, config: Option<ActixNestingTlsAcceptorConfig>) -> Self::Future {
        let res = ACTIX_MAX_CONN_COUNTER.with(|conns| {
            Ok(ActixNestingTlsAcceptorService {
                acceptor: (self.outer.clone(), self.inner.clone()).into(),
                config: config.unwrap_or(self.config.clone()),
                conns: conns.clone(),
            })
        });

        ready(res)
    }
}

// ActixNestingTlsAcceptorConfig ---------------------------------------

/// Configuration of actix service factory accepting connections using
/// nested TLS.
#[derive(Clone)]
pub struct ActixNestingTlsAcceptorConfig {
    handshake_timeout: Duration,
}

impl Default for ActixNestingTlsAcceptorConfig {
    fn default() -> Self {
        Self { handshake_timeout: ACTIX_DEFAULT_TLS_HANDSHAKE_TIMEOUT }
    }
}

// ActixNestingTlsAcceptorService --------------------------------------

/// Per-worker Actix service that performs nested TLS handshakes on accepted
/// IO.
pub struct ActixNestingTlsAcceptorService {
    config: ActixNestingTlsAcceptorConfig,

    acceptor: NestingTlsAcceptor,
    conns: Counter,
}

impl<IO: ActixStream> Service<IO> for ActixNestingTlsAcceptorService {
    type Response = ActixNestingTlsStream<IO>;
    type Error = TlsError<io::Error, Infallible>;
    type Future = ActixNestingTlsAcceptFut<IO>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.conns.available(cx) { Poll::Ready(Ok(())) } else { Poll::Pending }
    }

    fn call(&self, req: IO) -> Self::Future {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);

        if self.conns.available(&mut cx) {
            ActixNestingTlsAcceptFut {
                fut: Some(self.acceptor.accept(req)),
                timeout: Some(sleep(self.config.handshake_timeout)),
                error: None,
                _guard: Some(self.conns.get()),
            }
        } else {
            ActixNestingTlsAcceptFut {
                fut: None,
                timeout: None,
                error: Some(io::Error::other("maximum concurrent nested TLS connections exceeded")),
                _guard: None,
            }
        }
    }
}

// ActixNestingTlsAcceptFut --------------------------------------------

pin_project! {
    /// Future returned by [`ActixNestingTlsAcceptorService`] when accepting
    /// a single IO stream with nested TLS.
    pub struct ActixNestingTlsAcceptFut<IO: ActixStream> {
        #[pin]
        fut: Option<NestingTlsAccept<IO>>,
        #[pin]
        timeout: Option<Sleep>,
        error: Option<io::Error>,
        _guard: Option<CounterGuard>,
    }
}

impl<IO: ActixStream> Future for ActixNestingTlsAcceptFut<IO> {
    type Output = Result<ActixNestingTlsStream<IO>, TlsError<io::Error, Infallible>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        if let Some(err) = this.error.take() {
            return Poll::Ready(Err(TlsError::Tls(err)));
        }

        let Some(fut) = this.fut.as_pin_mut() else {
            panic!("unexpected polling state: missing handshake future")
        };
        let Some(timeout) = this.timeout.as_pin_mut() else {
            panic!("unexpected polling state: missing timeout future")
        };

        match fut.poll(cx) {
            Poll::Ready(Ok(stream)) => Poll::Ready(Ok(ActixNestingTlsStream(stream))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(TlsError::Tls(err))),
            Poll::Pending => timeout.poll(cx).map(|_| Err(TlsError::Timeout)),
        }
    }
}
