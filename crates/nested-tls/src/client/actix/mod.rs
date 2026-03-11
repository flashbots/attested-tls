#![cfg(feature = "actix")]

// ---------------------------------------------------------------------

use std::{
    fmt,
    future::Future,
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use actix_http::Uri;
use actix_rt::net::{ActixStream, Ready, TcpStream};
use actix_service::Service;
use actix_tls::connect::{ConnectError, ConnectInfo, Connection, ConnectorService};
use rustls::{ClientConfig, pki_types::ServerName};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::client::{NestingTlsConnector, NestingTlsStream};

// ---------------------------------------------------------------------

#[cfg(test)]
mod tests;

// ActixNestingTlsStream -----------------------------------------------

// A wrapper around [`crate::client::NestingTlsStream`] that implements
// `actix_rt::net::ActixStream` trait.
pub struct ActixNestingTlsStream<IO>(NestingTlsStream<IO>);

impl_more::impl_from!(<IO> in NestingTlsStream<IO> => ActixNestingTlsStream<IO>);
impl_more::impl_deref_and_mut!(<IO> in ActixNestingTlsStream<IO> => NestingTlsStream<IO> );

impl<IO: fmt::Debug> fmt::Debug for ActixNestingTlsStream<IO> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NestingTlsConnection").finish()
    }
}

impl<IO: ActixStream> AsyncRead for ActixNestingTlsStream<IO> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
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

// NestingTlsConnectorService ------------------------------------------

/// Connector service for actix clients that establishes nested TLS.
#[derive(Clone)]
pub struct ActixNestingTlsConnectorService {
    connector: NestingTlsConnector,
    tcp: ConnectorService,
}

impl ActixNestingTlsConnectorService {
    /// Builds a connector service from outer and inner client TLS configs.
    pub fn new(outer: Arc<ClientConfig>, inner: Arc<ClientConfig>) -> Self {
        Self { tcp: ConnectorService::default(), connector: NestingTlsConnector::new(outer, inner) }
    }
}

impl Service<ConnectInfo<Uri>> for ActixNestingTlsConnectorService {
    type Response = Connection<Uri, ActixNestingTlsStream<TcpStream>>;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + 'static>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        <ConnectorService as Service<ConnectInfo<Uri>>>::poll_ready(&self.tcp, cx)
    }

    fn call(&self, req: ConnectInfo<Uri>) -> Self::Future {
        let host = req.hostname().to_string();

        let tcp = <ConnectorService as Service<ConnectInfo<Uri>>>::call(&self.tcp, req);
        let connector = self.connector.clone();

        Box::pin(async move {
            let conn = tcp.await.map_err(|err| ConnectError::Resolver(Box::new(err)))?;
            let (tcp_stream, uri) = conn.into_parts();

            let domain = ServerName::try_from(host).map_err(
                // ServerName::try_from only returns InvalidDnsNameError
                |_| ConnectError::Unresolved,
            )?;

            let nesting_tls_stream =
                connector.connect(domain, tcp_stream).await.map_err(ConnectError::Io)?;

            Ok(Connection::new(uri, ActixNestingTlsStream(nesting_tls_stream)))
        })
    }
}
