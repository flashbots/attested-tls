//! TLS exporter keying material accessor trait (RFC 5705).
//!
//! Implementors wrap a rustls [`Connection`] (client or server side) and expose
//! its RFC 5705 exporter output via a backend-agnostic trait. Consumers feed
//! the exported bytes into higher-layer attestation bindings — typically by
//! hashing them into a DCAP quote's `user_report_data` so the quote is
//! cryptographically bound to the specific TLS session that produced the
//! originating request.
//!
//! The trait is generic over TLS library choice so higher-level code can be
//! tested with a deterministic fake without standing up a real handshake. A
//! rustls-backed implementation is provided behind the `rustls-exporter`
//! feature.
//!
//! [`Connection`]: https://docs.rs/rustls/latest/rustls/enum.Connection.html

use thiserror::Error;

/// Errors from a keying-material export attempt.
#[derive(Debug, Error)]
pub enum ExportError {
    /// The session cannot yet export — typically the handshake is incomplete.
    #[error("session is not ready to export keying material (handshake incomplete)")]
    HandshakeIncomplete,

    /// The underlying TLS library refused the export with a library-specific
    /// error. The wrapped string is the library's debug representation.
    #[error("underlying TLS error: {0}")]
    Tls(String),
}

/// Accessor for RFC 5705 TLS exporter keying material.
///
/// One implementation wraps a real rustls session (behind the `rustls-exporter`
/// feature); tests supply deterministic fakes.
pub trait SessionExporter {
    /// Fill `out` with `out.len()` bytes of RFC 5705 exporter keying material,
    /// derived from the session's negotiated master secret and the caller-
    /// supplied `(label, context)` pair.
    ///
    /// Both sides of a TLS session that call this with the same `(label,
    /// context, out.len())` observe byte-identical output. This is the
    /// cryptographic property consumers rely on when using the exporter as a
    /// channel-binding input.
    ///
    /// # Errors
    ///
    /// - [`ExportError::HandshakeIncomplete`] if the session hasn't finished
    ///   its handshake yet.
    /// - [`ExportError::Tls`] for any library-level failure.
    fn export_keying_material(
        &self,
        label: &[u8],
        context: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<(), ExportError>;
}

#[cfg(feature = "rustls-exporter")]
mod rustls_impl {
    use super::{ExportError, SessionExporter};
    use rustls::SideData;

    /// Wraps a reference to a rustls connection (client or server) and
    /// exposes its exporter via the [`SessionExporter`] trait.
    ///
    /// Both `rustls::ClientConnection` and `rustls::ServerConnection`
    /// deref/deref-mut to `ConnectionCommon<D>`, where `D` implements
    /// [`SideData`]. This wrapper is generic over `D` so the same adapter
    /// works on either side of a session.
    pub struct RustlsExporter<'a, D: SideData> {
        conn: &'a rustls::ConnectionCommon<D>,
    }

    impl<'a, D: SideData> RustlsExporter<'a, D> {
        /// Construct a new exporter bound to `conn`.
        pub fn new(conn: &'a rustls::ConnectionCommon<D>) -> Self {
            Self { conn }
        }
    }

    impl<D: SideData> SessionExporter for RustlsExporter<'_, D> {
        fn export_keying_material(
            &self,
            label: &[u8],
            context: Option<&[u8]>,
            out: &mut [u8],
        ) -> Result<(), ExportError> {
            // `rustls::ConnectionCommon::export_keying_material` fills the
            // provided buffer and returns a borrow of it; we discard the
            // borrow since callers already own `out`.
            self.conn
                .export_keying_material(out, label, context)
                .map(|_| ())
                .map_err(|e| match e {
                    rustls::Error::HandshakeNotComplete => ExportError::HandshakeIncomplete,
                    other => ExportError::Tls(format!("{other:?}")),
                })
        }
    }
}

#[cfg(feature = "rustls-exporter")]
pub use rustls_impl::RustlsExporter;
