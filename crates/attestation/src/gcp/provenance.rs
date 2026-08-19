//! GCP provenance check
use std::{
    collections::HashMap,
    io::Read,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use dcap_qvl::{intel, quote::Quote};
use serde_json::Value;
use thiserror::Error;

/// Public registry of GCP Confidential VM TDX PPIDs
const GCP_PROVENANCE_REGISTRY_URL: &str =
    "https://storage.googleapis.com/confidential-host-registry";

/// Maximum size in bytes of GCP provenance documents
const GCP_PROVENANCE_DOCUMENT_MAX_BYTES: u64 = 16 * 1024;
/// PPIDs in Intel PCK certificates are 128-bit values
const GCP_PPID_BYTES: usize = 16;
/// How long a cached PPID remains trusted before revalidation
const GCP_PROVENANCE_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// Overall timeout for fetching a provenance document (covers DNS, connect,
/// TLS handshake and read)
/// This matches the timeout in Google's Go provenance checker tool
const GCP_PROVENANCE_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// Checks PPIDs extracted from DCAP quotes against Google's public bucket,
/// to establish whether this is a GCP machine
#[derive(Clone, Debug)]
pub(crate) struct GcpProvenanceChecker {
    /// Cached entries with retrieval timestamp
    known_gcp_ppids: Arc<RwLock<HashMap<[u8; GCP_PPID_BYTES], Instant>>>,
}

impl GcpProvenanceChecker {
    pub(crate) fn new() -> Self {
        Self { known_gcp_ppids: Default::default() }
    }

    /// Given a DCAP TDX quote, check if the associated PPID has a
    /// 'provenance document' from GCP
    ///
    /// If a tokio runtime is available the blocking check is offloaded to
    /// its blocking pool; otherwise it runs inline on the current thread
    pub(crate) async fn verify_provenance(&self, quote: Quote) -> Result<(), GcpProvenanceError> {
        self.verify_provenance_with_registry_url(quote, GCP_PROVENANCE_REGISTRY_URL.to_string())
            .await
    }

    async fn verify_provenance_with_registry_url(
        &self,
        quote: Quote,
        registry_url: String,
    ) -> Result<(), GcpProvenanceError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let checker = self.clone();
                handle
                    .spawn_blocking(move || {
                        checker.verify_provenance_with_registry_url_blocking_at(
                            &quote,
                            &registry_url,
                            Instant::now(),
                        )
                    })
                    .await
                    .map_err(|err| GcpProvenanceError::TaskJoin(err.to_string()))?
            }
            Err(_) => self.verify_provenance_with_registry_url_blocking_at(
                &quote,
                &registry_url,
                Instant::now(),
            ),
        }
    }

    /// Given a DCAP TDX quote, check if the associated PPID has a
    /// 'provenance document' from GCP
    ///
    /// On a multi-threaded tokio runtime, mark the check as blocking so the
    /// runtime can keep scheduling other tasks on another worker
    pub(crate) fn verify_provenance_sync(&self, quote: &Quote) -> Result<(), GcpProvenanceError> {
        self.verify_provenance_with_registry_url_sync_at(
            quote,
            GCP_PROVENANCE_REGISTRY_URL,
            Instant::now(),
        )
    }

    fn verify_provenance_with_registry_url_sync_at(
        &self,
        quote: &Quote,
        registry_url: &str,
        now: Instant,
    ) -> Result<(), GcpProvenanceError> {
        let verify =
            || self.verify_provenance_with_registry_url_blocking_at(quote, registry_url, now);

        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ) =>
            {
                tokio::task::block_in_place(verify)
            }
            _ => verify(),
        }
    }

    fn verify_provenance_with_registry_url_blocking_at(
        &self,
        quote: &Quote,
        registry_url: &str,
        now: Instant,
    ) -> Result<(), GcpProvenanceError> {
        let ppid = extract_ppid_from_quote(quote)?;
        let stale_entry = {
            let known_gcp_ppids = self
                .known_gcp_ppids
                .read()
                .map_err(|err| GcpProvenanceError::CacheLock(err.to_string()))?;
            match known_gcp_ppids.get(&ppid).copied() {
                Some(stored_at) if is_cache_entry_fresh(stored_at, now) => return Ok(()),
                stale_entry => stale_entry,
            }
        };

        if let Some(stale_entry) = stale_entry {
            let mut known_gcp_ppids = self
                .known_gcp_ppids
                .write()
                .map_err(|err| GcpProvenanceError::CacheLock(err.to_string()))?;
            if known_gcp_ppids.get(&ppid) == Some(&stale_entry) {
                known_gcp_ppids.remove(&ppid);
            }
        }

        let provenance_url =
            format!("{}/{}", registry_url.trim_end_matches('/'), hex::encode(ppid));
        let document = fetch_provenance_document(&provenance_url)?;
        validate_provenance_document(&document)?;

        let fetched_at = Instant::now();
        self.known_gcp_ppids
            .write()
            .map_err(|err| GcpProvenanceError::CacheLock(err.to_string()))?
            .insert(ppid, fetched_at);

        Ok(())
    }
}

fn is_cache_entry_fresh(stored_at: Instant, now: Instant) -> bool {
    now.saturating_duration_since(stored_at) <= GCP_PROVENANCE_CACHE_TTL
}

/// Given a TDX quote, extract the PPID from PCK certificate
fn extract_ppid_from_quote(quote: &Quote) -> Result<[u8; GCP_PPID_BYTES], GcpProvenanceError> {
    let cert_chain = intel::extract_cert_chain(quote)
        .map_err(|err| GcpProvenanceError::PpidExtraction(err.to_string()))?;
    let leaf = cert_chain.first().ok_or(GcpProvenanceError::NoPckCertificate)?;
    let extension = intel::parse_pck_extension(leaf)
        .map_err(|err| GcpProvenanceError::PpidExtraction(err.to_string()))?;

    if extension.ppid.is_empty() {
        return Err(GcpProvenanceError::EmptyPpid);
    }
    extension
        .ppid
        .try_into()
        .map_err(|ppid: Vec<u8>| GcpProvenanceError::InvalidPpidLength(ppid.len()))
}

/// Synchronously attempt to fetch provenance document
fn fetch_provenance_document(url: &str) -> Result<String, GcpProvenanceError> {
    let agent = ureq::AgentBuilder::new().timeout(GCP_PROVENANCE_FETCH_TIMEOUT).build();
    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::Status(status, _)) => {
            return Err(GcpProvenanceError::RegistryFetch(format!("HTTP status {status}")));
        }
        Err(err) => {
            tracing::warn!(url, error = %err, "GCP provenance registry unavailable");
            return Err(GcpProvenanceError::RegistryUnavailable(err.to_string()));
        }
    };

    if response.status() != 200 {
        return Err(GcpProvenanceError::RegistryFetch(format!(
            "unexpected HTTP status {}",
            response.status()
        )));
    }

    let mut limited_reader = response.into_reader().take(GCP_PROVENANCE_DOCUMENT_MAX_BYTES + 1);
    let mut document = String::new();
    limited_reader
        .read_to_string(&mut document)
        .map_err(|err| GcpProvenanceError::RegistryFetch(err.to_string()))?;

    if document.len() as u64 > GCP_PROVENANCE_DOCUMENT_MAX_BYTES {
        return Err(GcpProvenanceError::DocumentTooLarge);
    }

    Ok(document)
}

/// Basic checks that the response looks like a provenance document
fn validate_provenance_document(document: &str) -> Result<(), GcpProvenanceError> {
    let value: Value = serde_json::from_str(document)?;
    let object = value.as_object().ok_or(GcpProvenanceError::InvalidDocument)?;

    let has_zone = object.get("zone").and_then(Value::as_str).is_some_and(|zone| !zone.is_empty());
    let has_timestamp = object.get("timestamp").is_some_and(|timestamp| match timestamp {
        Value::String(timestamp) => !timestamp.is_empty(),
        Value::Number(_) => true,
        _ => false,
    });

    if has_zone && has_timestamp { Ok(()) } else { Err(GcpProvenanceError::InvalidDocument) }
}

#[derive(Error, Debug)]
pub enum GcpProvenanceError {
    #[error("quote parse: {0}")]
    Quote(String),
    #[error("PCK certificate chain is empty")]
    NoPckCertificate,
    #[error("PPID is empty")]
    EmptyPpid,
    #[error("PPID has invalid length: {0} bytes (expected 16)")]
    InvalidPpidLength(usize),
    #[error("PPID extraction: {0}")]
    PpidExtraction(String),
    #[error("registry fetch: {0}")]
    RegistryFetch(String),
    #[error("registry unavailable: {0}")]
    RegistryUnavailable(String),
    #[error("provenance document is invalid")]
    InvalidDocument,
    #[error("provenance document exceeds maximum size")]
    DocumentTooLarge,
    #[error("provenance document JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("provenance cache lock: {0}")]
    CacheLock(String),
    #[error("blocking task join: {0}")]
    TaskJoin(String),
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read as _, Write as _},
        net::SocketAddr,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    use super::*;
    use crate::dcap;

    const MOCK_PPID_HEX: &str = "d04ec06d4e6d92dc90d0ad3cf5ee2ddf";

    fn spawn_test_registry_server(
        status: u16,
        body: impl Into<String>,
    ) -> (SocketAddr, thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.into();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let bytes_read = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..bytes_read]).to_string();
            let status_text = if status == 200 { "OK" } else { "Not Found" };
            let response = format!(
                "HTTP/1.1 {status} {status_text}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });

        (addr, handle)
    }

    fn spawn_blocked_test_registry_server(
        body: impl Into<String>,
    ) -> (SocketAddr, mpsc::Receiver<()>, mpsc::Sender<()>, thread::JoinHandle<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let body = body.into();
        let (request_started_tx, request_started_rx) = mpsc::channel();
        let (send_response_tx, send_response_rx) = mpsc::channel();

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let bytes_read = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..bytes_read]).to_string();
            request_started_tx.send(()).unwrap();
            send_response_rx.recv().unwrap();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });

        (addr, request_started_rx, send_response_tx, handle)
    }

    #[test]
    fn extracts_ppid_from_mock_tdx_quote() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let ppid = extract_ppid_from_quote(&quote).unwrap();

        assert_eq!(hex::encode(ppid), MOCK_PPID_HEX);
    }

    #[test]
    fn extracts_ppid_from_fixture_dcap_quote() {
        let attestation = include_bytes!("../../test-assets/dcap-tdx-1766059550570652607");
        let quote = Quote::parse(attestation).unwrap();
        let ppid = extract_ppid_from_quote(&quote).unwrap();

        assert_eq!(ppid.len(), 16);
        assert!(!ppid.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn provenance_check_fetches_registry_document_for_ppid() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(
            200,
            r#"{"zone":"projects/test/zones/us-central1-a","timestamp":"2026-06-11T00:00:00Z"}"#,
        );

        GcpProvenanceChecker::new()
            .verify_provenance_with_registry_url_sync_at(
                &quote,
                &format!("http://{addr}"),
                Instant::now(),
            )
            .unwrap();

        let request = request_handle.join().unwrap();
        assert!(request.starts_with(&format!("GET /{MOCK_PPID_HEX} HTTP/1.1")));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn async_provenance_check_remains_cancellable() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_started, send_response, request_handle) =
            spawn_blocked_test_registry_server(
                r#"{"zone":"projects/test/zones/us-central1-a","timestamp":"2026-06-11T00:00:00Z"}"#,
            );
        let checker = GcpProvenanceChecker::new();

        let task = tokio::spawn(async move {
            checker.verify_provenance_with_registry_url(quote, format!("http://{addr}")).await
        });
        request_started.recv_timeout(Duration::from_secs(1)).unwrap();

        task.abort();
        let join_result = tokio::time::timeout(Duration::from_secs(1), task).await;
        send_response.send(()).unwrap();
        request_handle.join().unwrap();

        let join_error = join_result.expect("aborted verification remained blocked").unwrap_err();
        assert!(join_error.is_cancelled());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sync_provenance_check_runs_from_tokio_worker() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(
            200,
            r#"{"zone":"projects/test/zones/us-central1-a","timestamp":"2026-06-11T00:00:00Z"}"#,
        );

        GcpProvenanceChecker::new()
            .verify_provenance_with_registry_url_sync_at(
                &quote,
                &format!("http://{addr}"),
                Instant::now(),
            )
            .unwrap();

        let request = request_handle.join().unwrap();
        assert!(request.starts_with(&format!("GET /{MOCK_PPID_HEX} HTTP/1.1")));
    }

    #[test]
    fn provenance_check_caches_known_gcp_ppids() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(
            200,
            r#"{"zone":"projects/test/zones/us-central1-a","timestamp":"2026-06-11T00:00:00Z"}"#,
        );
        let checker = GcpProvenanceChecker::new();
        let registry_url = format!("http://{addr}");

        checker
            .verify_provenance_with_registry_url_sync_at(&quote, &registry_url, Instant::now())
            .unwrap();
        checker
            .verify_provenance_with_registry_url_sync_at(&quote, &registry_url, Instant::now())
            .unwrap();

        let request = request_handle.join().unwrap();
        assert!(request.starts_with(&format!("GET /{MOCK_PPID_HEX} HTTP/1.1")));
    }

    #[test]
    fn provenance_check_revalidates_stale_cached_ppids() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(
            200,
            r#"{"zone":"projects/test/zones/us-central1-a","timestamp":"2026-06-11T00:00:00Z"}"#,
        );
        let checker = GcpProvenanceChecker::new();
        let registry_url = format!("http://{addr}");
        let ppid = extract_ppid_from_quote(&quote).unwrap();
        let stale_at = Instant::now() - (GCP_PROVENANCE_CACHE_TTL + Duration::from_secs(1));

        checker.known_gcp_ppids.write().unwrap().insert(ppid, stale_at);

        checker
            .verify_provenance_with_registry_url_sync_at(&quote, &registry_url, Instant::now())
            .unwrap();

        let request = request_handle.join().unwrap();
        assert!(request.starts_with(&format!("GET /{MOCK_PPID_HEX} HTTP/1.1")));
    }

    #[test]
    fn provenance_check_fails_closed_on_registry_miss() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(404, "not found");

        let err = GcpProvenanceChecker::new()
            .verify_provenance_with_registry_url_sync_at(
                &quote,
                &format!("http://{addr}"),
                Instant::now(),
            )
            .unwrap_err();

        request_handle.join().unwrap();
        assert!(matches!(err, GcpProvenanceError::RegistryFetch(_)));
    }

    #[test]
    fn provenance_check_rejects_non_200_success_status() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(201, "created");

        let err = GcpProvenanceChecker::new()
            .verify_provenance_with_registry_url_sync_at(
                &quote,
                &format!("http://{addr}"),
                Instant::now(),
            )
            .unwrap_err();

        request_handle.join().unwrap();
        assert!(matches!(err, GcpProvenanceError::RegistryFetch(_)));
    }

    #[test]
    fn provenance_check_fails_closed_on_invalid_document() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(200, r#"{"zone":""}"#);

        let err = GcpProvenanceChecker::new()
            .verify_provenance_with_registry_url_sync_at(
                &quote,
                &format!("http://{addr}"),
                Instant::now(),
            )
            .unwrap_err();

        request_handle.join().unwrap();
        assert!(matches!(err, GcpProvenanceError::InvalidDocument));
    }

    #[test]
    fn provenance_check_fails_closed_on_oversized_document() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let oversized_body = "x".repeat((GCP_PROVENANCE_DOCUMENT_MAX_BYTES + 1) as usize);
        let (addr, request_handle) = spawn_test_registry_server(200, oversized_body);

        let err = GcpProvenanceChecker::new()
            .verify_provenance_with_registry_url_sync_at(
                &quote,
                &format!("http://{addr}"),
                Instant::now(),
            )
            .unwrap_err();

        request_handle.join().unwrap();
        assert!(matches!(err, GcpProvenanceError::DocumentTooLarge));
    }
}
