use std::{
    collections::HashSet,
    io::Read,
    sync::{Arc, RwLock},
    time::Duration,
};

use dcap_qvl::{intel, quote::Quote};
use serde_json::Value;
use thiserror::Error;

/// Public registry of GCP Confidential VM TDX PPIDs
const GCP_PROVENANCE_REGISTRY_URL: &str =
    "https://storage.googleapis.com/confidential-host-registry";

/// Maximum size in bytes of GCP provenance documents
const GCP_PROVENANCE_DOCUMENT_MAX_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug)]
pub(crate) struct GcpProvenanceChecker {
    known_gcp_ppids: Arc<RwLock<HashSet<Vec<u8>>>>,
}

impl GcpProvenanceChecker {
    pub(crate) fn new() -> Self {
        Self { known_gcp_ppids: Default::default() }
    }

    /// Given a DCAP TDX quote, check if the associated PPID has a
    /// 'provenance document' from GCP
    pub(crate) async fn verify_provenance(&self, quote: Quote) -> Result<(), GcpProvenanceError> {
        let checker = self.clone();
        tokio::task::spawn_blocking(move || {
            checker.verify_provenance_with_registry_url_sync(&quote, GCP_PROVENANCE_REGISTRY_URL)
        })
        .await
        .map_err(|err| GcpProvenanceError::TaskJoin(err.to_string()))?
    }

    /// Given a DCAP TDX quote, check if the associated PPID has a
    /// 'provenance document' from GCP
    pub(crate) fn verify_provenance_sync(&self, quote: &Quote) -> Result<(), GcpProvenanceError> {
        self.verify_provenance_with_registry_url_sync(quote, GCP_PROVENANCE_REGISTRY_URL)
    }

    fn verify_provenance_with_registry_url_sync(
        &self,
        quote: &Quote,
        registry_url: &str,
    ) -> Result<(), GcpProvenanceError> {
        let ppid = extract_ppid_from_quote(quote)?;
        {
            let known_gcp_ppids = self
                .known_gcp_ppids
                .read()
                .map_err(|err| GcpProvenanceError::CacheLock(err.to_string()))?;
            if known_gcp_ppids.contains(&ppid) {
                return Ok(());
            }
        }

        let provenance_url =
            format!("{}/{}", registry_url.trim_end_matches('/'), hex::encode(&ppid));
        let document = fetch_provenance_document(&provenance_url)?;
        validate_provenance_document(&document)?;

        self.known_gcp_ppids
            .write()
            .map_err(|err| GcpProvenanceError::CacheLock(err.to_string()))?
            .insert(ppid);

        Ok(())
    }
}

fn extract_ppid_from_quote(quote: &Quote) -> Result<Vec<u8>, GcpProvenanceError> {
    let cert_chain = intel::extract_cert_chain(quote)
        .map_err(|err| GcpProvenanceError::PpidExtraction(err.to_string()))?;
    let leaf = cert_chain.first().ok_or(GcpProvenanceError::NoPckCertificate)?;
    let extension = intel::parse_pck_extension(leaf)
        .map_err(|err| GcpProvenanceError::PpidExtraction(err.to_string()))?;

    if extension.ppid.is_empty() {
        return Err(GcpProvenanceError::EmptyPpid);
    }

    Ok(extension.ppid)
}

fn fetch_provenance_document(url: &str) -> Result<String, GcpProvenanceError> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(2)).build();
    let response =
        agent.get(url).call().map_err(|err| GcpProvenanceError::RegistryFetch(err.to_string()))?;

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
    #[error("PPID extraction: {0}")]
    PpidExtraction(String),
    #[error("registry fetch: {0}")]
    RegistryFetch(String),
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
        thread,
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

    #[test]
    fn extracts_ppid_from_mock_tdx_quote() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let ppid = extract_ppid_from_quote(&quote).unwrap();

        assert_eq!(hex::encode(ppid), MOCK_PPID_HEX);
    }

    #[test]
    fn extracts_ppid_from_fixture_dcap_quote() {
        let attestation = include_bytes!("../test-assets/dcap-tdx-1766059550570652607");
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
            .verify_provenance_with_registry_url_sync(&quote, &format!("http://{addr}"))
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

        checker.verify_provenance_with_registry_url_sync(&quote, &registry_url).unwrap();
        checker.verify_provenance_with_registry_url_sync(&quote, &registry_url).unwrap();

        let request = request_handle.join().unwrap();
        assert!(request.starts_with(&format!("GET /{MOCK_PPID_HEX} HTTP/1.1")));
    }

    #[test]
    fn provenance_check_fails_closed_on_registry_miss() {
        let attestation = dcap::create_dcap_attestation([0u8; 64]).unwrap();
        let quote = Quote::parse(&attestation).unwrap();
        let (addr, request_handle) = spawn_test_registry_server(404, "not found");

        let err = GcpProvenanceChecker::new()
            .verify_provenance_with_registry_url_sync(&quote, &format!("http://{addr}"))
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
            .verify_provenance_with_registry_url_sync(&quote, &format!("http://{addr}"))
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
            .verify_provenance_with_registry_url_sync(&quote, &format!("http://{addr}"))
            .unwrap_err();

        request_handle.join().unwrap();
        assert!(matches!(err, GcpProvenanceError::DocumentTooLarge));
    }
}
