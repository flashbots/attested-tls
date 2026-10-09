//! Google's endorsement of the firmware a GCP TDX quote's MRTD names
//!
//! Google publishes one signed `VMLaunchEndorsement` per TDX firmware
//! build, keyed by MRTD, signed under `GCE-cc-tcb-root`. A live `gcp-tdx`
//! verification fetches the quote's, verifies it at the verification
//! instant and records it in the [`EndorsementSnapshot`]; a replay verifies
//! the recorded one at the snapshot's instant.
//!
//! [`EndorsementSnapshot`]: crate::EndorsementSnapshot
use std::{
    collections::HashMap,
    io::Read,
    sync::{Arc, RwLock},
    time::Duration,
};

use prost::Message;
use rsa::{
    RsaPublicKey,
    pkcs8::DecodePublicKey,
    pss::{Signature, VerifyingKey},
    signature::Verifier,
};
use sha2::Sha256;
use thiserror::Error;
use x509_parser::prelude::*;

use crate::HTTP_CONNECT_TIMEOUT;

/// Where Google publishes one endorsement per TDX firmware MRTD
const GCE_TCB_ENDORSEMENT_BUCKET_URL: &str =
    "https://storage.googleapis.com/gce_tcb_integrity/ovmf_x64_csm/tdx";
/// `GCE-cc-tcb-root_1.crt` from `https://pki.goog/cloud_integrity/`, DER
pub const GCE_CC_TCB_ROOT_DER: &[u8] = include_bytes!("../../assets/GCE-cc-tcb-root_1.crt");
/// The pinned root's published name
pub const GCE_CC_TCB_ROOT_NAME: &str = "GCE-cc-tcb-root_1";
/// Overall timeout for fetching an endorsement (DNS, connect, TLS, read)
const GCE_TCB_ENDORSEMENT_FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum size in bytes of an endorsement document
const GCE_TCB_ENDORSEMENT_MAX_BYTES: u64 = 64 * 1024;

/// `VMLaunchEndorsement` from Google's `gce-tcb-verifier` protobuf
#[derive(Clone, PartialEq, Message)]
struct VmLaunchEndorsement {
    #[prost(bytes = "vec", tag = "1")]
    serialized_uefi_golden: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

/// `VMGoldenMeasurement`, the fields this check reads
#[derive(Clone, PartialEq, Message)]
struct VmGoldenMeasurement {
    #[prost(bytes = "vec", tag = "4")]
    cert: Vec<u8>,
    #[prost(message, optional, tag = "8")]
    tdx: Option<VmTdx>,
}

#[derive(Clone, PartialEq, Message)]
struct VmTdx {
    #[prost(message, repeated, tag = "2")]
    measurements: Vec<VmTdxMeasurement>,
}

#[derive(Clone, PartialEq, Message)]
struct VmTdxMeasurement {
    #[prost(bytes = "vec", tag = "3")]
    mrtd: Vec<u8>,
}

/// A `VMLaunchEndorsement` as Google published it, verbatim
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcpFirmwareEndorsement(Vec<u8>);

impl GcpFirmwareEndorsement {
    /// Wrap published bytes; nothing is checked until [`Self::verify`]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Verify at `at` (Unix seconds) that this endorsement names `mrtd`
    pub fn verify(&self, mrtd: [u8; 48], at: u64) -> Result<(), GcpEndorsementError> {
        verify_endorsement(&self.0, mrtd, at)
    }
}

/// Verify at `at` (Unix seconds) that `endorsement` names `mrtd`: its
/// certificate is issued and signed by the pinned root and valid then, and
/// its RSA-PSS signature over the golden measurement holds
fn verify_endorsement(
    endorsement: &[u8],
    mrtd: [u8; 48],
    at: u64,
) -> Result<(), GcpEndorsementError> {
    verify_endorsement_under_root(endorsement, GCE_CC_TCB_ROOT_DER, mrtd, at)
}

fn verify_endorsement_under_root(
    endorsement: &[u8],
    root_der: &[u8],
    mrtd: [u8; 48],
    at: u64,
) -> Result<(), GcpEndorsementError> {
    let endorsement = VmLaunchEndorsement::decode(endorsement)?;
    let golden = VmGoldenMeasurement::decode(&*endorsement.serialized_uefi_golden)?;
    let (_, root) = X509Certificate::from_der(root_der)
        .map_err(|e| GcpEndorsementError::Cert(e.to_string()))?;
    let (_, leaf) = X509Certificate::from_der(&golden.cert)
        .map_err(|e| GcpEndorsementError::Cert(e.to_string()))?;
    let at = i64::try_from(at)
        .ok()
        .and_then(|at| ASN1Time::from_timestamp(at).ok())
        .ok_or(GcpEndorsementError::CertNotValidAt)?;
    verify_leaf_under_root(&leaf, &root, at)?;
    let key = RsaPublicKey::from_public_key_der(leaf.public_key().raw)
        .map_err(|e| GcpEndorsementError::Key(e.to_string()))?;
    let signature =
        Signature::try_from(&*endorsement.signature).map_err(|_| GcpEndorsementError::Signature)?;
    VerifyingKey::<Sha256>::new(key)
        .verify(&endorsement.serialized_uefi_golden, &signature)
        .map_err(|_| GcpEndorsementError::Signature)?;
    let tdx = golden.tdx.ok_or(GcpEndorsementError::NoTdx)?;
    if tdx.measurements.iter().any(|m| m.mrtd == mrtd) {
        Ok(())
    } else {
        Err(GcpEndorsementError::MrtdNotEndorsed(hex::encode(mrtd)))
    }
}

/// The chain is one hop. The leaf must name the pinned root as its issuer,
/// be valid at `at` along with the root, carry no critical extension this
/// check does not understand, and carry the root's signature. An extended
/// key usage, if present, must allow any purpose or server authentication,
/// the same rule Google's reference verifier applies through Go's default
/// `cert.Verify` options. Google publishes no revocation source for these
/// certificates, so none is consulted.
fn verify_leaf_under_root(
    leaf: &X509Certificate<'_>,
    root: &X509Certificate<'_>,
    at: ASN1Time,
) -> Result<(), GcpEndorsementError> {
    if leaf.issuer() != root.subject() {
        return Err(GcpEndorsementError::CertChain);
    }
    if !root.validity().is_valid_at(at) || !leaf.validity().is_valid_at(at) {
        return Err(GcpEndorsementError::CertNotValidAt);
    }
    for extension in leaf.extensions() {
        match extension.parsed_extension() {
            ParsedExtension::KeyUsage(usage) if !usage.digital_signature() => {
                return Err(GcpEndorsementError::CertKeyUsage);
            }
            ParsedExtension::ExtendedKeyUsage(usage) if !(usage.any || usage.server_auth) => {
                return Err(GcpEndorsementError::CertExtendedKeyUsage);
            }
            ParsedExtension::KeyUsage(_) |
            ParsedExtension::ExtendedKeyUsage(_) |
            ParsedExtension::BasicConstraints(_) |
            ParsedExtension::SubjectKeyIdentifier(_) |
            ParsedExtension::AuthorityKeyIdentifier(_) |
            ParsedExtension::SubjectAlternativeName(_) => {}
            _ if extension.critical => {
                return Err(GcpEndorsementError::CertCriticalExtension(extension.oid.to_string()));
            }
            _ => {}
        }
    }
    leaf.verify_signature(Some(root.public_key())).map_err(|_| GcpEndorsementError::CertChain)?;
    Ok(())
}

/// Fetches and verifies Google's endorsement for an MRTD, keeping one
/// verified copy per MRTD until it stops verifying
#[derive(Clone, Debug, Default)]
pub struct GcpEndorsementChecker {
    endorsements: Arc<RwLock<HashMap<[u8; 48], Arc<GcpFirmwareEndorsement>>>>,
}

impl GcpEndorsementChecker {
    /// An empty cache; clones share it, so one checker can serve many
    /// verifiers
    pub fn new() -> Self {
        Self::default()
    }

    /// Google's endorsement of `mrtd`, verified at `at` (Unix seconds); the
    /// fetch runs on the tokio blocking pool when a runtime is available
    pub(crate) async fn endorsement_for(
        &self,
        mrtd: [u8; 48],
        at: u64,
    ) -> Result<GcpFirmwareEndorsement, GcpEndorsementError> {
        self.endorsement_for_with_bucket_url(mrtd, GCE_TCB_ENDORSEMENT_BUCKET_URL.to_string(), at)
            .await
    }

    async fn endorsement_for_with_bucket_url(
        &self,
        mrtd: [u8; 48],
        bucket_url: String,
        at: u64,
    ) -> Result<GcpFirmwareEndorsement, GcpEndorsementError> {
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                let checker = self.clone();
                handle
                    .spawn_blocking(move || {
                        checker.endorsement_for_with_bucket_url_blocking_at(mrtd, &bucket_url, at)
                    })
                    .await
                    .map_err(|err| GcpEndorsementError::TaskJoin(err.to_string()))?
            }
            Err(_) => self.endorsement_for_with_bucket_url_blocking_at(mrtd, &bucket_url, at),
        }
    }

    /// Google's endorsement of `mrtd`, verified at `at` (Unix seconds); on
    /// a multi-threaded tokio runtime the fetch is marked as blocking
    pub(crate) fn endorsement_for_sync(
        &self,
        mrtd: [u8; 48],
        at: u64,
    ) -> Result<GcpFirmwareEndorsement, GcpEndorsementError> {
        self.endorsement_for_with_bucket_url_sync_at(mrtd, GCE_TCB_ENDORSEMENT_BUCKET_URL, at)
    }

    fn endorsement_for_with_bucket_url_sync_at(
        &self,
        mrtd: [u8; 48],
        bucket_url: &str,
        at: u64,
    ) -> Result<GcpFirmwareEndorsement, GcpEndorsementError> {
        let fetch = || self.endorsement_for_with_bucket_url_blocking_at(mrtd, bucket_url, at);

        match tokio::runtime::Handle::try_current() {
            Ok(handle)
                if matches!(
                    handle.runtime_flavor(),
                    tokio::runtime::RuntimeFlavor::MultiThread
                ) =>
            {
                tokio::task::block_in_place(fetch)
            }
            _ => fetch(),
        }
    }

    fn endorsement_for_with_bucket_url_blocking_at(
        &self,
        mrtd: [u8; 48],
        bucket_url: &str,
        at: u64,
    ) -> Result<GcpFirmwareEndorsement, GcpEndorsementError> {
        let cached = self
            .endorsements
            .read()
            .map_err(|err| GcpEndorsementError::CacheLock(err.to_string()))?
            .get(&mrtd)
            .cloned();
        if let Some(cached) = cached {
            match cached.verify(mrtd, at) {
                Ok(()) => return Ok((*cached).clone()),
                Err(err) => {
                    tracing::warn!(
                        mrtd = hex::encode(mrtd),
                        error = %err,
                        "cached GCP firmware endorsement no longer verifies; refetching"
                    );
                    let mut endorsements = self
                        .endorsements
                        .write()
                        .map_err(|err| GcpEndorsementError::CacheLock(err.to_string()))?;
                    if endorsements.get(&mrtd).is_some_and(|current| Arc::ptr_eq(current, &cached))
                    {
                        endorsements.remove(&mrtd);
                    }
                }
            }
        }

        let url = format!("{}/{}.binarypb", bucket_url.trim_end_matches('/'), hex::encode(mrtd));
        let endorsement = GcpFirmwareEndorsement::new(fetch_endorsement(&url)?);
        endorsement.verify(mrtd, at)?;
        self.endorsements
            .write()
            .map_err(|err| GcpEndorsementError::CacheLock(err.to_string()))?
            .insert(mrtd, Arc::new(endorsement.clone()));
        Ok(endorsement)
    }
}

/// Synchronously fetch an endorsement document
fn fetch_endorsement(url: &str) -> Result<Vec<u8>, GcpEndorsementError> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .proxy(None)
        .max_redirects(5)
        .timeout_connect(Some(HTTP_CONNECT_TIMEOUT))
        .timeout_global(Some(GCE_TCB_ENDORSEMENT_FETCH_TIMEOUT))
        .build()
        .into();
    let response = match agent.get(url).call() {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(status)) => {
            return Err(GcpEndorsementError::Fetch(format!("HTTP status {status}")));
        }
        Err(err) => {
            tracing::warn!(url, error = %err, "GCP firmware endorsement bucket unavailable");
            return Err(GcpEndorsementError::Unavailable(err.to_string()));
        }
    };

    if response.status() != 200 {
        return Err(GcpEndorsementError::Fetch(format!(
            "unexpected HTTP status {}",
            response.status()
        )));
    }

    let mut document = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(GCE_TCB_ENDORSEMENT_MAX_BYTES + 1)
        .read_to_end(&mut document)
        .map_err(|err| GcpEndorsementError::Fetch(err.to_string()))?;
    if document.len() as u64 > GCE_TCB_ENDORSEMENT_MAX_BYTES {
        return Err(GcpEndorsementError::TooLarge);
    }
    Ok(document)
}

#[derive(Error, Debug)]
pub enum GcpEndorsementError {
    #[error("endorsement fetch: {0}")]
    Fetch(String),
    #[error("endorsement bucket unavailable: {0}")]
    Unavailable(String),
    #[error("endorsement exceeds maximum size")]
    TooLarge,
    #[error("malformed endorsement: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("endorsement certificate: {0}")]
    Cert(String),
    #[error("endorsement certificate is not issued by {GCE_CC_TCB_ROOT_NAME}")]
    CertChain,
    #[error("endorsement certificate is not valid at the verification instant")]
    CertNotValidAt,
    #[error("endorsement certificate has an unrecognised critical extension {0}")]
    CertCriticalExtension(String),
    #[error("endorsement certificate is not for digital signatures")]
    CertKeyUsage,
    #[error("endorsement certificate's extended key usage excludes this use")]
    CertExtendedKeyUsage,
    #[error("endorsement public key: {0}")]
    Key(String),
    #[error("endorsement signature does not verify")]
    Signature,
    #[error("endorsement names no TDX measurements")]
    NoTdx,
    #[error("endorsement does not name MRTD {0}")]
    MrtdNotEndorsed(String),
    #[error("archived snapshot carries no firmware endorsement")]
    NotArchived,
    #[error("endorsement cache lock: {0}")]
    CacheLock(String),
    #[error("blocking task join: {0}")]
    TaskJoin(String),
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write as _,
        net::TcpListener,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use sha2::Digest as _;

    use super::*;

    /// Google's endorsement of the c3-standard-4 firmware a guest booted on
    /// 2026-10-01, that quote's MRTD, and an instant inside the
    /// certificate's validity
    const ENDORSEMENT: &[u8] =
        include_bytes!("../../test-assets/gce-endorsement-c3-standard-4.binarypb");
    const MRTD: &str = "c1ee9c16e3afc506cfe042c5b846a368528f3b37618eafb27469bc114cf914e9222c91618470e7f2b28ac360968270a5";
    const AT: u64 = 1_790_873_673;
    const AFTER_EXPIRY: u64 = 2_000_000_000;

    fn mrtd() -> [u8; 48] {
        hex::decode(MRTD).unwrap().try_into().unwrap()
    }

    /// Serve `ENDORSEMENT` for `MRTD` and 404 for anything else, counting
    /// requests
    fn spawn_endorsement_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let counter = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = [0u8; 2048];
                let n = stream.read(&mut request).unwrap_or(0);
                let request = String::from_utf8_lossy(&request[..n]);
                counter.fetch_add(1, Ordering::SeqCst);
                let (status, body): (&str, &[u8]) =
                    if request.contains(&format!("/{MRTD}.binarypb")) {
                        ("200 OK", ENDORSEMENT)
                    } else {
                        ("404 Not Found", b"")
                    };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(body);
            }
        });
        (format!("http://{addr}"), hits)
    }

    #[test]
    fn the_fixture_endorses_the_firmware_it_was_fetched_for() {
        verify_endorsement(ENDORSEMENT, mrtd(), AT).unwrap();
    }

    #[test]
    fn another_mrtd_is_not_endorsed() {
        assert!(matches!(
            verify_endorsement(ENDORSEMENT, [0x11; 48], AT),
            Err(GcpEndorsementError::MrtdNotEndorsed(_))
        ));
    }

    #[test]
    fn a_tampered_signature_or_body_fails() {
        let mut tampered = ENDORSEMENT.to_vec();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            verify_endorsement(&tampered, mrtd(), AT),
            Err(GcpEndorsementError::Signature)
        ));
        let mut tampered = ENDORSEMENT.to_vec();
        tampered[64] ^= 1;
        assert!(verify_endorsement(&tampered, mrtd(), AT).is_err());
        assert!(matches!(
            verify_endorsement(&ENDORSEMENT[..100], mrtd(), AT),
            Err(GcpEndorsementError::Decode(_))
        ));
    }

    #[test]
    fn outside_the_certificates_validity_fails() {
        assert!(matches!(
            verify_endorsement(ENDORSEMENT, mrtd(), AFTER_EXPIRY),
            Err(GcpEndorsementError::CertNotValidAt)
        ));
    }

    /// A leaf issued under Google's root name, signed by a key that is not
    /// the root's, with the given extended key usages
    fn leaf_under_googles_name(purposes: &[rcgen::ExtendedKeyUsagePurpose]) -> Vec<u8> {
        let signer = rcgen::KeyPair::generate().unwrap();
        let issuer = rcgen::Issuer::from_ca_cert_der(
            &rustls::pki_types::CertificateDer::from(GCE_CC_TCB_ROOT_DER),
            rcgen::KeyPair::generate().unwrap(),
        )
        .unwrap();
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.not_before =
            ::time::OffsetDateTime::from_unix_timestamp(AT as i64 - 86_400).unwrap();
        params.not_after = ::time::OffsetDateTime::from_unix_timestamp(AT as i64 + 86_400).unwrap();
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = purposes.to_vec();
        params.signed_by(&signer, &issuer).unwrap().der().to_vec()
    }

    fn check_leaf(leaf_der: &[u8]) -> Result<(), GcpEndorsementError> {
        let (_, root) = X509Certificate::from_der(GCE_CC_TCB_ROOT_DER).unwrap();
        let (_, leaf) = X509Certificate::from_der(leaf_der).unwrap();
        assert_eq!(leaf.issuer(), root.subject(), "the test leaf must carry the root's name");
        verify_leaf_under_root(&leaf, &root, ASN1Time::from_timestamp(AT as i64).unwrap())
    }

    /// A leaf is rejected on its issuer name before anything else
    #[test]
    fn a_certificate_under_another_root_is_rejected() {
        let (_, other_root) = x509_parser::pem::parse_x509_pem(include_bytes!(
            "../../assets/microsoft-rsa-devices-root-ca-2021.pem"
        ))
        .unwrap();
        assert!(matches!(
            verify_endorsement_under_root(ENDORSEMENT, &other_root.contents, mrtd(), AT),
            Err(GcpEndorsementError::CertChain)
        ));
    }

    /// Google's name on the leaf is not enough: the root's key must have
    /// signed it
    #[test]
    fn a_leaf_with_the_roots_name_but_another_signer_is_rejected() {
        assert!(matches!(
            check_leaf(&leaf_under_googles_name(&[])),
            Err(GcpEndorsementError::CertChain)
        ));
        assert!(matches!(
            check_leaf(&leaf_under_googles_name(&[rcgen::ExtendedKeyUsagePurpose::ServerAuth])),
            Err(GcpEndorsementError::CertChain)
        ));
        assert!(matches!(
            check_leaf(&leaf_under_googles_name(&[rcgen::ExtendedKeyUsagePurpose::Any])),
            Err(GcpEndorsementError::CertChain)
        ));
    }

    /// An extended key usage that excludes this use is rejected before the
    /// signature is looked at
    #[test]
    fn a_leaf_restricted_to_another_purpose_is_rejected() {
        for purposes in [
            vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth],
            vec![rcgen::ExtendedKeyUsagePurpose::CodeSigning],
            vec![
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
                rcgen::ExtendedKeyUsagePurpose::EmailProtection,
            ],
        ] {
            assert!(matches!(
                check_leaf(&leaf_under_googles_name(&purposes)),
                Err(GcpEndorsementError::CertExtendedKeyUsage)
            ));
        }
    }

    #[test]
    fn the_pinned_root_is_the_published_one() {
        assert_eq!(
            hex::encode(Sha256::digest(GCE_CC_TCB_ROOT_DER)),
            "e876bc6978bf4f3da445f98a0a82363c8c0bae5a1fc033c6df65846a6cb0f18c"
        );
        let (_, root) = X509Certificate::from_der(GCE_CC_TCB_ROOT_DER).unwrap();
        assert_eq!(root.subject(), root.issuer());
    }

    #[test]
    fn an_endorsement_is_fetched_once_then_served_from_cache() {
        let (bucket_url, hits) = spawn_endorsement_server();
        let checker = GcpEndorsementChecker::new();

        let first =
            checker.endorsement_for_with_bucket_url_sync_at(mrtd(), &bucket_url, AT).unwrap();
        let second =
            checker.endorsement_for_with_bucket_url_sync_at(mrtd(), &bucket_url, AT).unwrap();

        assert_eq!(first.as_bytes(), ENDORSEMENT);
        assert_eq!(first, second);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_cached_endorsement_that_stops_verifying_is_evicted_and_refetched() {
        let (bucket_url, hits) = spawn_endorsement_server();
        let checker = GcpEndorsementChecker::new();

        checker.endorsement_for_with_bucket_url_sync_at(mrtd(), &bucket_url, AT).unwrap();
        assert!(matches!(
            checker.endorsement_for_with_bucket_url_sync_at(mrtd(), &bucket_url, AFTER_EXPIRY),
            Err(GcpEndorsementError::CertNotValidAt)
        ));
        assert_eq!(hits.load(Ordering::SeqCst), 2, "the stale entry is refetched, not served");
        checker.endorsement_for_with_bucket_url_sync_at(mrtd(), &bucket_url, AT).unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 3, "the failed refetch left nothing cached");
    }

    #[test]
    fn an_mrtd_google_has_not_endorsed_fails_closed() {
        let (bucket_url, _) = spawn_endorsement_server();
        let checker = GcpEndorsementChecker::new();
        assert!(matches!(
            checker.endorsement_for_with_bucket_url_sync_at([0x22; 48], &bucket_url, AT),
            Err(GcpEndorsementError::Fetch(_))
        ));
    }

    #[tokio::test]
    async fn the_async_fetch_runs_on_the_blocking_pool() {
        let (bucket_url, hits) = spawn_endorsement_server();
        let checker = GcpEndorsementChecker::new();
        let endorsement =
            checker.endorsement_for_with_bucket_url(mrtd(), bucket_url, AT).await.unwrap();
        assert_eq!(endorsement.as_bytes(), ENDORSEMENT);
        assert_eq!(hits.load(Ordering::SeqCst), 1);
    }
}
