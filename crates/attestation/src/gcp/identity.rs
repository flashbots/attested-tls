//! GCE instance binding, following Google's canonical PZID encoding.
//!
//! Reference: [Google's PZID implementation].
//!
//! [Google's PZID implementation]: https://github.com/google/go-tdx-guest/blob/2108462acb71e7fd471b9535e1af2895d747c7c1/gce/pzid.go
use dcap_qvl::quote::{Quote, Report};
use sha2::{Digest, Sha384};
use thiserror::Error;

use super::GcpProvenanceError;

/// A complete GCP instance identity, using numeric project and instance
/// IDs.
#[derive(
    Clone, Debug, PartialEq, Eq, serde::Serialize, parity_scale_codec::Encode, serde::Deserialize,
)]
#[serde(try_from = "IdentityWire")]
pub struct GcpInstanceIdentity {
    project_number: u64,
    zone: String,
    instance_id: u64,
}

#[derive(serde::Deserialize, parity_scale_codec::Decode)]
struct IdentityWire {
    project_number: u64,
    zone: String,
    instance_id: u64,
}
impl TryFrom<IdentityWire> for GcpInstanceIdentity {
    type Error = GcpInstanceIdentityError;
    fn try_from(v: IdentityWire) -> Result<Self, Self::Error> {
        Self::new(v.project_number, v.zone, v.instance_id)
    }
}
impl parity_scale_codec::Decode for GcpInstanceIdentity {
    fn decode<I: parity_scale_codec::Input>(
        input: &mut I,
    ) -> Result<Self, parity_scale_codec::Error> {
        IdentityWire::decode(input)?.try_into().map_err(|_| "invalid GCP identity".into())
    }
}

impl GcpInstanceIdentity {
    pub fn project_number(&self) -> u64 {
        self.project_number
    }
    pub fn zone(&self) -> &str {
        &self.zone
    }
    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    /// Constructs an identity. `zone` must be a short zone name such as
    /// `us-central1-a`, containing only lowercase ASCII letters, digits and
    /// `-`.
    pub fn new(
        project_number: u64,
        zone: impl Into<String>,
        instance_id: u64,
    ) -> Result<Self, GcpInstanceIdentityError> {
        let zone = zone.into();
        if zone.is_empty() ||
            !zone.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(GcpInstanceIdentityError::InvalidZone(zone));
        }
        Ok(Self { project_number, zone, instance_id })
    }

    fn payload(&self) -> String {
        format!(
            r#"{{"instanceId":{},"numericalProjectId":{},"zone":"{}"}}"#,
            self.instance_id, self.project_number, self.zone,
        )
    }

    pub(crate) fn digest(&self) -> [u8; 48] {
        Sha384::digest(self.payload().as_bytes()).into()
    }
}

/// Invalid input to [`GcpInstanceIdentity::new`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GcpInstanceIdentityError {
    #[error("invalid GCP zone: {0:?}")]
    InvalidZone(String),
}

/// Check a quote whose authenticity has already been established by DCAP.
pub(crate) fn verify_instance(
    quote: &Quote,
    allowed: &[[u8; 48]],
) -> Result<(), GcpProvenanceError> {
    let actual = match &quote.report {
        Report::TD10(report) => &report.mr_owner,
        Report::TD15(report) => &report.base.mr_owner,
        Report::SgxEnclave(_) => {
            return Err(GcpProvenanceError::Quote("expected TDX report".into()));
        }
    };
    if allowed.contains(actual) {
        Ok(())
    } else {
        Err(GcpProvenanceError::InstanceIdentityMismatch { actual: hex::encode(actual) })
    }
}

#[cfg(test)]
mod tests {
    use dcap_qvl::quote::TDReport15;

    use super::*;

    fn identity() -> GcpInstanceIdentity {
        GcpInstanceIdentity::new(123456789012, "us-central1-a", 112233445566778899).unwrap()
    }

    #[test]
    fn matches_google_payload_and_go_digest() {
        // Google's TestPZIDPayload at revision
        // 2108462acb71e7fd471b9535e1af2895d747c7c1: https://github.com/google/go-tdx-guest/blob/2108462acb71e7fd471b9535e1af2895d747c7c1/gce/pzid_test.go
        // Digests independently generated with Go's fmt.Sprintf,
        // strconv.Quote, and crypto/sha512.Sum384, following that
        // revision's PZIDDigest.
        assert_eq!(
            identity().payload(),
            r#"{"instanceId":112233445566778899,"numericalProjectId":123456789012,"zone":"us-central1-a"}"#
        );
        assert_eq!(
            hex::encode(identity().digest()),
            "c9f79053aed02b9c4a2012fd7af9905c62e5790a9181f23bdedab6405b2a5866c8a68db6e565956d8b4844a3241059f2"
        );
        let large = GcpInstanceIdentity::new(u64::MAX, "us-central1-a", u64::MAX).unwrap();
        assert_eq!(
            large.payload(),
            r#"{"instanceId":18446744073709551615,"numericalProjectId":18446744073709551615,"zone":"us-central1-a"}"#
        );
        assert_eq!(
            hex::encode(large.digest()),
            "b7312e892da3ae655e6a0a735c98a03c281617760b36eb04874919442dd35d5b93eeb525823d1056c5f1ffeef6f0aace"
        );
    }

    #[test]
    fn rejects_invalid_zone() {
        for zone in [
            "",
            "US-central1-a",
            "us-central1-a\"",
            "us central1-a",
            "zones/us-central1-a",
            "ü",
            "us-central1-a\n",
        ] {
            assert!(GcpInstanceIdentity::new(1, zone, 2).is_err(), "{zone:?}");
        }
    }

    #[test]
    fn checks_both_tdx_report_variants_and_all_identity_components() {
        let bytes =
            mock_tdx::generate_mock_tdx_quote_with_mr_owner([0; 64], identity().digest()).unwrap();
        let mut quote = Quote::parse(&bytes).unwrap();
        let Report::TD10(base) = quote.report else { panic!("expected TD10") };
        for report in [
            Report::TD10(base),
            Report::TD15(TDReport15 { base, tee_tcb_svn2: [0; 16], mr_service_td: [0; 48] }),
        ] {
            quote.report = report;
            verify_instance(&quote, &[identity().digest()]).unwrap();
            for wrong in [
                GcpInstanceIdentity::new(123456789013, "us-central1-a", 112233445566778899)
                    .unwrap(),
                GcpInstanceIdentity::new(123456789012, "us-central1-b", 112233445566778899)
                    .unwrap(),
                GcpInstanceIdentity::new(123456789012, "us-central1-a", 112233445566778900)
                    .unwrap(),
            ] {
                assert!(matches!(
                    verify_instance(&quote, &[wrong.digest()]),
                    Err(GcpProvenanceError::InstanceIdentityMismatch { .. })
                ));
            }
            assert!(verify_instance(&quote, &[]).is_err());
        }
    }

    #[test]
    fn observed_legacy_gcp_quote_has_no_instance_binding() {
        let bytes = include_bytes!("../../test-assets/gcp-tdx-1782809233226668671");
        let quote = Quote::parse(bytes).unwrap();
        let Report::TD10(report) = quote.report else { panic!("expected TD10") };
        assert_eq!(report.mr_owner, [0; 48]);
        assert!(matches!(
            verify_instance(&quote, &[identity().digest()]),
            Err(GcpProvenanceError::InstanceIdentityMismatch { .. })
        ));
    }

    #[tokio::test]
    async fn observed_gcp_quote_verifies_instance_binding_with_stored_collateral() {
        use crate::dcap::{
            verify_dcap_attestation_with_given_timestamp,
            verify_dcap_attestation_with_timestamp_sync,
        };

        #[derive(serde::Deserialize)]
        struct FixtureIdentity {
            project_number: u64,
            zone: String,
            instance_id: u64,
            verification_timestamp: u64,
            report_data: String,
            mr_owner: String,
            quote_sha256: String,
        }

        let raw = include_bytes!("../../test-assets/gcp-tdx-1793093343786079228");
        let metadata: FixtureIdentity = serde_json::from_slice(include_bytes!(
            "../../test-assets/gcp-tdx-identity-1793093343786079228.json"
        ))
        .unwrap();
        let collateral: dcap_qvl::QuoteCollateralV3 = serde_saphyr::from_slice(include_bytes!(
            "../../test-assets/gcp-tdx-collateral-1793093343786079228.yaml"
        ))
        .unwrap();
        assert_eq!(hex::encode(sha2::Sha256::digest(raw)), metadata.quote_sha256);
        let expected =
            GcpInstanceIdentity::new(metadata.project_number, &metadata.zone, metadata.instance_id)
                .unwrap();
        assert_eq!(hex::encode(expected.digest()), metadata.mr_owner);
        // The fixture's report data was extracted from the quote, rather
        // than an independently supplied challenge. This tests
        // reproducible quote verification and identity binding, not
        // freshness at capture time.
        let report_data: [u8; 64] = hex::decode(metadata.report_data).unwrap().try_into().unwrap();
        let pccs = pccs::Pccs::new(
            pccs::CollateralSource::IntelPcs { subscription_key: None },
            pccs::CachePolicy::Passthrough,
        );
        let (_, async_quote) = verify_dcap_attestation_with_given_timestamp(
            raw.to_vec(),
            report_data,
            pccs.clone(),
            Some(collateral.clone()),
            metadata.verification_timestamp,
            false,
        )
        .await
        .unwrap();
        let (_, sync_quote) = verify_dcap_attestation_with_timestamp_sync(
            raw.to_vec(),
            report_data,
            pccs,
            Some(collateral),
            metadata.verification_timestamp,
            false,
        )
        .unwrap();

        for quote in [async_quote, sync_quote] {
            verify_instance(&quote, &[expected.digest()]).unwrap();
            for wrong in [
                GcpInstanceIdentity::new(
                    metadata.project_number + 1,
                    &metadata.zone,
                    metadata.instance_id,
                )
                .unwrap(),
                GcpInstanceIdentity::new(
                    metadata.project_number,
                    "us-central1-b",
                    metadata.instance_id,
                )
                .unwrap(),
                GcpInstanceIdentity::new(
                    metadata.project_number,
                    &metadata.zone,
                    metadata.instance_id + 1,
                )
                .unwrap(),
            ] {
                assert!(matches!(
                    verify_instance(&quote, &[wrong.digest()]),
                    Err(GcpProvenanceError::InstanceIdentityMismatch { .. })
                ));
            }
        }
    }
}

/// Collect once at local generator construction; providers supply their own
/// identity.
pub(crate) fn collect_identity() -> Result<GcpInstanceIdentity, GcpProvenanceError> {
    #[cfg(any(test, feature = "mock"))]
    {
        Ok(GcpInstanceIdentity::new(123456789012, "us-central1-a", 112233445566778899).unwrap())
    }
    #[cfg(not(any(test, feature = "mock")))]
    collect_identity_from("http://metadata.google.internal/computeMetadata/v1/")
}

#[cfg(any(test, not(feature = "mock")))]
fn collect_identity_from(base: &str) -> Result<GcpInstanceIdentity, GcpProvenanceError> {
    use std::io::Read;
    let agent = ureq::AgentBuilder::new()
        .redirects(0)
        .timeout_connect(std::time::Duration::from_secs(2))
        .timeout(std::time::Duration::from_secs(2))
        .build();
    let read = |key: &str| -> Result<String, GcpProvenanceError> {
        let response = agent
            .get(&format!("{base}{key}"))
            .set("Metadata-Flavor", "Google")
            .call()
            .map_err(|e| GcpProvenanceError::Metadata(e.to_string()))?;
        if response.status() != 200 || response.header("Metadata-Flavor") != Some("Google") {
            return Err(GcpProvenanceError::Metadata("invalid metadata response".into()));
        }
        let mut value = String::new();
        response
            .into_reader()
            .take(1025)
            .read_to_string(&mut value)
            .map_err(|e| GcpProvenanceError::Metadata(e.to_string()))?;
        if value.len() > 1024 {
            return Err(GcpProvenanceError::Metadata("metadata response too large".into()));
        }
        Ok(value.trim().to_owned())
    };
    let number = |key| {
        read(key)?.parse::<u64>().map_err(|e| GcpProvenanceError::Metadata(format!("{key}: {e}")))
    };
    let project = number("project/numeric-project-id")?;
    let instance = number("instance/id")?;
    let zone = read("instance/zone")?;
    GcpInstanceIdentity::new(project, zone.rsplit('/').next().unwrap_or_default(), instance)
        .map_err(|e| GcpProvenanceError::Metadata(e.to_string()))
}

#[cfg(test)]
mod metadata_tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn metadata_collection_validates_responses() {
        for (flavor, project, zone, success) in [
            ("Google", "769748474199", "projects/769748474199/zones/us-central1-a", true),
            ("Wrong", "769748474199", "us-central1-a", false),
            ("Google", "not-a-number", "us-central1-a", false),
            ("Google", "769748474199", "bad zone", false),
        ] {
            let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}/", server.local_addr().unwrap());
            let worker = std::thread::spawn(move || {
                for index in 0..3 {
                    let (mut stream, _) = server.accept().unwrap();
                    let mut buffer = [0; 2048];
                    let n = stream.read(&mut buffer).unwrap();
                    let request = String::from_utf8_lossy(&buffer[..n]);
                    assert!(request.to_ascii_lowercase().contains("metadata-flavor: google"));
                    let body = match index {
                        0 => project,
                        1 => "3276058549398918005",
                        _ => zone,
                    };
                    write!(stream, "HTTP/1.1 200 OK\r\nMetadata-Flavor: {flavor}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    if flavor != "Google" || (index == 0 && project == "not-a-number") {
                        break;
                    }
                }
            });
            let result = collect_identity_from(&base);
            assert_eq!(result.is_ok(), success);
            if let Ok(identity) = result {
                assert_eq!(identity.zone(), "us-central1-a");
            }
            worker.join().unwrap();
        }
    }
    #[test]
    fn metadata_limits_redirects_status_and_timeout() {
        for (status, body, delay) in
            [(302, "", false), (500, "", false), (200, "", true), (200, "oversized", false)]
        {
            let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}/", server.local_addr().unwrap());
            let worker = std::thread::spawn(move || {
                let (mut stream, _) = server.accept().unwrap();
                let mut buffer = [0; 2048];
                let _ = stream.read(&mut buffer);
                if delay {
                    std::thread::sleep(std::time::Duration::from_millis(2200));
                }
                let body = if body == "oversized" { "1".repeat(1025) } else { body.to_owned() };
                let _ = write!(
                    stream,
                    "HTTP/1.1 {status} Test\r\nMetadata-Flavor: Google\r\nLocation: /redirect\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            });
            assert!(collect_identity_from(&base).is_err());
            worker.join().unwrap();
        }
    }
}
