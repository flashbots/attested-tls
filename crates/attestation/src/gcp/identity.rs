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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GcpInstanceIdentity {
    project_number: u64,
    zone: String,
    instance_id: u64,
}

impl GcpInstanceIdentity {
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
