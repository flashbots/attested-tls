//! A real GCP quote replays only with the endorsement it was archived with
#![cfg(not(feature = "mock"))]

use attestation::{
    AttestationError,
    AttestationEvidence,
    AttestationExchangeMessage,
    AttestationType,
    AttestationVerifier,
    EndorsementSnapshot,
    GcpEndorsementError,
    GcpFirmwareEndorsement,
    PlatformMetadata,
    QuoteCollateralV3,
    measurements::MeasurementPolicy,
};

/// A GCP quote, the DCAP collateral it verified against, the instant, and
/// Google's endorsement of its firmware
struct Fixture {
    at: u64,
    evidence: AttestationExchangeMessage,
    dcap_collateral: QuoteCollateralV3,
    endorsement: GcpFirmwareEndorsement,
}

/// The crate's own GCP quote and collateral, with the endorsement Google
/// publishes for its MRTD
fn portable_fixture() -> Fixture {
    let quote = include_bytes!("../test-assets/gcp-tdx-1782809233226668671").to_vec();
    let platform = PlatformMetadata {
        attestation_type: AttestationType::GcpTdx.try_into().unwrap(),
        ram_bytes: 0,
        num_disks: 0,
        acpi: None,
        dm_verity_boot: false,
        smbios_handoff: None,
    };
    Fixture {
        at: 1_782_809_233,
        evidence: AttestationEvidence { quote, platform }.into(),
        dcap_collateral: serde_saphyr::from_slice(include_bytes!(
            "../test-assets/gcp-tdx-collateral-1782809233226668671.yaml"
        ))
        .unwrap(),
        endorsement: GcpFirmwareEndorsement::new(
            include_bytes!("../test-assets/gce-endorsement-gcp-tdx-1782809233226668671.binarypb")
                .to_vec(),
        ),
    }
}

/// One founder's harvest on a c3-standard-4 guest, 2026-10-01, as its
/// verifier archived it
fn founding_fixture() -> Fixture {
    #[derive(serde::Deserialize)]
    struct Founding {
        at: u64,
        evidence: AttestationExchangeMessage,
        dcap_collateral: QuoteCollateralV3,
        gcp_firmware_endorsement: String,
    }
    let founding: Founding =
        serde_json::from_str(include_str!("../test-assets/gcp-tdx-founding-1790873673.json"))
            .unwrap();
    Fixture {
        at: founding.at,
        evidence: founding.evidence,
        dcap_collateral: founding.dcap_collateral,
        endorsement: GcpFirmwareEndorsement::new(
            hex::decode(founding.gcp_firmware_endorsement).unwrap(),
        ),
    }
}

fn fixtures() -> [Fixture; 2] {
    [portable_fixture(), founding_fixture()]
}

/// The binding the evidence carries, read back from the quote
fn report_data(evidence: &AttestationExchangeMessage) -> [u8; 64] {
    let quote = &evidence.attestation_evidence.as_ref().unwrap().quote;
    dcap_qvl::quote::Quote::parse(quote).unwrap().report.as_td10().unwrap().report_data
}

fn verifier() -> AttestationVerifier {
    let policy =
        MeasurementPolicy::from_json_bytes(br#"[{"attestation_type": "gcp-tdx"}]"#.to_vec())
            .unwrap();
    AttestationVerifier::builder(policy).build()
}

fn replay(
    fixture: &Fixture,
    endorsement: Option<GcpFirmwareEndorsement>,
) -> Result<Option<attestation::VerifiedAttestation>, AttestationError> {
    let mut endorsements = EndorsementSnapshot::dcap(fixture.dcap_collateral.clone(), fixture.at);
    if let Some(endorsement) = endorsement {
        endorsements = endorsements.with_gcp_firmware(endorsement);
    }
    verifier().verify_attestation_archived(
        fixture.evidence.clone(),
        report_data(&fixture.evidence),
        &endorsements,
    )
}

#[test]
fn a_gcp_archive_replays_with_its_recorded_endorsement() {
    for fixture in fixtures() {
        let replayed = replay(&fixture, Some(fixture.endorsement.clone()))
            .unwrap()
            .expect("the fixture carries an attestation");
        assert_eq!(replayed.endorsements.at, fixture.at);
        assert_eq!(replayed.endorsements.gcp_firmware, Some(fixture.endorsement));
    }
}

#[test]
fn a_gcp_archive_without_an_endorsement_is_refused() {
    for fixture in fixtures() {
        let replayed = replay(&fixture, None);
        assert!(
            matches!(
                replayed,
                Err(AttestationError::GcpFirmwareEndorsement(GcpEndorsementError::NotArchived))
            ),
            "{replayed:?}"
        );
    }
}

#[test]
fn a_gcp_archive_with_a_tampered_endorsement_is_refused() {
    for fixture in fixtures() {
        let mut tampered = fixture.endorsement.clone().into_bytes();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let replayed = replay(&fixture, Some(GcpFirmwareEndorsement::new(tampered)));
        assert!(
            matches!(
                replayed,
                Err(AttestationError::GcpFirmwareEndorsement(GcpEndorsementError::Signature))
            ),
            "{replayed:?}"
        );
    }
}

/// Each fixture's endorsement names its own firmware and not the other's
#[test]
fn an_endorsement_for_another_firmware_is_refused() {
    let [portable, founding] = fixtures();
    for (fixture, other) in [(&portable, &founding), (&founding, &portable)] {
        let replayed = replay(fixture, Some(other.endorsement.clone()));
        assert!(
            matches!(
                replayed,
                Err(AttestationError::GcpFirmwareEndorsement(
                    GcpEndorsementError::MrtdNotEndorsed(_)
                ))
            ),
            "{replayed:?}"
        );
    }
}
