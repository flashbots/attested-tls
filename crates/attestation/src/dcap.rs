//! Data Center Attestation Primitives (DCAP) evidence generation and
//! verification
//!
//! Three entry points, one per situation a relying party is in:
//!
//! - [verify_dcap_attestation] is for a live handshake with an async
//!   runtime to hand: it fetches whatever collateral the quote needs and
//!   judges freshness at the wall clock.
//! - [verify_dcap_attestation_sync] is for a live handshake inside a
//!   callback that cannot await, such as a rustls certificate verifier. It
//!   can only read the PCCS cache, so the collateral has to be there
//!   already; a miss fails and starts a background fetch for next time.
//! - [verify_dcap_attestation_archived] is for re-checking evidence long
//!   after the fact, against the [EndorsementSnapshot] its original
//!   verification reported. It fetches nothing and judges freshness at the
//!   snapshot's instant, so the verdict is the same however much later it
//!   runs.
//!
//! They differ only in where collateral and the instant come from; the
//! verification itself is one function they all reach.
//!
//! Every verify function returns the parsed [Quote] beside the
//! [VerifiedAttestation]: verification parses it anyway, and the GCP
//! provenance check needs the PPID from its PCK leaf. Other callers drop
//! it.
use dcap_qvl::{
    QuoteCollateralV3,
    intel::{quote_ca, quote_fmspc},
    quote::{Quote, Report},
    tcb_info::TcbInfo,
    verify::QuoteVerifier,
};
#[cfg(any(test, feature = "mock"))]
use mock_tdx::generate_mock_tdx_quote;
#[cfg(test)]
use pccs::{CachePolicy, CollateralSource};
use pccs::{Pccs, PccsError};
use thiserror::Error;

use crate::{
    AttestationError,
    EndorsementSnapshot,
    VerifiedAttestation,
    measurements::MultiMeasurements,
};

/// FMSPC with which to override TCB level checks on Azure (not used for GCP
/// or other platforms)
const AZURE_BAD_FMSPC: &str = "90C06F000000";

/// Generate a TDX quote
pub fn create_dcap_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, AttestationError> {
    let quote = generate_quote(input_data)?;
    tracing::info!("Generated TDX quote of {} bytes", quote.len());
    Ok(quote)
}

/// Verify a DCAP TDX quote
///
/// Collateral comes from `pccs`, and every freshness check is evaluated
/// at the wall clock. To re-verify archived evidence, see
/// [verify_dcap_attestation_archived].
#[cfg(not(any(test, feature = "mock")))]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote(input, expected_input_data, pccs, false, &QuoteVerifier::new_prod()).await
}

/// Synchronous version - verify a DCAP TDX quote
///
/// This relies on having DCAP collateral already present in the cache
///
/// [`CachePolicy::Passthrough`](pccs::CachePolicy::Passthrough) is not
/// supported because fetching collateral requires asynchronous I/O.
///
/// If possible, prefer the async version
#[cfg(not(any(test, feature = "mock")))]
pub fn verify_dcap_attestation_sync(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote_sync(input, expected_input_data, pccs, false, &QuoteVerifier::new_prod())
}

/// Re-verify a DCAP TDX quote against the endorsements a previous
/// verification reported
///
/// The quote is checked against the snapshot's collateral bundle, with
/// every freshness check evaluated at the snapshot's instant rather than
/// the wall clock, and nothing is fetched. Same evidence, same snapshot,
/// same verdict, however much later it runs.
///
/// A snapshot with no DCAP bundle is refused rather than completed by a
/// fetch: that would evaluate live collateral at a pinned instant, which
/// reproduces nothing.
#[cfg(not(any(test, feature = "mock")))]
pub fn verify_dcap_attestation_archived(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    endorsements: &EndorsementSnapshot,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote_archived(
        input,
        expected_input_data,
        endorsements,
        false,
        &QuoteVerifier::new_prod(),
    )
}

/// Verify a quote minted by [mock_tdx], which chains to the mock root CA
///
/// With a passthrough PCCS this verifies against the embedded mock
/// collateral, which is what lets a mock build run with no network at all.
#[cfg(any(test, feature = "mock"))]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    if pccs.is_passthrough() {
        return verify_quote_archived(
            input,
            expected_input_data,
            &mock_endorsements_now()?,
            false,
            &mock_tdx::mock_dcap_verifier(),
        );
    }
    verify_quote(input, expected_input_data, pccs, false, &mock_tdx::mock_dcap_verifier()).await
}

/// Synchronous version - verify a quote minted by [mock_tdx]
#[cfg(any(test, feature = "mock"))]
pub fn verify_dcap_attestation_sync(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    if pccs.is_passthrough() {
        return verify_quote_archived(
            input,
            expected_input_data,
            &mock_endorsements_now()?,
            false,
            &mock_tdx::mock_dcap_verifier(),
        );
    }
    verify_quote_sync(input, expected_input_data, pccs, false, &mock_tdx::mock_dcap_verifier())
}

/// Re-verify a quote minted by [mock_tdx] against a reported snapshot
#[cfg(any(test, feature = "mock"))]
pub fn verify_dcap_attestation_archived(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    endorsements: &EndorsementSnapshot,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote_archived(
        input,
        expected_input_data,
        endorsements,
        false,
        &mock_tdx::mock_dcap_verifier(),
    )
}

/// The embedded mock collateral, held to the wall clock
#[cfg(any(test, feature = "mock"))]
fn mock_endorsements_now() -> Result<EndorsementSnapshot, DcapVerificationError> {
    Ok(EndorsementSnapshot::dcap(mock_tdx::mock_collateral(), unix_time_now_secs()?))
}

fn unix_time_now_secs() -> Result<u64, DcapVerificationError> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())
}

/// Fetch collateral through the PCCS and verify at the wall clock
///
/// Every live verification goes through here or [verify_quote_sync]: the
/// public entry points pick the root per build, while the Azure verifier
/// passes Intel's whatever the build. `override_azure_outdated_tcb` is the
/// TCB relaxation the Azure verifier applies to the quote inside an HCL
/// report.
pub(crate) async fn verify_quote(
    raw_quote: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
    override_azure_outdated_tcb: bool,
    verifier: &QuoteVerifier,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    let now = unix_time_now_secs()?;
    let quote = Quote::parse(&raw_quote)?;
    let ca = quote_ca(&quote)?.as_id_str();
    let fmspc = hex::encode_upper(quote_fmspc(&quote)?);

    let (collateral, _is_fresh) = pccs.get_collateral(fmspc, ca, now).await?;

    verify_quote_with_collateral(
        raw_quote,
        quote,
        expected_input_data,
        collateral,
        now,
        override_azure_outdated_tcb,
        verifier,
    )
}

/// [verify_quote], for a caller with no async runtime
///
/// The collateral has to be in the PCCS cache already.
pub(crate) fn verify_quote_sync(
    raw_quote: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
    override_azure_outdated_tcb: bool,
    verifier: &QuoteVerifier,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    let now = unix_time_now_secs()?;
    let quote = Quote::parse(&raw_quote)?;
    let ca = quote_ca(&quote)?.as_id_str();
    let fmspc = hex::encode_upper(quote_fmspc(&quote)?);

    let collateral = pccs.get_collateral_sync(fmspc, ca, now)?;

    verify_quote_with_collateral(
        raw_quote,
        quote,
        expected_input_data,
        collateral,
        now,
        override_azure_outdated_tcb,
        verifier,
    )
}

/// Verify against a reported snapshot: its bundle, at its instant, with
/// nothing fetched
///
/// The snapshot is checked before the quote is parsed, so a snapshot with
/// no DCAP bundle is refused up front.
pub(crate) fn verify_quote_archived(
    raw_quote: Vec<u8>,
    expected_input_data: [u8; 64],
    endorsements: &EndorsementSnapshot,
    override_azure_outdated_tcb: bool,
    verifier: &QuoteVerifier,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    let collateral =
        endorsements.dcap.clone().ok_or(DcapVerificationError::ArchivedWithoutDcapCollateral)?;
    let quote = Quote::parse(&raw_quote)?;

    verify_quote_with_collateral(
        raw_quote,
        quote,
        expected_input_data,
        collateral,
        endorsements.at,
        override_azure_outdated_tcb,
        verifier,
    )
}

/// Verify a quote against collateral already in hand, at a given instant
fn verify_quote_with_collateral(
    raw_quote: Vec<u8>,
    quote: Quote,
    expected_input_data: [u8; 64],
    collateral: QuoteCollateralV3,
    now: u64,
    override_azure_outdated_tcb: bool,
    verifier: &QuoteVerifier,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    tracing::info!("Verifying DCAP attestation: {quote:?}");

    let fmspc = hex::encode_upper(quote_fmspc(&quote)?);

    // Override outdated TCB only if we are on Azure and the FMSPC is known
    // to be outdated
    let override_outdated_tcb = if override_azure_outdated_tcb {
        |mut tcb_info: TcbInfo| {
            // This is a workaround for a known outdated FMSPC used by azure
            if tcb_info.fmspc == AZURE_BAD_FMSPC {
                for tcb_level in &mut tcb_info.tcb_levels {
                    if tcb_level.tcb.sgx_components[7].svn > 3 {
                        tcb_level.tcb.sgx_components[7].svn = 3
                    }
                }
            }
            tcb_info
        }
    } else {
        |tcb_info: TcbInfo| tcb_info
    };

    let verified_report = verifier.dangerous_verify_with_tcb_override(
        &raw_quote,
        &collateral,
        now,
        override_outdated_tcb,
    )?;

    if verified_report.status != "UpToDate" {
        tracing::warn!(
            status = %verified_report.status,
            advisory_ids = ?verified_report.advisory_ids,
            fmspc,
            "DCAP verification succeeded with non-UpToDate TCB status"
        );
    }

    let measurements = MultiMeasurements::from_dcap_qvl_quote(&quote)?;

    if get_quote_input_data(&quote.report) != expected_input_data {
        return Err(DcapVerificationError::InputMismatch);
    }

    Ok((
        VerifiedAttestation {
            measurements,
            expected_measurements: None,
            endorsements: EndorsementSnapshot::dcap(collateral, now),
        },
        quote,
    ))
}

/// Create a mock quote for testing on non-confidential hardware
#[cfg(any(test, feature = "mock"))]
fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, AttestationError> {
    generate_mock_tdx_quote(input).map_err(|error| AttestationError::Mock(format!("{error}")))
}

/// Create a quote
#[cfg(not(any(test, feature = "mock")))]
fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, AttestationError> {
    Ok(tdx_attest::get_quote(&input)?)
}

/// Given a [Report] get the input data regardless of report type
pub fn get_quote_input_data(report: &Report) -> [u8; 64] {
    match report {
        Report::TD10(r) => r.report_data,
        Report::TD15(r) => r.base.report_data,
        Report::SgxEnclave(r) => r.report_data,
    }
}

/// An error when verifying a DCAP attestation
#[derive(Error, Debug)]
pub enum DcapVerificationError {
    #[error("Quote input is not as expected")]
    InputMismatch,
    #[error("SGX quote given when TDX quote expected")]
    SgxNotSupported,
    #[error("System Time: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("DCAP quote verification: {0}")]
    DcapQvl(#[from] anyhow::Error),
    #[error("PCCS: {0}")]
    Pccs(#[from] PccsError),
    #[error("Timestamp exceeds i64 range")]
    TimeStampExceedsI64,
    #[error("Archived snapshot carries no DCAP collateral to replay the quote against")]
    ArchivedWithoutDcapCollateral,
}

#[cfg(test)]
mod tests {
    use mock_tdx::{MockPcsConfig, spawn_mock_pcs_server};

    use super::*;
    use crate::measurements::MeasurementPolicy;

    #[test]
    fn test_dcap_verify() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../test-assets/dcap-tdx-1766059550570652607");

        // To avoid this test stopping working when the certificate is no
        // longer valid we pass in a timestamp
        let now = 1769509141;

        let measurements_json = br#"
        [{
            "measurement_id": "cvm-image-azure-tdx.rootfs-20241107200854.wic.vhd",
            "attestation_type": "dcap-tdx",
            "measurements": {
            "0": { "expected": "a5844e88897b70c318bef929ef4dfd6c7304c52c4bc9c3f39132f0fdccecf3eb5bab70110ee42a12509a31c037288694"},
            "1": { "expected": "0564ec85d8d7cbaebde0f6cce94f3b15722c656b610426abbfde11a5e14e9a9ee07c752df120b85267bb6c6c743a9301"},
            "2": { "expected": "d6b50192d3c4a98ac0a58e12b1e547edd02d79697c1fb9faa2f6fd0b150553b23f399e6d63612699b208468da7b748f3"},
            "3": { "expected": "b26c7be2db28613938cd75fd4173b963130712acb710f2820f9f0519e93f781dbabd7ba945870f499826d0ed169c5b42"},
            "4": { "expected": "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"}
            }
        }]
        "#;

        let measurement_policy =
            MeasurementPolicy::from_json_bytes(measurements_json.to_vec()).unwrap();

        let collateral_bytes: &'static [u8] =
            include_bytes!("../test-assets/dcap-quote-collateral-00.yaml");

        let fixture_collateral: QuoteCollateralV3 =
            serde_saphyr::from_slice(collateral_bytes).unwrap();

        // A real Intel quote, so it is checked against Intel's root
        // whatever the build: the public archived entry point would
        // use the mock root under `test`
        let (VerifiedAttestation { measurements, endorsements, .. }, _) = verify_quote_archived(
            attestation_bytes.to_vec(),
            [
                116, 39, 106, 100, 143, 31, 212, 145, 244, 116, 162, 213, 44, 114, 216, 80, 227,
                118, 129, 87, 180, 62, 194, 151, 169, 145, 116, 130, 189, 119, 39, 139, 161, 136,
                37, 136, 57, 29, 25, 86, 182, 246, 70, 106, 216, 184, 220, 205, 85, 245, 114, 33,
                173, 129, 180, 32, 247, 70, 250, 141, 176, 248, 99, 125,
            ],
            &EndorsementSnapshot::dcap(fixture_collateral.clone(), now),
            false,
            &QuoteVerifier::new_prod(),
        )
        .unwrap();

        // The snapshot handed back is the one the verification ran against,
        // which is what lets a caller archive and replay it
        assert_eq!(endorsements, EndorsementSnapshot::dcap(fixture_collateral, now));
        let platform_metadata =
            crate::mock_platform_metadata(crate::AttestationType::DcapTdx).unwrap();
        measurement_policy.check_measurement(&measurements, Some(&platform_metadata)).unwrap();
    }

    /// An archived snapshot without a bundle is refused up front, before
    /// the quote is even parsed: completing it with a fetch would evaluate
    /// live collateral at a pinned instant, which reproduces nothing
    #[test]
    fn archived_without_collateral_is_refused() {
        let endorsements = EndorsementSnapshot { at: 0, dcap: None };

        let err = verify_dcap_attestation_archived(Vec::new(), [0; 64], &endorsements).unwrap_err();

        assert!(matches!(err, DcapVerificationError::ArchivedWithoutDcapCollateral), "{err:?}");
    }

    // This specifically tests a quote which has outdated TCB level from
    // Azure
    #[test]
    fn test_dcap_verify_azure_override() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../test-assets/azure_failed_dcap_quote_10.bin");

        // To avoid this test stopping working when the certificate is no
        // longer valid we pass in a timestamp
        let now = 1771414156;

        let collateral_bytes: &'static [u8] =
            include_bytes!("../test-assets/azure-collateral.yaml");

        let collateral = serde_saphyr::from_slice(collateral_bytes).unwrap();

        verify_quote_archived(
            attestation_bytes.to_vec(),
            [
                210, 20, 43, 100, 53, 152, 235, 95, 174, 43, 200, 82, 157, 215, 154, 85, 139, 41,
                248, 104, 204, 187, 101, 49, 203, 40, 218, 185, 220, 228, 119, 40, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            &EndorsementSnapshot::dcap(collateral, now),
            true,
            &QuoteVerifier::new_prod(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn test_mock_dcap_verify_uses_pccs_when_provided() {
        let mock_pcs = spawn_mock_pcs_server(MockPcsConfig {
            include_fmspcs_listing: false,
            ..MockPcsConfig::default()
        })
        .await
        .unwrap();
        let pccs = Pccs::new(
            CollateralSource::Pccs { url: mock_pcs.base_url.clone() },
            CachePolicy::OnDemand,
        );
        let expected_input_data = [0xA5; 64];
        let quote = create_dcap_attestation(expected_input_data).unwrap();

        let (verified, _) =
            verify_dcap_attestation(quote, expected_input_data, pccs).await.unwrap();

        assert_eq!(verified.measurements, crate::measurements::mock_dcap_measurements());
        assert_eq!(mock_pcs.tcb_call_count(), 1);
        assert_eq!(mock_pcs.qe_call_count(), 1);
    }
}
