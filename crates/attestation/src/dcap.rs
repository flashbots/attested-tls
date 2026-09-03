//! Data Center Attestation Primitives (DCAP) evidence generation and
//! verification
//!
//! Every verify function returns the parsed [Quote] beside the
//! [VerifiedAttestation]: verification parses it anyway, and the GCP
//! provenance check needs the PPID from its PCK leaf. Other callers drop
//! it.
use dcap_qvl::{
    QuoteCollateralV3,
    collateral::CollateralClient,
    intel::{quote_ca, quote_fmspc},
    quote::{Quote, Report},
    tcb_info::TcbInfo,
    verify::QuoteVerifier,
};
#[cfg(any(test, feature = "mock"))]
use mock_tdx::generate_mock_tdx_quote;
use pccs::{Pccs, PccsError};
use thiserror::Error;

use crate::{
    AttestationError,
    EndorsementSnapshot,
    VerifiedAttestation,
    VerifyMode,
    measurements::MultiMeasurements,
};

/// FMSPC with which to override TCB level checks on Azure (not used for GCP
/// or other platforms)
const AZURE_BAD_FMSPC: &str = "90C06F000000";

/// For fetching collateral directly from Intel, if no PCCS is specified
pub const PCS_URL: &str = "https://api.trustedservices.intel.com";

/// Generate a TDX quote
pub fn create_dcap_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, AttestationError> {
    let quote = generate_quote(input_data)?;
    tracing::info!("Generated TDX quote of {} bytes", quote.len());
    Ok(quote)
}

/// Verify a DCAP TDX quote
///
/// `pccs` only matters on [VerifyMode::Live]: collateral comes from it, or
/// straight from Intel when there is none. [VerifyMode::Archived] carries
/// its own bundle and never consults it.
#[cfg(not(any(test, feature = "mock")))]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    mode: VerifyMode,
    pccs: Option<Pccs>,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote(input, expected_input_data, mode, pccs, false, &QuoteVerifier::new_prod(), None)
        .await
}

/// Verify a quote minted by [mock_tdx], which chains to the mock root CA
///
/// With neither a pinned bundle nor a PCCS this verifies against the
/// embedded mock collateral, which is what lets a mock build run with no
/// network at all.
#[cfg(any(test, feature = "mock"))]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    mode: VerifyMode,
    pccs: Option<Pccs>,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote(
        input,
        expected_input_data,
        mode,
        pccs,
        false,
        &mock_tdx::mock_dcap_verifier(),
        Some(mock_tdx::mock_collateral()),
    )
    .await
}

/// Synchronous version - verify a DCAP TDX quote
///
/// `pccs` only matters on [VerifyMode::Live], and then the collateral has
/// to be in its cache already. [VerifyMode::Archived] carries its own
/// bundle and never consults it.
///
/// If possible, prefer the async version
#[cfg(not(any(test, feature = "mock")))]
pub fn verify_dcap_attestation_sync(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    mode: VerifyMode,
    pccs: Pccs,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote_sync(input, expected_input_data, mode, pccs, false, &QuoteVerifier::new_prod())
}

/// Synchronous version - verify a quote minted by [mock_tdx]
#[cfg(any(test, feature = "mock"))]
pub fn verify_dcap_attestation_sync(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    mode: VerifyMode,
    pccs: Pccs,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    verify_quote_sync(
        input,
        expected_input_data,
        mode,
        pccs,
        false,
        &mock_tdx::mock_dcap_verifier(),
    )
}

/// The collateral a DCAP verification runs against, or `None` to fetch it,
/// and the instant to evaluate freshness at
///
/// The one place a verification reads the wall clock. An archived snapshot
/// has to carry a DCAP bundle: completing one with a fetch would evaluate
/// live collateral at a pinned instant, which is neither mode.
fn resolve_mode(
    mode: VerifyMode,
) -> Result<(Option<QuoteCollateralV3>, u64), DcapVerificationError> {
    match mode {
        VerifyMode::Live => {
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
            Ok((None, now.as_secs()))
        }
        VerifyMode::Archived(EndorsementSnapshot { at, dcap: Some(collateral) }) => {
            Ok((Some(collateral), at))
        }
        VerifyMode::Archived(EndorsementSnapshot { dcap: None, .. }) => {
            Err(DcapVerificationError::ArchivedWithoutDcapCollateral)
        }
    }
}

/// Resolve the collateral a verification runs against, then verify
///
/// Every root goes through here: the public entry points pick one per
/// build, while the Azure verifier and the fixture tests replaying real
/// captures pass Intel's, whatever the build. `override_azure_outdated_tcb`
/// is the TCB relaxation the Azure verifier applies to the quote inside an
/// HCL report. `fallback_collateral` is the bundle of last resort, used
/// when the mode pins none and there is no PCCS; `None` fetches from Intel.
pub(crate) async fn verify_quote(
    raw_quote: Vec<u8>,
    expected_input_data: [u8; 64],
    mode: VerifyMode,
    pccs: Option<Pccs>,
    override_azure_outdated_tcb: bool,
    verifier: &QuoteVerifier,
    fallback_collateral: Option<QuoteCollateralV3>,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    let (pinned_collateral, now) = resolve_mode(mode)?;
    let quote = Quote::parse(&raw_quote)?;
    let ca = quote_ca(&quote)?.as_id_str();
    let fmspc = hex::encode_upper(quote_fmspc(&quote)?);

    let collateral = if let Some(pinned_collateral) = pinned_collateral {
        pinned_collateral
    } else if let Some(ref pccs) = pccs {
        let (collateral, _is_fresh) = pccs.get_collateral(fmspc.clone(), ca, now).await?;
        collateral
    } else if let Some(fallback_collateral) = fallback_collateral {
        fallback_collateral
    } else {
        CollateralClient::with_default_http(PCS_URL)?
            .fetch_for_fmspc_without_pck_chain(&fmspc, ca, false)
            .await?
    };

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
/// On [VerifyMode::Live] the collateral has to be in the PCCS cache
/// already: there is no fetch of last resort here.
pub(crate) fn verify_quote_sync(
    raw_quote: Vec<u8>,
    expected_input_data: [u8; 64],
    mode: VerifyMode,
    pccs: Pccs,
    override_azure_outdated_tcb: bool,
    verifier: &QuoteVerifier,
) -> Result<(VerifiedAttestation, Quote), DcapVerificationError> {
    let (pinned_collateral, now) = resolve_mode(mode)?;
    let quote = Quote::parse(&raw_quote)?;
    let ca = quote_ca(&quote)?.as_id_str();
    let fmspc = hex::encode_upper(quote_fmspc(&quote)?);

    let collateral = match pinned_collateral {
        Some(pinned_collateral) => pinned_collateral,
        None => pccs.get_collateral_sync(fmspc, ca, now)?,
    };

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

    /// An archived snapshot without a bundle is refused up front, before
    /// the quote is even parsed: completing it with a fetch would evaluate
    /// live collateral at a pinned instant, which is neither mode
    #[tokio::test]
    async fn archived_without_collateral_is_refused() {
        let mode = VerifyMode::Archived(EndorsementSnapshot { at: 0, dcap: None });

        let err =
            verify_dcap_attestation(Vec::new(), [0; 64], mode.clone(), None).await.unwrap_err();
        assert!(matches!(err, DcapVerificationError::ArchivedWithoutDcapCollateral), "{err:?}");

        let err = verify_dcap_attestation_sync(
            Vec::new(),
            [0; 64],
            mode,
            Pccs::new_without_prewarm(None),
        )
        .unwrap_err();
        assert!(matches!(err, DcapVerificationError::ArchivedWithoutDcapCollateral), "{err:?}");
    }

    #[tokio::test]
    async fn test_dcap_verify() {
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

        let (VerifiedAttestation { measurements: async_measurements, endorsements }, _) =
            verify_quote(
                attestation_bytes.to_vec(),
                [
                    116, 39, 106, 100, 143, 31, 212, 145, 244, 116, 162, 213, 44, 114, 216, 80,
                    227, 118, 129, 87, 180, 62, 194, 151, 169, 145, 116, 130, 189, 119, 39, 139,
                    161, 136, 37, 136, 57, 29, 25, 86, 182, 246, 70, 106, 216, 184, 220, 205, 85,
                    245, 114, 33, 173, 129, 180, 32, 247, 70, 250, 141, 176, 248, 99, 125,
                ],
                VerifyMode::Archived(EndorsementSnapshot::dcap(fixture_collateral.clone(), now)),
                None,
                false,
                &QuoteVerifier::new_prod(),
                None,
            )
            .await
            .unwrap();

        let (VerifiedAttestation { measurements: sync_measurements, .. }, _) = verify_quote_sync(
            attestation_bytes.to_vec(),
            [
                116, 39, 106, 100, 143, 31, 212, 145, 244, 116, 162, 213, 44, 114, 216, 80, 227,
                118, 129, 87, 180, 62, 194, 151, 169, 145, 116, 130, 189, 119, 39, 139, 161, 136,
                37, 136, 57, 29, 25, 86, 182, 246, 70, 106, 216, 184, 220, 205, 85, 245, 114, 33,
                173, 129, 180, 32, 247, 70, 250, 141, 176, 248, 99, 125,
            ],
            VerifyMode::Archived(EndorsementSnapshot::dcap(fixture_collateral.clone(), now)),
            Pccs::new_without_prewarm(None),
            false,
            &QuoteVerifier::new_prod(),
        )
        .unwrap();

        assert_eq!(async_measurements, sync_measurements);
        // A caller archiving provenance gets back the bundle the
        // verification consumed, not a second copy of it
        assert_eq!(endorsements.dcap, Some(fixture_collateral));
        // ... and the instant it was held to, which is the other half of
        // what makes the verification reproducible
        assert_eq!(endorsements.at, now);
        let platform_metadata =
            crate::mock_platform_metadata(crate::AttestationType::DcapTdx).unwrap();
        measurement_policy
            .check_measurement(&async_measurements, Some(&platform_metadata))
            .unwrap();
    }

    // This specifically tests a quote which has outdated TCB level from
    // Azure
    #[tokio::test]
    async fn test_dcap_verify_azure_override() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../test-assets/azure_failed_dcap_quote_10.bin");

        // To avoid this test stopping working when the certificate is no
        // longer valid we pass in a timestamp
        let now = 1771414156;

        let collateral_bytes: &'static [u8] =
            include_bytes!("../test-assets/azure-collateral.yaml");

        let collateral = serde_saphyr::from_slice(collateral_bytes).unwrap();

        verify_quote(
            attestation_bytes.to_vec(),
            [
                210, 20, 43, 100, 53, 152, 235, 95, 174, 43, 200, 82, 157, 215, 154, 85, 139, 41,
                248, 104, 204, 187, 101, 49, 203, 40, 218, 185, 220, 228, 119, 40, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            VerifyMode::Archived(EndorsementSnapshot::dcap(collateral, now)),
            None,
            true,
            &QuoteVerifier::new_prod(),
            None,
        )
        .await
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
        let pccs = Pccs::new(Some(mock_pcs.base_url.clone()));
        let expected_input_data = [0xA5; 64];
        let quote = create_dcap_attestation(expected_input_data).unwrap();

        let (verified, _) =
            verify_dcap_attestation(quote, expected_input_data, VerifyMode::Live, Some(pccs))
                .await
                .unwrap();

        assert_eq!(verified.measurements, crate::measurements::mock_dcap_measurements());
        assert_eq!(mock_pcs.tcb_call_count(), 1);
        assert_eq!(mock_pcs.qe_call_count(), 1);
    }
}
