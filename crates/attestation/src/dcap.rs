//! Data Center Attestation Primitives (DCAP) evidence generation and
//! verification
use configfs_tsm::QuoteGenerationError;
use dcap_qvl::{
    QuoteCollateralV3,
    collateral::get_collateral_for_fmspc,
    quote::{Quote, Report},
};
use pccs::{Pccs, PccsError};
use thiserror::Error;

use crate::{AttestationError, measurements::MultiMeasurements};

/// For fetching collateral directly from Intel, if no PCCS is specified
pub const PCS_URL: &str = "https://api.trustedservices.intel.com";

/// Quote generation using configfs_tsm
pub fn create_dcap_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, AttestationError> {
    let quote = generate_quote(input_data)?;
    tracing::info!("Generated TDX quote of {} bytes", quote.len());
    Ok(quote)
}

/// Verify a DCAP TDX quote, and return the measurement values
#[cfg(not(any(test, feature = "mock")))]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Option<Pccs>,
) -> Result<MultiMeasurements, DcapVerificationError> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    verify_dcap_attestation_with_given_timestamp(input, expected_input_data, pccs, None, now, false)
        .await
}

/// Allows the timestamp to be given, making it possible to test with
/// existing attestations
///
/// If collateral is given, it is used instead of contacting PCCS (used in
/// tests)
///
/// # Note: `override_azure_outdated_tcb` parameter is a stub
///
/// The `override_azure_outdated_tcb` parameter only has an effect when the
/// crate is built with the `azure-tcb-override` feature. That feature is
/// currently a stub (see `Cargo.toml`); enabling it today has no effect on
/// verification behavior.
///
/// Callers passing `true` under the default feature set will silently receive
/// standard verification behavior. This is a footgun—once Phala-Network's
/// upstream `dcap-qvl` crate publishes a crates.io release that exposes the
/// Azure TCB override API they have already merged on their main branch, this
/// stub will be wired up and the parameter will take effect. Until then,
/// prefer `false` and rely on proper TCB hygiene.
pub async fn verify_dcap_attestation_with_given_timestamp(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs_option: Option<Pccs>,
    collateral: Option<QuoteCollateralV3>,
    now: u64,
    override_azure_outdated_tcb: bool,
) -> Result<MultiMeasurements, DcapVerificationError> {
    let quote = Quote::parse(&input)?;
    tracing::info!("Verifying DCAP attestation: {quote:?}");

    let ca = quote.ca()?;
    let fmspc = hex::encode_upper(quote.fmspc()?);

    let collateral = if let Some(given_collateral) = collateral {
        given_collateral
    } else if let Some(ref pccs) = pccs_option {
        let (collateral, _is_fresh) = pccs.get_collateral(fmspc.clone(), ca, now).await?;
        collateral
    } else {
        get_collateral_for_fmspc(
            PCS_URL,
            fmspc.clone(),
            ca,
            false, // Indicates not SGX
        )
        .await?
    };

    // The azure-tcb-override feature gates the workaround for a known outdated FMSPC on Azure.
    // Without the feature (the default) the standard verify() is used — correct for SGX/Intel
    // deployments.  See attested-oss/tasks/phase-1d.md Task 3 for context.
    let _ = override_azure_outdated_tcb; // only meaningful when azure-tcb-override is active
    let verified_report = dcap_qvl::verify::verify(&input, &collateral, now)?;

    if verified_report.status != "UpToDate" {
        tracing::warn!(
            status = %verified_report.status,
            advisory_ids = ?verified_report.advisory_ids,
            fmspc,
            "DCAP verification succeeded with non-UpToDate TCB status"
        );
    }

    let measurements = MultiMeasurements::from_dcap_qvl_quote(&quote)?;

    if get_quote_input_data(quote.report) != expected_input_data {
        return Err(DcapVerificationError::InputMismatch);
    }

    Ok(measurements)
}

#[cfg(any(test, feature = "mock"))]
#[allow(clippy::unused_async)]
pub async fn verify_dcap_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    _pccs: Option<Pccs>,
) -> Result<MultiMeasurements, DcapVerificationError> {
    // In tests we use mock quotes which will fail to verify
    let quote = tdx_quote::Quote::from_bytes(&input)?;
    if quote.report_input_data() != expected_input_data {
        return Err(DcapVerificationError::InputMismatch);
    }
    Ok(MultiMeasurements::from_tdx_quote(&quote))
}

/// Create a mock quote for testing on non-confidential hardware
#[cfg(any(test, feature = "mock"))]
fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, QuoteGenerationError> {
    let attestation_key = tdx_quote::SigningKey::random(&mut rand_core::OsRng);
    let provisioning_certification_key = tdx_quote::SigningKey::random(&mut rand_core::OsRng);
    Ok(tdx_quote::Quote::mock(
        attestation_key.clone(),
        provisioning_certification_key.clone(),
        input,
        b"Mock cert chain".to_vec(),
    )
    .as_bytes())
}

/// Create a quote
#[cfg(not(any(test, feature = "mock")))]
fn generate_quote(input: [u8; 64]) -> Result<Vec<u8>, QuoteGenerationError> {
    configfs_tsm::create_tdx_quote(input)
}

/// Given a [Report] get the input data regardless of report type
pub fn get_quote_input_data(report: Report) -> [u8; 64] {
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
    #[cfg(any(test, feature = "mock"))]
    #[error("Quote parse: {0}")]
    QuoteParse(#[from] tdx_quote::QuoteParseError),
    #[error("PCCS: {0}")]
    Pccs(#[from] PccsError),
    #[error("Timestamp exceeds i64 range")]
    TimeStampExceedsI64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::measurements::MeasurementPolicy;
    #[tokio::test]
    async fn test_dcap_verify() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../test-assets/dcap-tdx-1766059550570652607");

        // To avoid this test stopping working when the certificate is no longer
        // valid we pass in a timestamp
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

        let collateral = serde_saphyr::from_slice(collateral_bytes).unwrap();

        let measurements = verify_dcap_attestation_with_given_timestamp(
            attestation_bytes.to_vec(),
            [
                116, 39, 106, 100, 143, 31, 212, 145, 244, 116, 162, 213, 44, 114, 216, 80, 227,
                118, 129, 87, 180, 62, 194, 151, 169, 145, 116, 130, 189, 119, 39, 139, 161, 136,
                37, 136, 57, 29, 25, 86, 182, 246, 70, 106, 216, 184, 220, 205, 85, 245, 114, 33,
                173, 129, 180, 32, 247, 70, 250, 141, 176, 248, 99, 125,
            ],
            None,
            Some(collateral),
            now,
            false,
        )
        .await
        .unwrap();

        measurement_policy.check_measurement(&measurements).unwrap();
    }

    // This specifically tests a quote which has outdated TCB level from Azure.
    // Ignored pending dcap-qvl crates.io/Phala-fork TCB-override reconciliation;
    // see attested-oss/tasks/phase-1d.md Task 3.  The test requires
    // dcap_qvl::verify::dangerous_verify_with_tcb_override which is only present in the
    // Phala-Network fork and is absent from crates.io 0.3.12.
    #[ignore]
    #[tokio::test]
    async fn test_dcap_verify_azure_override() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../test-assets/azure_failed_dcap_quote_10.bin");

        // To avoid this test stopping working when the certificate is no longer
        // valid we pass in a timestamp
        let now = 1771414156;

        let collateral_bytes: &'static [u8] =
            include_bytes!("../test-assets/azure-collateral.yaml");

        let collateral = serde_saphyr::from_slice(collateral_bytes).unwrap();

        let _measurements = verify_dcap_attestation_with_given_timestamp(
            attestation_bytes.to_vec(),
            [
                210, 20, 43, 100, 53, 152, 235, 95, 174, 43, 200, 82, 157, 215, 154, 85, 139, 41,
                248, 104, 204, 187, 101, 49, 203, 40, 218, 185, 220, 228, 119, 40, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            None,
            Some(collateral),
            now,
            true,
        )
        .await
        .unwrap();
    }
}
