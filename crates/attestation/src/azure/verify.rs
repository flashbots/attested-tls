//! Verification of Microsoft Azure vTPM attestation evidence. Pure
//! computation over the evidence bytes: DCAP verification of the TDX quote,
//! HCL report binding checks, vTPM quote verification, and AK certificate
//! chain verification against pinned Azure roots.
//!
//! Three entry points, one per situation a relying party is in:
//!
//! - [verify_azure_attestation] is for a live handshake with an async
//!   runtime to hand: it fetches whatever collateral the quote needs and
//!   judges freshness at the wall clock.
//! - [verify_azure_attestation_sync] is for a live handshake inside a
//!   callback that cannot await, such as a rustls certificate verifier. It
//!   can only read the PCCS cache, so the collateral has to be there
//!   already; a miss fails and starts a background fetch for next time.
//! - [verify_azure_attestation_archived] is for re-checking evidence long
//!   after the fact, against the [EndorsementSnapshot] its original
//!   verification reported. It fetches nothing and judges freshness at the
//!   snapshot's instant, so the verdict is the same however much later it
//!   runs.
//!
//! They share one body and differ only in the DCAP leg, which is where
//! collateral and the instant come from. Parsing before it and the vTPM leg
//! after it are identical, and the vTPM leg takes its instant from whatever
//! the DCAP leg reported, so the archived path pins the AK chain check
//! without any code of its own.
use az_cvm_vtpm::{hcl, tdx};
use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};
use dcap_qvl::verify::QuoteVerifier;
use num_bigint::BigUint;
use openssl::pkey::PKey;
use pccs::Pccs;
use serde::Deserialize;
use x509_parser::prelude::*;

use super::{
    AttestationDocument,
    MaaError,
    TpmAttest,
    ak_certificate::verify_ak_cert_with_azure_roots,
    ensure_azure_attestation_payload_size,
};
use crate::{
    EndorsementSnapshot,
    VerifiedAttestation,
    dcap::{verify_quote, verify_quote_archived, verify_quote_sync},
    measurements::MultiMeasurements,
};

/// The TD quote inside an Azure attestation, and the input data it has to
/// commit to
///
/// Split from [VtpmLeg] so the three verification entry points share
/// everything but the DCAP call
struct PreparedTdQuote {
    tdx_quote_bytes: Vec<u8>,
    expected_tdx_input_data: [u8; 64],
}

/// Everything the vTPM leg of an Azure verification needs once the TD quote
/// has been verified
struct VtpmLeg {
    hcl_report: hcl::HclReport,
    var_data_hash: [u8; 32],
    tpm_attestation: TpmAttest,
}

/// Verify a TDX attestation from Azure
///
/// Collateral for the TD quote comes from `pccs`, and both legs are held
/// to the wall clock. To re-verify archived evidence, see
/// [verify_azure_attestation_archived].
pub async fn verify_azure_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
    override_azure_outdated_tcb: bool,
) -> Result<VerifiedAttestation, MaaError> {
    let (prepared, vtpm) = prepare_azure_attestation(input)?;

    let (dcap, _) = verify_quote(
        prepared.tdx_quote_bytes,
        prepared.expected_tdx_input_data,
        pccs,
        override_azure_outdated_tcb,
        &QuoteVerifier::new_prod(),
    )
    .await?;

    finish_azure_attestation_verification(vtpm, expected_input_data, dcap)
}

/// Verify a TDX attestation from Azure - synchronous version
///
/// This relies on having DCAP collateral already present in the cache
///
/// [`CachePolicy::Passthrough`](pccs::CachePolicy::Passthrough) is not
/// supported because fetching collateral requires asynchronous I/O.
///
/// If possible, prefer the async version
pub fn verify_azure_attestation_sync(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    pccs: Pccs,
    override_azure_outdated_tcb: bool,
) -> Result<VerifiedAttestation, MaaError> {
    let (prepared, vtpm) = prepare_azure_attestation(input)?;

    let (dcap, _) = verify_quote_sync(
        prepared.tdx_quote_bytes,
        prepared.expected_tdx_input_data,
        pccs,
        override_azure_outdated_tcb,
        &QuoteVerifier::new_prod(),
    )?;

    finish_azure_attestation_verification(vtpm, expected_input_data, dcap)
}

/// Re-verify a TDX attestation from Azure against the endorsements a
/// previous verification reported
///
/// The TD quote is checked against the snapshot's collateral bundle and the
/// AK certificate chain is checked at the snapshot's instant, so both legs
/// are held to the same instant as the original verification and nothing
/// is fetched. A snapshot with no DCAP bundle is refused; see
/// [crate::dcap::verify_dcap_attestation_archived].
pub fn verify_azure_attestation_archived(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
    endorsements: &EndorsementSnapshot,
    override_azure_outdated_tcb: bool,
) -> Result<VerifiedAttestation, MaaError> {
    let (prepared, vtpm) = prepare_azure_attestation(input)?;

    let (dcap, _) = verify_quote_archived(
        prepared.tdx_quote_bytes,
        prepared.expected_tdx_input_data,
        endorsements,
        override_azure_outdated_tcb,
        &QuoteVerifier::new_prod(),
    )?;

    finish_azure_attestation_verification(vtpm, expected_input_data, dcap)
}

/// Parses the attestation during verification
fn prepare_azure_attestation(input: Vec<u8>) -> Result<(PreparedTdQuote, VtpmLeg), MaaError> {
    ensure_azure_attestation_payload_size(&input)?;

    let attestation_document: AttestationDocument = serde_json::from_slice(&input)?;
    tracing::info!("Attempting to verify azure attestation: {attestation_document:?}");

    let AttestationDocument { tdx_quote_base64, hcl_report_base64, tpm_attestation } =
        attestation_document;

    let hcl_report_bytes = BASE64_URL_SAFE.decode(hcl_report_base64)?;
    let hcl_report = hcl::HclReport::new(hcl_report_bytes)?;
    let var_data_hash = hcl_report.var_data_sha256();

    let mut expected_tdx_input_data = [0u8; 64];
    expected_tdx_input_data[..32].copy_from_slice(&var_data_hash);

    let tdx_quote_bytes = BASE64_URL_SAFE.decode(tdx_quote_base64)?;

    Ok((
        PreparedTdQuote { tdx_quote_bytes, expected_tdx_input_data },
        VtpmLeg { hcl_report, var_data_hash, tpm_attestation },
    ))
}

/// The vTPM leg, after the DCAP leg has been verified
///
/// Only the DCAP leg's endorsements travel upward: this platform is judged
/// on the vTPM PCRs, not the TD quote's measurements. The AK certificate
/// chain is checked at the instant the DCAP leg reported, so one instant is
/// behind every freshness check. This leg fetches nothing — AK chain in the
/// evidence, roots compiled in — so the DCAP leg's endorsements are the
/// whole snapshot.
fn finish_azure_attestation_verification(
    vtpm: VtpmLeg,
    expected_input_data: [u8; 64],
    dcap: VerifiedAttestation,
) -> Result<VerifiedAttestation, MaaError> {
    let VtpmLeg { hcl_report, var_data_hash, tpm_attestation } = vtpm;
    let now = dcap.endorsements.at;
    let hcl_ak_pub = hcl_report.ak_pub()?;

    // Get attestation key from runtime claims
    let (ak_from_claims, user_data_input) = {
        let runtime_data_raw = hcl_report.var_data();
        let claims: HclRuntimeClaims = serde_json::from_slice(runtime_data_raw)?;

        let ak_jwk = claims
            .keys
            .iter()
            .find(|k| k.kid == "HCLAkPub")
            .ok_or(MaaError::ClaimsMissingHCLAkPub)?;

        let user_data = claims.user_data.as_deref().ok_or(MaaError::ClaimsMissingUserData)?;
        let user_data_bytes = hex::decode(user_data)?;
        let user_data_input: [u8; 64] =
            user_data_bytes.try_into().map_err(|_| MaaError::ClaimsUserDataBadLength)?;

        (RsaPubKey::from_jwk(ak_jwk)?, user_data_input)
    };

    // Check that the TD report input data matches the HCL var data hash
    let td_report: tdx::TdReport = hcl_report.try_into()?;
    if var_data_hash != td_report.report_mac.reportdata[..32] {
        return Err(MaaError::TdReportInputMismatch);
    }
    if user_data_input != expected_input_data {
        return Err(MaaError::ClaimsUserDataInputMismatch);
    }

    // Verify the vTPM quote
    let vtpm_quote = tpm_attestation.quote;
    let hcl_ak_pub_der = hcl_ak_pub.key.try_to_der().map_err(|_| MaaError::JwkConversion)?;
    let pub_key = PKey::public_key_from_der(&hcl_ak_pub_der)?;
    let pcrs = vtpm_quote.verify(&pub_key, &expected_input_data[..32])?;

    // Parse AK certificate
    let (_type_label, ak_certificate_der) =
        pem_rfc7468::decode_vec(tpm_attestation.ak_certificate_pem.as_bytes())?;
    let ak_intermediate_certificate_ders = tpm_attestation
        .ak_intermediate_certificates_pem
        .iter()
        .map(|pem| pem_rfc7468::decode_vec(pem.as_bytes()).map(|(_type_label, der)| der))
        .collect::<Result<Vec<_>, _>>()?;

    let (remaining_bytes, ak_certificate) = X509Certificate::from_der(&ak_certificate_der)?;
    let leaf_len = ak_certificate_der.len() - remaining_bytes.len();
    let ak_leaf_certificate_der = &ak_certificate_der[..leaf_len];

    // Check that AK public key matches that from TPM quote and HCL claims
    let ak_from_certificate = RsaPubKey::from_certificate(&ak_certificate)?;
    let ak_from_hcl = RsaPubKey::from_openssl_pubkey(&pub_key)?;
    if ak_from_claims != ak_from_hcl {
        return Err(MaaError::AkFromClaimsNotEqualAkFromHcl);
    }
    if ak_from_claims != ak_from_certificate {
        return Err(MaaError::AkFromClaimsNotEqualAkFromCertificate);
    }

    // Verify the AK certificate against microsoft root cert
    verify_ak_cert_with_azure_roots(
        ak_leaf_certificate_der,
        &ak_intermediate_certificate_ders,
        now,
    )?;

    Ok(VerifiedAttestation {
        measurements: MultiMeasurements::from_indexed_pcrs(pcrs),
        expected_measurements: None,
        endorsements: dcap.endorsements,
    })
}

/// Extract the measurements from the attestation, but do not verify
/// anything. input must be < [super::MAX_AZURE_ATTESTATION_PAYLOAD_SIZE],
/// otherwise an error is returned.
pub fn get_measurements(input: &[u8]) -> Result<MultiMeasurements, MaaError> {
    ensure_azure_attestation_payload_size(input)?;

    let attestation_document: AttestationDocument = serde_json::from_slice(input)?;
    let vtpm_quote = attestation_document.tpm_attestation.quote;
    let pcrs = vtpm_quote.indexed_pcrs_unverified()?;
    Ok(MultiMeasurements::from_indexed_pcrs(pcrs))
}

/// JSON Web Key used in [HclRuntimeClaims]
#[derive(Debug, Deserialize)]
struct Jwk {
    #[allow(unused)]
    pub kty: String,
    pub kid: String,
    #[allow(unused)]
    pub n: Option<String>,
    #[allow(unused)]
    pub e: Option<String>,
    // other fields ignored
}

/// The internal data structure for HCL runtime claims
#[derive(Debug, serde::Deserialize)]
struct HclRuntimeClaims {
    keys: Vec<Jwk>,
    #[allow(unused)]
    #[serde(rename = "vm-configuration")]
    vm_config: Option<serde_json::Value>,
    #[serde(rename = "user-data")]
    user_data: Option<String>,
}

/// This is only used as a common type to compare public keys with different
/// formats
#[derive(Debug, PartialEq)]
struct RsaPubKey {
    n: BigUint,
    e: BigUint,
}

impl RsaPubKey {
    fn from_jwk(jwk: &Jwk) -> Result<Self, MaaError> {
        if jwk.kty != "RSA" {
            return Err(MaaError::NotRsa);
        }

        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let n_bytes = URL_SAFE_NO_PAD.decode(jwk.n.clone().ok_or(MaaError::JwkParse)?)?;
        let e_bytes = URL_SAFE_NO_PAD.decode(jwk.e.clone().ok_or(MaaError::JwkParse)?)?;

        Ok(Self { n: BigUint::from_bytes_be(&n_bytes), e: BigUint::from_bytes_be(&e_bytes) })
    }

    fn from_certificate(cert: &X509Certificate) -> Result<Self, MaaError> {
        let spki = cert.public_key();
        let Ok(x509_parser::public_key::PublicKey::RSA(rsa_from_cert)) = spki.parsed() else {
            return Err(MaaError::NotRsa);
        };

        Ok(Self {
            n: BigUint::from_bytes_be(rsa_from_cert.modulus),
            e: BigUint::from_bytes_be(rsa_from_cert.exponent),
        })
    }

    fn from_openssl_pubkey(key: &PKey<openssl::pkey::Public>) -> Result<Self, MaaError> {
        let rsa_from_pkey = key.rsa()?;

        Ok(Self {
            n: BigUint::from_bytes_be(&rsa_from_pkey.n().to_vec()),
            e: BigUint::from_bytes_be(&rsa_from_pkey.e().to_vec()),
        })
    }
}

#[cfg(test)]
mod tests {
    use dcap_qvl::QuoteCollateralV3;

    use super::{super::MAX_AZURE_ATTESTATION_PAYLOAD_SIZE, *};
    use crate::EndorsementSnapshot;

    fn input_data_from_attestation(attestation_bytes: &[u8]) -> [u8; 64] {
        let attestation_document: AttestationDocument =
            serde_saphyr::from_slice(attestation_bytes).unwrap();
        let hcl_report_bytes =
            BASE64_URL_SAFE.decode(attestation_document.hcl_report_base64).unwrap();
        let hcl_report = hcl::HclReport::new(hcl_report_bytes).unwrap();
        let claims: HclRuntimeClaims = serde_json::from_slice(hcl_report.var_data()).unwrap();
        let user_data_hex = claims.user_data.unwrap();
        hex::decode(user_data_hex).unwrap().try_into().unwrap()
    }

    fn assert_payload_too_large(err: MaaError, actual: usize) {
        match err {
            MaaError::AzureAttestationPayloadTooLarge { actual: got, max } => {
                assert_eq!(got, actual);
                assert_eq!(max, MAX_AZURE_ATTESTATION_PAYLOAD_SIZE);
            }
            err => panic!("unexpected error: {err}"),
        }
    }

    #[test]
    fn get_measurements_rejects_oversized_payload_before_deserialize() {
        let actual = MAX_AZURE_ATTESTATION_PAYLOAD_SIZE + 1;
        let input = vec![b'{'; actual];

        let err = match get_measurements(&input) {
            Ok(_) => panic!("oversized payload should fail"),
            Err(err) => err,
        };

        assert_payload_too_large(err, actual);
    }

    /// All verification entry points must reject an oversized payload, and
    /// must do so before attempting DCAP verification (no collateral or
    /// usable PCCS is provided here).
    #[tokio::test]
    async fn verify_rejects_oversized_payload_before_deserialize() {
        let actual = MAX_AZURE_ATTESTATION_PAYLOAD_SIZE + 1;
        let input = vec![b'{'; actual];

        let err = verify_azure_attestation(
            input.clone(),
            [0; 64],
            Pccs::new(
                pccs::CollateralSource::IntelPcs { subscription_key: None },
                pccs::CachePolicy::Passthrough,
            ),
            false,
        )
        .await
        .unwrap_err();
        assert_payload_too_large(err, actual);

        let err = verify_azure_attestation_sync(
            input.clone(),
            [0; 64],
            Pccs::new(
                pccs::CollateralSource::IntelPcs { subscription_key: None },
                pccs::CachePolicy::OnDemand,
            ),
            false,
        )
        .unwrap_err();
        assert_payload_too_large(err, actual);

        let err = verify_azure_attestation_archived(
            input,
            [0; 64],
            &EndorsementSnapshot { at: 0, dcap: None },
            false,
        )
        .unwrap_err();
        assert_payload_too_large(err, actual);
    }

    #[tokio::test]
    async fn test_decode_hcl() {
        // From cvm-reverse-proxy/internal/attestation/azure/tdx/testdata/
        // hclreport. bin
        let hcl_bytes: &'static [u8] = include_bytes!("../../test-assets/hclreport.bin");

        let hcl_report = hcl::HclReport::new(hcl_bytes.to_vec()).unwrap();
        let hcl_var_data = hcl_report.var_data();
        let var_data_values: serde_json::Value = serde_json::from_slice(hcl_var_data).unwrap();

        // Check that it contains 64 byte user data
        assert_eq!(hex::decode(var_data_values["user-data"].as_str().unwrap()).unwrap().len(), 64);
    }

    /// Verify a complete observed Azure attestation payload that includes
    /// AK intermediates fetched from the leaf certificate's AIA URLs.
    #[test]
    fn test_verify() {
        // generated using the attester module's [capture_azure_fixture].
        let attestation_bytes: &'static [u8] =
            include_bytes!("../../test-assets/azure-tdx-with-ak-intermediates-1780922561.yaml");
        let collateral_bytes: &'static [u8] = include_bytes!(
            "../../test-assets/azure-collateral-with-ak-intermediates-1780922561.yaml"
        );

        // Fixed timestamp within the quote collateral and AK certificate
        // validity windows, so this offline fixture test does not expire
        // when wall-clock time advances.
        let now = 1_780_922_561;

        let attestation_document: AttestationDocument =
            serde_saphyr::from_slice(attestation_bytes).unwrap();
        assert_eq!(attestation_document.tpm_attestation.ak_intermediate_certificates_pem.len(), 2);

        let attestation_json = serde_json::to_vec(&attestation_document).unwrap();
        let fixture_collateral: QuoteCollateralV3 =
            serde_saphyr::from_slice(collateral_bytes).unwrap();

        let endorsements = EndorsementSnapshot::dcap(fixture_collateral, now);
        let VerifiedAttestation { measurements, endorsements: reported, .. } =
            verify_azure_attestation_archived(attestation_json, [0; 64], &endorsements, false)
                .unwrap();

        // The snapshot handed back is the one both legs were held to, so a
        // replay of a replay reports the same thing
        assert_eq!(reported, endorsements);
        assert!(matches!(measurements, MultiMeasurements::Azure(_)));
    }

    #[test]
    fn test_verify_fails_on_input_mismatch() {
        let attestation_bytes: &'static [u8] =
            include_bytes!("../../test-assets/azure-tdx-1764662251380464271.yaml");
        let now = 1771423480;

        let mut expected_input_data = input_data_from_attestation(attestation_bytes);
        expected_input_data[63] ^= 0x01;

        let collateral_bytes: &'static [u8] =
            include_bytes!("../../test-assets/azure-collateral02.yaml");
        let collateral = serde_saphyr::from_slice(collateral_bytes).unwrap();
        let attestation_json = serde_json::to_vec(
            &serde_saphyr::from_slice::<AttestationDocument>(attestation_bytes).unwrap(),
        )
        .unwrap();

        let err = verify_azure_attestation_archived(
            attestation_json,
            expected_input_data,
            &EndorsementSnapshot::dcap(collateral, now),
            false,
        )
        .unwrap_err();

        assert!(matches!(err, MaaError::ClaimsUserDataInputMismatch));
    }
}
