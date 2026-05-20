//! AWS Nitro Enclaves attestation generation and verification.

use std::collections::HashMap;

use nsm_nitro_enclave_utils::{
    api::{
        ByteBuf,
        Time,
        nsm::{AttestationDoc, Digest, ErrorCode, Request, Response},
    },
    driver::{Driver, nitro::Nitro},
    verify::AttestationDocVerifierExt,
};
use thiserror::Error;

use crate::measurements::MultiMeasurements;

const AWS_ROOT_CERT_DER: &[u8] = include_bytes!("../assets/aws-nitro-enclaves-root-g1.der");
pub(crate) const NITRO_PCR_LENGTH: usize = 48;

/// Generate a Nitro attestation document using the Nitro Secure Module.
pub fn create_nitro_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, NitroError> {
    let nitro = Nitro::init();
    request_attestation(&nitro, input_data)
}

fn request_attestation(driver: &impl Driver, input_data: [u8; 64]) -> Result<Vec<u8>, NitroError> {
    match driver.process_request(Request::Attestation {
        nonce: Some(ByteBuf::from(input_data.to_vec())),
        user_data: None,
        public_key: None,
    }) {
        Response::Attestation { document } => Ok(document),
        Response::Error(error) => Err(NitroError::Nsm(error)),
        response => Err(NitroError::UnexpectedResponse(format!("{response:?}"))),
    }
}

/// Verify a Nitro attestation document and return its PCR measurements.
pub fn verify_nitro_attestation(
    input: Vec<u8>,
    expected_input_data: [u8; 64],
) -> Result<MultiMeasurements, NitroError> {
    let doc = decode_with_accepted_roots(&input)?;

    match doc.nonce.as_ref() {
        Some(nonce) if nonce.as_ref() == expected_input_data.as_slice() => {}
        _ => return Err(NitroError::InputMismatch),
    }

    measurements_from_doc(&doc)
}

/// Extract Nitro PCR measurements from a verified attestation document.
pub fn get_measurements(input: &[u8]) -> Result<MultiMeasurements, NitroError> {
    let doc = decode_with_accepted_roots(input)?;
    measurements_from_doc(&doc)
}

fn decode_with_accepted_roots(input: &[u8]) -> Result<AttestationDoc, NitroError> {
    let production_result = decode_with_root(input, AWS_ROOT_CERT_DER);
    #[allow(clippy::needless_match)]
    match production_result {
        Ok(doc) => Ok(doc),
        Err(production_error) => {
            #[cfg(any(test, feature = "mock"))]
            {
                let mock_root = mock_nitro_root_cert_der()?;
                if let Ok(doc) = decode_with_root(input, &mock_root) {
                    return Ok(doc);
                }
            }

            Err(production_error)
        }
    }
}

fn decode_with_root(input: &[u8], root_cert_der: &[u8]) -> Result<AttestationDoc, NitroError> {
    decode_with_root_at_time(input, root_cert_der, Time::default())
}

fn decode_with_root_at_time(
    input: &[u8],
    root_cert_der: &[u8],
    time: Time,
) -> Result<AttestationDoc, NitroError> {
    AttestationDoc::from_cose(input, root_cert_der, time)
        .map_err(|err| NitroError::Verification(format!("{err:?}")))
}

fn measurements_from_doc(doc: &AttestationDoc) -> Result<MultiMeasurements, NitroError> {
    let expected_pcr_len = match doc.digest {
        Digest::SHA256 => 32,
        Digest::SHA384 => NITRO_PCR_LENGTH,
        Digest::SHA512 => 64,
    };

    let mut measurements = HashMap::new();
    for (index, value) in &doc.pcrs {
        let index = u32::try_from(*index).map_err(|_| NitroError::InvalidPcrIndex(*index))?;
        if index > 31 {
            return Err(NitroError::InvalidPcrIndex(index as usize));
        }
        if value.as_ref().len() != expected_pcr_len {
            return Err(NitroError::BadPcrLength {
                index,
                expected: expected_pcr_len,
                actual: value.as_ref().len(),
            });
        }
        measurements.insert(index, value.as_ref().to_vec());
    }

    Ok(MultiMeasurements::Nitro(measurements))
}

#[cfg(any(test, feature = "mock"))]
fn mock_nitro_pki() -> &'static nsm_nitro_enclave_utils_keygen::NsmCertChain {
    use std::time::Duration;

    use once_cell::sync::Lazy;

    static MOCK_NITRO_PKI: Lazy<nsm_nitro_enclave_utils_keygen::NsmCertChain> = Lazy::new(|| {
        nsm_nitro_enclave_utils_keygen::NsmCertChain::generate(Duration::from_secs(3600))
    });

    &MOCK_NITRO_PKI
}

#[cfg(any(test, feature = "mock"))]
fn mock_nitro_root_cert_der() -> Result<Vec<u8>, NitroError> {
    use nsm_nitro_enclave_utils_keygen::DerEncodeExt;

    mock_nitro_pki().root.to_der().map_err(|err| NitroError::MockPki(format!("{err:?}")))
}

#[cfg(any(test, feature = "mock"))]
fn mock_nitro_pcrs() -> nsm_nitro_enclave_utils::pcr::Pcrs {
    use std::collections::BTreeMap;

    use nsm_nitro_enclave_utils::pcr::{PcrIndex, Pcrs};

    Pcrs::seed(BTreeMap::from([
        (PcrIndex::Zero, "attested-tls-mock-nitro-pcr0".to_string()),
        (PcrIndex::One, "attested-tls-mock-nitro-pcr1".to_string()),
        (PcrIndex::Two, "attested-tls-mock-nitro-pcr2".to_string()),
        (PcrIndex::Three, "attested-tls-mock-nitro-pcr3".to_string()),
        (PcrIndex::Four, "attested-tls-mock-nitro-pcr4".to_string()),
        (PcrIndex::Eight, "attested-tls-mock-nitro-pcr8".to_string()),
    ]))
}

/// Create a locally signed mock Nitro attestation document for tests and
/// local development.
#[cfg(any(test, feature = "mock"))]
pub fn create_mock_nitro_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, NitroError> {
    use nsm_nitro_enclave_utils::{api::SecretKey, driver::dev::DevNitro};
    use nsm_nitro_enclave_utils_keygen::DerEncodeExt;

    let pki = mock_nitro_pki();
    let signing_key_bytes = pki.end_signer.signing_key.to_bytes();
    let signing_key = SecretKey::from_slice(signing_key_bytes.as_ref())
        .map_err(|err| NitroError::MockPki(format!("{err:?}")))?;

    let nitro = DevNitro::builder(
        signing_key,
        ByteBuf::from(
            pki.end_signer.cert.to_der().map_err(|err| NitroError::MockPki(format!("{err:?}")))?,
        ),
    )
    .ca_bundle(vec![ByteBuf::from(
        pki.int.to_der().map_err(|err| NitroError::MockPki(format!("{err:?}")))?,
    )])
    .pcrs(mock_nitro_pcrs())
    .build();

    request_attestation(&nitro, input_data)
}

/// Mock Nitro PCR values used in tests and local development.
#[cfg(any(test, feature = "mock"))]
pub fn mock_nitro_measurements() -> MultiMeasurements {
    use nsm_nitro_enclave_utils::pcr::PcrIndex;

    let pcrs = mock_nitro_pcrs();
    MultiMeasurements::Nitro(HashMap::from([
        (0, pcrs.get(PcrIndex::Zero).as_ref().to_vec()),
        (1, pcrs.get(PcrIndex::One).as_ref().to_vec()),
        (2, pcrs.get(PcrIndex::Two).as_ref().to_vec()),
        (3, pcrs.get(PcrIndex::Three).as_ref().to_vec()),
        (4, pcrs.get(PcrIndex::Four).as_ref().to_vec()),
        (8, pcrs.get(PcrIndex::Eight).as_ref().to_vec()),
    ]))
}

/// An error when generating or verifying AWS Nitro attestation.
#[derive(Error, Debug)]
pub enum NitroError {
    #[error("Nitro Secure Module returned error: {0:?}")]
    Nsm(ErrorCode),
    #[error("Unexpected Nitro Secure Module response: {0}")]
    UnexpectedResponse(String),
    #[error("Nitro attestation verification: {0}")]
    Verification(String),
    #[error("Nitro attestation nonce is not as expected")]
    InputMismatch,
    #[error("Invalid Nitro PCR index: {0}")]
    InvalidPcrIndex(usize),
    #[error("Nitro PCR {index} has length {actual}, expected {expected}")]
    BadPcrLength { index: u32, expected: usize, actual: usize },
    #[cfg(any(test, feature = "mock"))]
    #[error("Mock Nitro PKI: {0}")]
    MockPki(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AttestationExchangeMessage, AttestationType, AttestationVerifier};

    #[test]
    fn aws_signed_attestation_fixture_verifies() {
        let attestation = include_bytes!("../test-assets/aws-nitro-attestation-sample.bin");
        let timestamp_millis = 1_680_010_000_000;
        let doc = decode_with_root_at_time(
            attestation,
            AWS_ROOT_CERT_DER,
            Time::new(Box::new(move || timestamp_millis)),
        )
        .unwrap();
        let measurements = measurements_from_doc(&doc).unwrap();

        if let MultiMeasurements::Nitro(pcrs) = measurements {
            assert!(pcrs.contains_key(&0));
        } else {
            panic!("expected Nitro measurements");
        }
    }

    #[test]
    fn aws_signed_attestation_fixture_has_expected_measurements() {
        let attestation = include_bytes!("../test-assets/aws-nitro-attestation-sample.bin");
        let timestamp_millis = 1_680_010_000_000;
        let doc = decode_with_root_at_time(
            attestation,
            AWS_ROOT_CERT_DER,
            Time::new(Box::new(move || timestamp_millis)),
        )
        .unwrap();
        let measurements = measurements_from_doc(&doc).unwrap();
        let mut expected_pcrs = HashMap::from([
            (
                3,
                hex::decode(
                    "e48b6ac6bab30e3717d28c2c88f2ba8b614e454590eb00b26170eef0d707b5b8e3a97662c20b2ced6192d3aaa2f5e24e",
                )
                .unwrap(),
            ),
            (
                4,
                hex::decode(
                    "3413af1370600b63aef6362b3d2506bcd6b6c263c8736b913d09e83c8bf24f93eb23eb87b15672586ef78c4289594acd",
                )
                .unwrap(),
            ),
        ]);
        for index in 0..16 {
            expected_pcrs.entry(index).or_insert_with(|| vec![0u8; NITRO_PCR_LENGTH]);
        }
        let expected = MultiMeasurements::Nitro(expected_pcrs);

        assert_eq!(measurements, expected);
    }

    #[tokio::test]
    async fn mock_nitro_verifier_supports_async_and_sync_verification() {
        let input_data = [7u8; 64];
        let attestation = create_mock_nitro_attestation(input_data).unwrap();
        let exchange =
            AttestationExchangeMessage { attestation_type: AttestationType::AwsNitro, attestation };
        let verifier = AttestationVerifier::mock();

        let async_measurements =
            verifier.verify_attestation(exchange.clone(), input_data).await.unwrap().unwrap();
        let sync_measurements =
            verifier.verify_attestation_sync(exchange, input_data).unwrap().unwrap();

        assert_eq!(async_measurements, mock_nitro_measurements());
        assert_eq!(sync_measurements, mock_nitro_measurements());
    }

    #[test]
    fn nonce_mismatch_is_rejected() {
        let attestation = create_mock_nitro_attestation([1u8; 64]).unwrap();
        let err = verify_nitro_attestation(attestation, [2u8; 64]).unwrap_err();

        assert!(matches!(err, NitroError::InputMismatch));
    }
}
