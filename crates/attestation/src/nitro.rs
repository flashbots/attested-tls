//! AWS Nitro Enclaves attestation generation and verification.

use std::collections::HashMap;

use coset::{CborSerializable, CoseSign1};
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

use crate::measurements::{MultiMeasurements, NITRO_PCR_LENGTH};

const AWS_ROOT_CERT_DER: &[u8] = include_bytes!("../assets/aws-nitro-enclaves-root-g1.der");

/// Generate a Nitro attestation document using the Nitro Secure Module.
pub fn create_nitro_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, NitroError> {
    let nitro = Nitro::init();
    create_nitro_attestation_with_driver(&nitro, input_data)
}

/// Return true if we can successfully talk to the Nitro Secure Module.
pub(crate) fn running_on_nitro() -> bool {
    let nitro = Nitro::init();
    matches!(nitro.process_request(Request::DescribeNSM), Response::DescribeNSM { .. })
}

/// Generate a Nitro attestation with given Nitro driver.
/// Re-using the Nitro when generating multiple attestations gives a very
/// small performance gain as we keep the file descriptor for `/dev/nsm`.
pub fn create_nitro_attestation_with_driver(
    driver: &impl Driver,
    input_data: [u8; 64],
) -> Result<Vec<u8>, NitroError> {
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

/// Extract Nitro PCR measurements without verifying the attestation
/// document.
pub fn get_measurements(input: &[u8]) -> Result<MultiMeasurements, NitroError> {
    let doc = decode_without_verification(input)?;
    measurements_from_doc(&doc)
}

/// Decode an attestation document without verifying timestamp or signature
fn decode_without_verification(input: &[u8]) -> Result<AttestationDoc, NitroError> {
    let cose = CoseSign1::from_slice(input)
        .map_err(|err| NitroError::Decode(format!("COSE decode: {err:?}")))?;
    let payload = cose
        .payload
        .as_ref()
        .ok_or_else(|| NitroError::Decode("missing COSE payload".to_string()))?;

    AttestationDoc::from_binary(payload)
        .map_err(|err| NitroError::Decode(format!("attestation document decode: {err:?}")))
}

/// Decode an attestation document, checking against AWS root of trust, or
/// mock root of trust if compiled in test or mock mode
fn decode_with_accepted_roots(input: &[u8]) -> Result<AttestationDoc, NitroError> {
    let production_result = decode_with_root(input, AWS_ROOT_CERT_DER);
    #[allow(clippy::needless_match)]
    match production_result {
        Ok(doc) => Ok(doc),
        Err(production_error) => {
            #[cfg(test)]
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

/// Decode an attestation document, and verify against a given root of trust
/// and the current time
fn decode_with_root(input: &[u8], root_cert_der: &[u8]) -> Result<AttestationDoc, NitroError> {
    decode_with_root_at_time(input, root_cert_der, Time::default())
}

/// Decode an attestation document, and verify against a given root of trust
/// and a given timestamp
fn decode_with_root_at_time(
    input: &[u8],
    root_cert_der: &[u8],
    time: Time,
) -> Result<AttestationDoc, NitroError> {
    AttestationDoc::from_cose(input, root_cert_der, time)
        .map_err(|err| NitroError::Verification(format!("{err:?}")))
}

/// Extract PCRs from a Nitro attestation document
fn measurements_from_doc(doc: &AttestationDoc) -> Result<MultiMeasurements, NitroError> {
    if doc.digest != Digest::SHA384 {
        return Err(NitroError::UnsupportedDigest(doc.digest));
    }

    let mut measurements = HashMap::new();
    for (index, value) in &doc.pcrs {
        let index = u32::try_from(*index).map_err(|_| NitroError::InvalidPcrIndex(*index))?;
        if index > 31 {
            return Err(NitroError::InvalidPcrIndex(index as usize));
        }
        if value.as_ref().len() != NITRO_PCR_LENGTH {
            return Err(NitroError::BadPcrLength {
                index,
                expected: NITRO_PCR_LENGTH,
                actual: value.as_ref().len(),
            });
        }
        measurements.insert(
            index,
            value.as_ref().try_into().map_err(|_| NitroError::BadPcrLength {
                index,
                expected: NITRO_PCR_LENGTH,
                actual: value.as_ref().len(),
            })?,
        );
    }

    Ok(MultiMeasurements::Nitro(measurements))
}

/// Generate a mock Nitro root of trust certificate chain
#[cfg(test)]
fn mock_nitro_pki() -> &'static nsm_nitro_enclave_utils_keygen::NsmCertChain {
    use std::time::Duration;

    use once_cell::sync::Lazy;

    static MOCK_NITRO_PKI: Lazy<nsm_nitro_enclave_utils_keygen::NsmCertChain> = Lazy::new(|| {
        nsm_nitro_enclave_utils_keygen::NsmCertChain::generate(Duration::from_secs(3600))
    });

    &MOCK_NITRO_PKI
}

/// Get mock Nitro root of trust certificate encoded as DER
#[cfg(test)]
fn mock_nitro_root_cert_der() -> Result<Vec<u8>, NitroError> {
    use nsm_nitro_enclave_utils_keygen::DerEncodeExt;

    mock_nitro_pki().root.to_der().map_err(|err| NitroError::MockPki(format!("{err:?}")))
}

/// PCR values for mock Nitro attestations
#[cfg(test)]
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

/// Create a locally signed mock Nitro attestation document for tests.
#[cfg(test)]
fn create_mock_nitro_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, NitroError> {
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

    create_nitro_attestation_with_driver(&nitro, input_data)
}

/// Mock Nitro PCR values used in tests.
#[cfg(test)]
pub(crate) fn mock_nitro_measurements() -> MultiMeasurements {
    use nsm_nitro_enclave_utils::pcr::PcrIndex;

    let pcrs = mock_nitro_pcrs();
    MultiMeasurements::Nitro(HashMap::from([
        (0, pcrs.get(PcrIndex::Zero).as_ref().try_into().unwrap()),
        (1, pcrs.get(PcrIndex::One).as_ref().try_into().unwrap()),
        (2, pcrs.get(PcrIndex::Two).as_ref().try_into().unwrap()),
        (3, pcrs.get(PcrIndex::Three).as_ref().try_into().unwrap()),
        (4, pcrs.get(PcrIndex::Four).as_ref().try_into().unwrap()),
        (8, pcrs.get(PcrIndex::Eight).as_ref().try_into().unwrap()),
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
    #[error("Nitro attestation decode: {0}")]
    Decode(String),
    #[error("Nitro attestation nonce is not as expected")]
    InputMismatch,
    #[error("Unsupported Nitro digest: {0:?}; expected SHA384")]
    UnsupportedDigest(Digest),
    #[error("Invalid Nitro PCR index: {0}")]
    InvalidPcrIndex(usize),
    #[error("Nitro PCR {index} has length {actual}, expected {expected}")]
    BadPcrLength { index: u32, expected: usize, actual: usize },
    #[cfg(test)]
    #[error("Mock Nitro PKI: {0}")]
    MockPki(String),
}

#[cfg(test)]
mod tests {
    use super::*;

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
                .unwrap()
                .try_into()
                .unwrap(),
            ),
            (
                4,
                hex::decode(
                    "3413af1370600b63aef6362b3d2506bcd6b6c263c8736b913d09e83c8bf24f93eb23eb87b15672586ef78c4289594acd",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
        ]);
        for index in 0..16 {
            expected_pcrs.entry(index).or_insert([0u8; NITRO_PCR_LENGTH]);
        }
        let expected = MultiMeasurements::Nitro(expected_pcrs);

        assert_eq!(measurements, expected);
    }

    #[test]
    fn another_aws_signed_attestation_fixture_has_expected_measurements() {
        let attestation = include_bytes!("../test-assets/aws-nitro-1779365257362730433");
        let timestamp_millis = 1_779_365_255_000;
        let doc = decode_with_root_at_time(
            attestation,
            AWS_ROOT_CERT_DER,
            Time::new(Box::new(move || timestamp_millis)),
        )
        .unwrap();
        let measurements = measurements_from_doc(&doc).unwrap();
        let mut expected_pcrs = HashMap::from([
            (
                0,
                hex::decode(
                    "5fd25293fa7f5682ab2290f0850da91ff42e7e37f79498a7f133dac86a66e678e3c399891a119d82ab35b2fca0d647fe",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
            (
                1,
                hex::decode(
                    "0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
            (
                2,
                hex::decode(
                    "c48f4b4ddb0711cac8c94de79f3e96e387eb52693cc3b1fb664ef90c7f9c5df602a16e7dabe6cad52e8791223ddf602b",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
            (
                3,
                hex::decode(
                    "ea81e40d742a2d5c5f9e099f5abce802914b55d7b2df6eeda212f8b4a96581a15689220b8dfcdda1825e3cfe2b7d6a06",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
            (
                4,
                hex::decode(
                    "50b5a4fd0bdcb66bfb04830da2a8baccf172629c3b30b8486c78ef06b18596fc4375fc0be0761e7033b41bf20ba28b41",
                )
                .unwrap()
                .try_into()
                .unwrap(),
            ),
        ]);
        for index in 0..16 {
            expected_pcrs.entry(index).or_insert([0u8; NITRO_PCR_LENGTH]);
        }
        let expected = MultiMeasurements::Nitro(expected_pcrs);

        assert_eq!(measurements, expected);
    }

    #[tokio::test]
    async fn mock_nitro_verifier_supports_async_and_sync_verification() {
        use crate::{AttestationExchangeMessage, AttestationType, AttestationVerifier};

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

    #[test]
    fn unsupported_digest_is_rejected() {
        use std::collections::BTreeMap;

        use nsm_nitro_enclave_utils::api::ByteBuf;

        let doc = AttestationDoc {
            module_id: "test".to_string(),
            digest: Digest::SHA256,
            timestamp: 0,
            pcrs: BTreeMap::from([(0usize, ByteBuf::from(vec![0u8; 32]))]),
            certificate: ByteBuf::from(Vec::new()),
            cabundle: Vec::new(),
            public_key: None,
            user_data: None,
            nonce: None,
        };

        let err = measurements_from_doc(&doc).unwrap_err();

        assert!(matches!(err, NitroError::UnsupportedDigest(Digest::SHA256)));
    }
}
