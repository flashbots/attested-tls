//! Microsoft Azure vTPM attestation evidence generation and verification
mod ak_certificate;
#[cfg(azure_attester_x86_64_linux)]
mod attester;
mod tpm_quote;
mod tpms_attest;
mod verify;

#[cfg(azure_attester_x86_64_linux)]
pub use attester::{create_azure_attestation, detect_azure_cvm};
use az_cvm_vtpm::hcl;
use openssl::error::ErrorStack;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tpm_quote::TpmQuote;
pub use tpm_quote::TpmQuoteError;
pub use tpms_attest::AttestError;
pub use verify::{get_measurements, verify_azure_attestation, verify_azure_attestation_sync};

/// The attestation evidence payload that gets sent over the channel
#[derive(Debug, Serialize, Deserialize)]
struct AttestationDocument {
    /// TDX quote from the IMDS
    tdx_quote_base64: String,
    /// Serialized HCL report
    hcl_report_base64: String,
    /// vTPM related evidence
    tpm_attestation: TpmAttest,
}

/// TPM related components of the attestation document
#[derive(Debug, Serialize, Deserialize)]
struct TpmAttest {
    /// Attestation Key certificate from vTPM
    ak_certificate_pem: String,
    /// Intermediate CA certificates fetched from the AK leaf certificate's
    /// AIA CA Issuers URLs. These are untrusted evidence; verification
    /// pins the Azure vTPM root CA.
    #[serde(default, deserialize_with = "deserialize_ak_intermediate_certificates_pem")]
    ak_intermediate_certificates_pem: Vec<String>,
    /// vTPM quote
    quote: TpmQuote,
    /// Raw TCG event log bytes (UEFI + IMA) [currently not used]
    ///
    /// `/sys/kernel/security/ima/ascii_runtime_measurements`,
    /// `/sys/kernel/security/tpm0/binary_bios_measurements`,
    event_log: Vec<u8>,
    /// Optional platform / instance metadata used to bind or verify the AK
    /// [currently not used]
    instance_info: Option<Vec<u8>>,
}

/// Maximum serialized Azure attestation evidence payload size produced
/// during generation and accepted during verification.
///
/// Observed Azure TDX vTPM payloads, including AIA-fetched AK
/// intermediates, are about 30 KiB. This limit leaves headroom for normal
/// chain/quote growth while rejecting oversized JSON/base64/PEM blobs
/// before deserializing them into owned strings and byte vectors.
///
/// Transports are expected to bound reads at the network edge, before the
/// payload is ever buffered (e.g. rustls currently caps TLS certificates,
/// which carry this evidence, at 64 KiB). This check is the library's own
/// explicit fail-closed limit, so verification stays safe regardless of
/// which transport delivered the evidence and of transport-internal limits
/// changing.
const MAX_AZURE_ATTESTATION_PAYLOAD_SIZE: usize = 128 * 1024;

/// Maximum number of Azure vTPM AK intermediate certificates to fetch
/// during generation and accept during verification.
///
/// This is a defensive resource/cycle bound for following untrusted AIA
/// URLs and parsing peer-supplied evidence. Azure chains currently observed
/// use 1-2 intermediates. Verification still pins Azure roots and fails
/// closed if this bound prevents collecting a complete chain.
const MAX_EVIDENCE_AK_INTERMEDIATE_CERTIFICATES: usize = 8;

fn ensure_azure_attestation_payload_size(input: &[u8]) -> Result<(), MaaError> {
    if input.len() > MAX_AZURE_ATTESTATION_PAYLOAD_SIZE {
        return Err(MaaError::AzureAttestationPayloadTooLarge {
            actual: input.len(),
            max: MAX_AZURE_ATTESTATION_PAYLOAD_SIZE,
        });
    }

    Ok(())
}

fn deserialize_ak_intermediate_certificates_pem<'de, D>(
    deserializer: D,
) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let certificates = Vec::<String>::deserialize(deserializer)?;
    if certificates.len() > MAX_EVIDENCE_AK_INTERMEDIATE_CERTIFICATES {
        return Err(serde::de::Error::custom(format_args!(
            "too many AK intermediate certificates in evidence: {} > {}",
            certificates.len(),
            MAX_EVIDENCE_AK_INTERMEDIATE_CERTIFICATES
        )));
    }
    Ok(certificates)
}

fn unix_time_now_secs() -> Result<u64, MaaError> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())
}

/// An error when generating or verifying a Microsoft Azure vTPM attestation
/// (MAA is short for Microsoft Azure Attestation)
#[derive(Error, Debug)]
pub enum MaaError {
    #[error("HCL: {0}")]
    Hcl(#[from] hcl::HclError),
    #[error("Azure attestation evidence payload is too large: {actual} bytes > {max} bytes")]
    AzureAttestationPayloadTooLarge { actual: usize, max: usize },
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("System time before Unix epoch: {0}")]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error("HTTP client: {0}")]
    Reqwest(#[from] reqwest::Error),
    #[error("vTPM quote could not be verified: {0}")]
    TpmQuoteVerify(#[from] tpm_quote::TpmQuoteError),
    #[error("PEM encode: {0}")]
    Pem(#[from] pem_rfc7468::Error),
    #[error("TD report input does not match hashed HCL var data")]
    TdReportInputMismatch,
    #[error("Base64 decode: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("Hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("Attestation Key from HCL runtime claims does not match that from HCL report")]
    AkFromClaimsNotEqualAkFromHcl,
    #[error(
        "Attestation Key from HCL runtime claims does not match that from attestation key certificate"
    )]
    AkFromClaimsNotEqualAkFromCertificate,
    #[error("WebPKI: {0}")]
    WebPki(#[from] webpki::Error),
    #[error("X509 parse: {0}")]
    X509Parse(#[from] x509_parser::asn1_rs::Err<x509_parser::error::X509Error>),
    #[error("X509: {0}")]
    X509(#[from] x509_parser::error::X509Error),
    #[error("Cannot encode JSON web key as DER")]
    JwkConversion,
    #[error("OpenSSL: {0}")]
    OpenSSL(#[from] ErrorStack),
    #[error("Cannot extract measurements from quote")]
    CannotExtractMeasurementsFromQuote,
    #[error("Expected AK key to be RSA")]
    NotRsa,
    #[error("JSON web key has missing field")]
    JwkParse,
    #[error("HCL runtime claims is missing HCLAkPub field")]
    ClaimsMissingHCLAkPub,
    #[error("HCL runtime claims is missing user-data field")]
    ClaimsMissingUserData,
    #[error("HCL runtime claims user-data must decode to exactly 64 bytes")]
    ClaimsUserDataBadLength,
    #[error("HCL runtime claims user-data does not match expected report input data")]
    ClaimsUserDataInputMismatch,
    #[error("DCAP verification: {0}")]
    DcapVerification(#[from] crate::dcap::DcapVerificationError),

    // Errors that can only occur during evidence generation on an Azure CVM
    #[cfg(azure_attester_x86_64_linux)]
    #[error("Report: {0}")]
    Report(#[from] az_tdx_vtpm::report::ReportError),
    #[cfg(azure_attester_x86_64_linux)]
    #[error("IMDS: {0}")]
    Imds(#[from] az_tdx_vtpm::imds::ImdsError),
    #[cfg(azure_attester_x86_64_linux)]
    #[error("vTPM report: {0}")]
    VtpmReport(#[from] az_tdx_vtpm::vtpm::ReportError),
    #[cfg(azure_attester_x86_64_linux)]
    #[error("vTPM quote: {0}")]
    VtpmQuote(#[from] az_tdx_vtpm::vtpm::QuoteError),
    #[cfg(azure_attester_x86_64_linux)]
    #[error("vTPM read: {0}")]
    TssEsapi(#[from] tss_esapi::Error),
    #[cfg(azure_attester_x86_64_linux)]
    #[error("IO: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(azure_attester_x86_64_linux)]
    #[error("AIA URL is not HTTP(S): {url}")]
    UnsupportedAiaUrl { url: String },
    #[cfg(azure_attester_x86_64_linux)]
    #[error("Failed to fetch AIA issuer certificate from {url}: {source}")]
    AiaFetch { url: String, source: Box<ureq::Error> },
    #[cfg(azure_attester_x86_64_linux)]
    #[error(
        "Azure vTPM AK issuer chain exceeded maximum intermediate certificate count: {max_depth}"
    )]
    AkIssuerChainTooDeep { max_depth: usize },
    #[cfg(azure_attester_x86_64_linux)]
    #[error("Azure vTPM AK issuer chain could not be built to a pinned Azure root certificate")]
    AkIssuerChainIncomplete,
    #[cfg(azure_attester_x86_64_linux)]
    #[error(
        "Azure metadata API returned a successful response with non-JSON content-type: {content_type:?}"
    )]
    AzureMetadataApiNonJsonResponse { content_type: Option<String> },
}
