mod mock_pcs;

use dcap_qvl::{
    QuoteCollateralV3,
    quote::{
        AuthData,
        AuthDataV4,
        CertificationData,
        Data,
        EnclaveReport,
        Header,
        QEReportCertificationData,
        Quote,
        Report,
        TDReport10,
    },
};
pub use mock_pcs::{MockPcsConfig, MockPcsServer, spawn_mock_pcs_server};
use p256::{
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::DecodePrivateKey,
};
use scale::Encode;
use serde::Serialize;
use sha2::Digest;

/// Embedded collateral fixture contents
const EMBEDDED_COLLATERAL_YAML: &str =
    include_str!("../test-assets/generated-dcap/mock-dcap-collateral.yaml");
/// Embedded manifest fixture contents
const EMBEDDED_MANIFEST_JSON: &str =
    include_str!("../test-assets/generated-dcap/mock-dcap-manifest.json");
/// Embedded root CA DER contents
const EMBEDDED_ROOT_CA_DER: &[u8] =
    include_bytes!("../test-assets/generated-dcap/mock-root-ca.der");
/// Embedded PCK private key PEM contents
const EMBEDDED_PCK_KEY_PEM: &str = include_str!("../test-assets/generated-dcap/mock-pck-key.pem");
/// Embedded PCK chain PEM contents
const EMBEDDED_PCK_CHAIN_PEM: &str =
    include_str!("../test-assets/generated-dcap/mock-pck-chain.pem");

/// Deterministic attestation secret key bytes
const ATTESTATION_SK: [u8; 32] = [0x55; 32];
/// TDX quote version used by the mock builder
const QUOTE_VERSION: u16 = 4;
/// ECDSA P-256 attestation key type
const ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE: u16 = 2;
/// TDX tee type
const TEE_TYPE_TDX: u32 = 0x00000081;
/// Intel QE vendor ID
const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];
/// Certification data type for a PCK chain
const PCK_CERT_CHAIN: u16 = 5;
/// Outer certification data type for a QE report block
const QE_REPORT_CERT: u16 = 6;
/// Fixed quote signature length
const ECDSA_SIGNATURE_BYTE_LEN: usize = 64;
/// Fixed attestation public key length
const ECDSA_PUBKEY_BYTE_LEN: usize = 64;
/// Fixed QE report length
const ENCLAVE_REPORT_BYTE_LEN: usize = 384;

/// Mock QE miscselect value
const QE_MISCSELECT: [u8; 4] = [0; 4];
/// Mock QE attributes value
const QE_ATTRIBUTES: [u8; 16] = [0; 16];
/// Mock QE mrsigner value
const QE_MRSIGNER: [u8; 32] = [0x5a; 32];
/// Mock QE ISV product ID
const QE_ISVPRODID: u16 = 2;
/// Mock QE ISV SVN
const QE_ISVSVN: u16 = 11;
/// Mock QE auth data
const QE_AUTH_DATA: [u8; 32] = [0xa5; 32];
/// Mock TD TCB SVN value for all components
const TDX_TCB_SVN: [u8; 16] = [1; 16];
/// Mock TD attributes with SEPT_VE_DISABLE enabled
const TD_ATTRIBUTES: [u8; 8] = [0, 0, 0, 0x10, 0, 0, 0, 0];
/// Mock MRTD value used in generated mock TDX quotes
pub const MOCK_MRTD: [u8; 48] = [0x10; 48];
/// Mock RTMR0 value used in generated mock TDX quotes
pub const MOCK_RTMR0: [u8; 48] = [0x50; 48];
/// Mock RTMR1 value used in generated mock TDX quotes
pub const MOCK_RTMR1: [u8; 48] = [0x60; 48];
/// Mock RTMR2 value used in generated mock TDX quotes
pub const MOCK_RTMR2: [u8; 48] = [0x70; 48];
/// Mock RTMR3 value used in generated mock TDX quotes
pub const MOCK_RTMR3: [u8; 48] = [0x80; 48];

/// Mock TDX material loaded from generated assets
pub struct MockTdxMaterial {
    /// Quote collateral used to verify generated mock quotes
    pub collateral: QuoteCollateralV3,
    /// Mock root CA in DER form
    pub root_ca_der: Vec<u8>,
    /// Mock PCK signing key
    pub pck_signing_key: SigningKey,
    /// Mock PCK certificate chain in PEM form
    pub pck_chain_pem: String,
    /// Manifest describing the generated mock platform
    pub manifest: FixtureManifest,
}

/// Load the generated mock TDX material from the workspace fixture
/// directory
pub fn load_mock_tdx_material() -> Result<MockTdxMaterial, Box<dyn std::error::Error>> {
    let collateral: QuoteCollateralV3 = serde_saphyr::from_str(EMBEDDED_COLLATERAL_YAML)?;
    let root_ca_der = EMBEDDED_ROOT_CA_DER.to_vec();
    let pck_signing_key = SigningKey::from_pkcs8_pem(EMBEDDED_PCK_KEY_PEM)?;
    let pck_chain_pem = EMBEDDED_PCK_CHAIN_PEM.to_string();
    let manifest: FixtureManifest = serde_json::from_str(EMBEDDED_MANIFEST_JSON)?;

    Ok(MockTdxMaterial { collateral, root_ca_der, pck_signing_key, pck_chain_pem, manifest })
}

/// Construct a p256 signing key from deterministic secret key bytes
pub(crate) fn signing_key_from_secret(
    secret: [u8; 32],
) -> Result<SigningKey, Box<dyn std::error::Error>> {
    Ok(SigningKey::from_bytes((&secret).into())?)
}

/// Generate a mock TDX DCAP quote using the generated fixture material
pub fn generate_mock_tdx_quote(
    report_data: [u8; 64],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let material = load_mock_tdx_material()?;
    generate_mock_tdx_quote_from_material(&material, report_data)
}

/// Generate a mock TDX DCAP quote from a specific loaded material set
pub fn generate_mock_tdx_quote_from_material(
    material: &MockTdxMaterial,
    report_data: [u8; 64],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let attestation_key = signing_key_from_secret(ATTESTATION_SK)?;
    let attestation_pubkey = raw_public_key(&attestation_key);

    let qe_report = build_qe_report(&attestation_pubkey)?;
    let qe_report_signature = sign_fixed_p256(&material.pck_signing_key, &qe_report);

    let outer_certification_data =
        CertificationData { cert_type: QE_REPORT_CERT, body: Data::new(Vec::new()) };
    let inner_certification_data = CertificationData {
        cert_type: PCK_CERT_CHAIN,
        body: Data::new(material.pck_chain_pem.as_bytes().to_vec()),
    };

    let auth_data = AuthData::V4(AuthDataV4 {
        ecdsa_signature: [0; ECDSA_SIGNATURE_BYTE_LEN],
        ecdsa_attestation_key: attestation_pubkey,
        certification_data: outer_certification_data,
        qe_report_data: QEReportCertificationData {
            qe_report,
            qe_report_signature,
            qe_auth_data: Data::new(QE_AUTH_DATA.to_vec()),
            certification_data: inner_certification_data,
        },
    });

    let mut quote = Quote {
        header: Header {
            version: QUOTE_VERSION,
            attestation_key_type: ATTESTATION_KEY_TYPE_ECDSA256_WITH_P256_CURVE,
            tee_type: TEE_TYPE_TDX,
            qe_svn: QE_ISVSVN,
            pce_svn: material.manifest.pce_svn,
            qe_vendor_id: INTEL_QE_VENDOR_ID,
            user_data: [0; 20],
        },
        report: Report::TD10(TDReport10 {
            tee_tcb_svn: TDX_TCB_SVN,
            mr_seam: [0; 48],
            mr_signer_seam: [0; 48],
            seam_attributes: [0; 8],
            td_attributes: TD_ATTRIBUTES,
            xfam: [0; 8],
            mr_td: MOCK_MRTD,
            mr_config_id: [0x20; 48],
            mr_owner: [0x30; 48],
            mr_owner_config: [0x40; 48],
            rt_mr0: MOCK_RTMR0,
            rt_mr1: MOCK_RTMR1,
            rt_mr2: MOCK_RTMR2,
            rt_mr3: MOCK_RTMR3,
            report_data,
        }),
        auth_data,
    };

    let signed_scope = signed_quote_scope(&quote);
    let auth_data = match &mut quote.auth_data {
        AuthData::V4(auth_data) => auth_data,
        AuthData::V3(_) => return Err("unexpected auth data version".into()),
    };
    auth_data.ecdsa_signature = sign_fixed_p256(&attestation_key, &signed_scope);

    Ok(quote.encode())
}

/// Sign raw bytes with ECDSA P-256 and return a fixed-size compact
/// signature
fn sign_fixed_p256(signing_key: &SigningKey, bytes: &[u8]) -> [u8; ECDSA_SIGNATURE_BYTE_LEN] {
    sign_raw_p256(signing_key, bytes).try_into().expect("p256 compact signature")
}

/// Sign raw bytes with ECDSA P-256 and return the compact r||s form
pub(crate) fn sign_raw_p256(signing_key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(bytes);
    signature.to_bytes().to_vec()
}

/// Build the QE report for the mock quote
fn build_qe_report(
    attestation_pubkey: &[u8; ECDSA_PUBKEY_BYTE_LEN],
) -> Result<[u8; ENCLAVE_REPORT_BYTE_LEN], Box<dyn std::error::Error>> {
    let qe_hash =
        sha2::Sha256::digest([attestation_pubkey.as_slice(), QE_AUTH_DATA.as_slice()].concat());
    let mut qe_report_data = [0u8; 64];
    qe_report_data[..32].copy_from_slice(&qe_hash);

    let qe_report = EnclaveReport {
        cpu_svn: [0; 16],
        misc_select: u32::from_le_bytes(QE_MISCSELECT),
        reserved1: [0; 28],
        attributes: QE_ATTRIBUTES,
        mr_enclave: [0; 32],
        reserved2: [0; 32],
        mr_signer: QE_MRSIGNER,
        reserved3: [0; 96],
        isv_prod_id: QE_ISVPRODID,
        isv_svn: QE_ISVSVN,
        reserved4: [0; 60],
        report_data: qe_report_data,
    };

    Ok(scale::Encode::encode(&qe_report).try_into().map_err(|_| "unexpected QE report length")?)
}

/// Encode the raw uncompressed P-256 public key without the SEC1 prefix
/// byte
fn raw_public_key(signing_key: &SigningKey) -> [u8; ECDSA_PUBKEY_BYTE_LEN] {
    let encoded = signing_key.verifying_key().to_encoded_point(false);
    encoded.as_bytes()[1..].try_into().expect("uncompressed p256 public key")
}

/// Return the quote bytes that are covered by the ISV report signature
fn signed_quote_scope(quote: &Quote) -> Vec<u8> {
    let mut encoded = scale::Encode::encode(quote);
    encoded.truncate(quote.signed_length());
    encoded
}

/// Summary manifest written alongside generated fixture files
#[derive(Serialize, serde::Deserialize)]
pub struct FixtureManifest {
    /// Mock platform FMSPC encoded as uppercase hex
    pub fmspc: String,
    /// Mock platform PCE ID encoded as uppercase hex
    pub pce_id_hex: String,
    /// Mock platform PCE SVN
    pub pce_svn: u16,
    /// Mock platform CPU SVN encoded as uppercase hex
    pub cpu_svn_hex: String,
    /// Mock platform PPID encoded as uppercase hex
    pub ppid_hex: String,
    /// Mock QE ISV SVN
    pub qe_isvsvn: u16,
    /// Human-readable issuer names embedded in the generated certificates
    pub issuer_common_names: IssuerNames,
    /// Generated fixture filenames
    pub files: OutputFiles,
}

/// Human-readable issuer names captured in the manifest
#[derive(Serialize, serde::Deserialize)]
pub struct IssuerNames {
    /// Root CA common name
    pub root_ca: String,
    /// TCB signing CA common name
    pub tcb_signing_ca: String,
    /// TCB signer common name
    pub tcb_signer: String,
    /// PCK certificate common name
    pub pck: String,
}

/// File inventory for the generated fixture set
#[derive(Serialize, serde::Deserialize)]
pub struct OutputFiles {
    /// Quote collateral fixture filename
    pub collateral: String,
    /// Manifest filename
    pub manifest: String,
    /// Root CA DER filename
    pub root_ca_der: String,
    /// Root CA PEM filename
    pub root_ca_pem: String,
    /// Root CA private key PEM filename
    pub root_ca_key_pem: String,
    /// TCB signer chain PEM filename
    pub tcb_signer_chain_pem: String,
    /// PCK chain PEM filename
    pub pck_chain_pem: String,
    /// PCK private key PEM filename
    pub pck_key_pem: String,
    /// Root CA CRL DER filename
    pub root_crl_der: String,
    /// PCK CRL DER filename
    pub pck_crl_der: String,
    /// TCB info JSON filename
    pub tcb_info_json: String,
    /// QE identity JSON filename
    pub qe_identity_json: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_TIME: u64 = 1_767_225_601;

    #[test]
    fn builds_quote_that_parses_and_verifies() {
        let material = load_mock_tdx_material().unwrap();
        let report_data = [0xAB; 64];

        let quote_bytes = generate_mock_tdx_quote_from_material(&material, report_data).unwrap();
        let quote = Quote::parse(&quote_bytes).unwrap();
        assert_eq!(quote.header.version, QUOTE_VERSION);
        assert_eq!(quote.header.tee_type, TEE_TYPE_TDX);
        assert_eq!(hex::encode_upper(quote.fmspc().unwrap()), material.manifest.fmspc);
        assert_eq!(quote.ca().unwrap(), "processor");

        let verifier = dcap_qvl::verify::QuoteVerifier::new(
            material.root_ca_der.clone(),
            dcap_qvl::verify::rustcrypto::backend(),
        );
        let verified = verifier.verify(&quote_bytes, &material.collateral, FIXTURE_TIME).unwrap();
        let dcap_qvl::quote::Report::TD10(report) = verified.report else {
            panic!("expected TD10 report");
        };
        assert_eq!(report.report_data, report_data);
        assert_eq!(report.mr_td, MOCK_MRTD);
        assert_eq!(report.rt_mr0, MOCK_RTMR0);
    }

    #[test]
    fn tampered_quote_signature_fails_verification() {
        const HEADER_BYTE_LEN: usize = 48;
        const TD_REPORT10_BYTE_LEN: usize = 584;
        const AUTH_DATA_SIZE_BYTE_LEN: usize = 4;

        let material = load_mock_tdx_material().unwrap();
        let mut quote_bytes = generate_mock_tdx_quote_from_material(&material, [0xCD; 64]).unwrap();
        let signature_offset = HEADER_BYTE_LEN + TD_REPORT10_BYTE_LEN + AUTH_DATA_SIZE_BYTE_LEN;
        quote_bytes[signature_offset] ^= 0x01;

        let verifier = dcap_qvl::verify::QuoteVerifier::new(
            material.root_ca_der.clone(),
            dcap_qvl::verify::rustcrypto::backend(),
        );
        assert!(verifier.verify(&quote_bytes, &material.collateral, FIXTURE_TIME).is_err());
    }
}
