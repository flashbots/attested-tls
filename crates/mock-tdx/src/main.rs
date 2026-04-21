use std::{
    fs::{self, write},
    path::PathBuf,
};

use dcap_qvl::{
    QuoteCollateralV3,
    intel::{PckExtension, parse_pck_extension},
    tcb_info::{Tcb, TcbComponents, TcbInfo, TcbLevel, TcbStatus},
};
use mock_tdx::{FixtureManifest, IssuerNames, OutputFiles};
use p256::{
    SecretKey,
    ecdsa::{Signature, SigningKey, signature::Signer},
    pkcs8::EncodePrivateKey,
};
use rcgen::{
    BasicConstraints,
    CertificateParams,
    CertificateRevocationListParams,
    CertifiedIssuer,
    CustomExtension,
    DnType,
    IsCa,
    KeyIdMethod,
    KeyPair,
    KeyUsagePurpose,
    SerialNumber,
};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time};

/// Default output directory for generated mock DCAP fixtures
const OUTPUT_DIR: &str = "crates/mock-tdx/test-assets/generated-dcap";
/// Serialized collateral fixture filename
const COLLATERAL_BASENAME: &str = "mock-dcap-collateral.yaml";
/// Mock platform manifest filename
const MANIFEST_BASENAME: &str = "mock-dcap-manifest.json";
/// Root CA DER filename
const ROOT_CA_DER_BASENAME: &str = "mock-root-ca.der";
/// Root CA PEM filename
const ROOT_CA_PEM_BASENAME: &str = "mock-root-ca.pem";
/// Root CA private key PEM filename
const ROOT_CA_KEY_BASENAME: &str = "mock-root-ca-key.pem";
/// TCB signer issuer chain PEM filename
const TCB_SIGNER_CHAIN_BASENAME: &str = "mock-tcb-signer-chain.pem";
/// PCK chain PEM filename
const PCK_CHAIN_BASENAME: &str = "mock-pck-chain.pem";
/// PCK private key PEM filename
const PCK_KEY_BASENAME: &str = "mock-pck-key.pem";
/// Root CA CRL DER filename
const ROOT_CRL_DER_BASENAME: &str = "mock-root-ca.crl.der";
/// PCK CRL DER filename
const PCK_CRL_DER_BASENAME: &str = "mock-pck.crl.der";
/// TCB info JSON filename
const TCB_INFO_JSON_BASENAME: &str = "mock-tcb-info.json";
/// QE identity JSON filename
const QE_IDENTITY_JSON_BASENAME: &str = "mock-qe-identity.json";

/// Deterministic PCK secret key bytes
const PCK_SK: [u8; 32] = [0x44; 32];

/// Deterministic root CA secret key bytes
const ROOT_CA_SK: [u8; 32] = [0x11; 32];
/// Common name used for the mock root CA
const ROOT_CA_CN: &str = "Mock Intel Root CA";
/// Common name used for the mock TCB signing CA
const TCB_CA_CN: &str = "Mock Intel TCB Signing CA";
/// Common name used for the mock TCB signer
const TCB_SIGNER_CN: &str = "Mock Intel TCB Signer";
/// Common name used for the mock PCK certificate
const PCK_CN: &str = "Mock Intel PCK";

/// Intel SGX extension OID for the mock PCK cert
const PCK_EXTENSION_OID: &[u64] = &[1, 2, 840, 113741, 1, 13, 1];
/// Deterministic TCB CA secret key bytes
const TCB_CA_SK: [u8; 32] = [0x22; 32];
/// Deterministic TCB signer secret key bytes
const TCB_SIGNER_SK: [u8; 32] = [0x33; 32];

/// Mock QE miscselect value
const QE_MISCSELECT: [u8; 4] = [0; 4];
/// Mock QE miscselect mask
const QE_MISCSELECT_MASK: [u8; 4] = [0xff; 4];
/// Mock QE attributes value
const QE_ATTRIBUTES: [u8; 16] = [0; 16];
/// Mock QE attributes mask
const QE_ATTRIBUTES_MASK: [u8; 16] = [0xff; 16];
/// Mock QE mrsigner value
const QE_MRSIGNER: [u8; 32] = [0x5a; 32];
/// Mock QE ISV product ID
const QE_ISVPRODID: u16 = 2;
/// Mock QE ISV SVN
const QE_ISVSVN: u16 = 11;
/// Mock TD TCB SVN value for all components
const TDX_TCB_SVN: [u8; 16] = [1; 16];

/// Fixed validity window used for checked-in mock fixtures
struct ValidityWindow {
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
}

/// Return the stable validity range used by generated mock fixtures
fn validity_window() -> ValidityWindow {
    let not_before = PrimitiveDateTime::new(
        Date::from_calendar_date(2025, Month::January, 1).expect("valid start date"),
        Time::MIDNIGHT,
    )
    .assume_utc();
    let not_after = PrimitiveDateTime::new(
        Date::from_calendar_date(2045, Month::January, 1).expect("valid end date"),
        Time::MIDNIGHT,
    )
    .assume_utc();
    ValidityWindow { not_before, not_after }
}

/// Construct an rcgen keypair from deterministic secret key bytes
fn key_pair_from_secret(secret: [u8; 32]) -> Result<KeyPair, Box<dyn std::error::Error>> {
    let pkcs8 = SecretKey::from_slice(&secret)?.to_pkcs8_pem(Default::default())?;
    Ok(KeyPair::from_pkcs8_pem_and_sign_algo(pkcs8.as_str(), &rcgen::PKCS_ECDSA_P256_SHA256)?)
}

/// Construct a p256 signing key from deterministic secret key bytes
fn signing_key_from_secret(secret: [u8; 32]) -> Result<SigningKey, Box<dyn std::error::Error>> {
    Ok(SigningKey::from_bytes((&secret).into())?)
}

/// Sign raw bytes with ECDSA P-256 and return the compact r||s form
fn sign_raw_p256(signing_key: &SigningKey, bytes: &[u8]) -> Vec<u8> {
    let signature: Signature = signing_key.sign(bytes);
    signature.to_bytes().to_vec()
}

/// Known-good Intel SGX extension DER reused for the mock PCK cert
///
/// This blob was copied from `dcap-qvl`'s `tests/generate_test_certs.sh`
/// where it is embedded as the OpenSSL DER payload for OID
/// `1.2.840.113741.1.13.1`
const VALID_PCK_EXTENSION_HEX: &str = "308201C1301E060A2A864886F84D010D01010410D04EC06D4E6D92DC90D0AD3CF5EE2DDF30820164060A2A864886F84D010D0102308201543010060B2A864886F84D010D01020102010B3010060B2A864886F84D010D01020202010B3010060B2A864886F84D010D0102030201023010060B2A864886F84D010D0102040201023011060B2A864886F84D010D010205020200FF3010060B2A864886F84D010D0102060201013010060B2A864886F84D010D0102070201003010060B2A864886F84D010D0102080201003010060B2A864886F84D010D0102090201003010060B2A864886F84D010D01020A0201003010060B2A864886F84D010D01020B0201003010060B2A864886F84D010D01020C0201003010060B2A864886F84D010D01020D0201003010060B2A864886F84D010D01020E0201003010060B2A864886F84D010D01020F0201003010060B2A864886F84D010D0102100201003010060B2A864886F84D010D01021102010D301F060B2A864886F84D010D01021204100B0B0202FF01000000000000000000003010060A2A864886F84D010D0103040200003014060A2A864886F84D010D0104040600906EA10000300F060A2A864886F84D010D01050A0100";
/// Return a known-good Intel SGX extension DER payload for the mock
/// PCK cert
fn intel_sgx_extension_der() -> Vec<u8> {
    hex::decode(VALID_PCK_EXTENSION_HEX).expect("valid extension hex")
}

/// Generate the full mock PKI and collateral fixture set into the
/// target directory
fn refresh_dcap_fixtures() -> Result<(), Box<dyn std::error::Error>> {
    let output_dir = &workspace_root().join(OUTPUT_DIR);
    fs::create_dir_all(output_dir)?;

    let validity = validity_window();
    let root_params = ca_params(ROOT_CA_CN, validity.not_before, validity.not_after, 1)?;
    let root_key = key_pair_from_secret(ROOT_CA_SK)?;
    let root = CertifiedIssuer::self_signed(root_params, root_key)?;

    let tcb_ca_params = ca_params(TCB_CA_CN, validity.not_before, validity.not_after, 2)?;
    let tcb_ca_key = key_pair_from_secret(TCB_CA_SK)?;
    let tcb_ca = CertifiedIssuer::signed_by(tcb_ca_params, tcb_ca_key, &root)?;

    let tcb_signer_key = key_pair_from_secret(TCB_SIGNER_SK)?;
    let tcb_signer_params =
        end_entity_params(TCB_SIGNER_CN, validity.not_before, validity.not_after, 3)?;
    let tcb_signer = tcb_signer_params.signed_by(&tcb_signer_key, &tcb_ca)?;

    let pck_key = key_pair_from_secret(PCK_SK)?;
    let mut pck_params = end_entity_params(PCK_CN, validity.not_before, validity.not_after, 4)?;
    pck_params
        .custom_extensions
        .push(CustomExtension::from_oid_content(PCK_EXTENSION_OID, intel_sgx_extension_der()));
    let pck_cert = pck_params.signed_by(&pck_key, &root)?;
    let pck_extension = parse_pck_extension(pck_cert.der().as_ref())?;

    let root_crl = CertificateRevocationListParams {
        this_update: validity.not_before,
        next_update: validity.not_after,
        crl_number: SerialNumber::from(1_u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&root)?;
    let pck_crl = CertificateRevocationListParams {
        this_update: validity.not_before,
        next_update: validity.not_after,
        crl_number: SerialNumber::from(2_u64),
        issuing_distribution_point: None,
        revoked_certs: Vec::new(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&tcb_ca)?;

    let tcb_info = mock_tcb_info(validity.not_before, validity.not_after, &pck_extension);
    let qe_identity = mock_qe_identity(validity.not_before, validity.not_after);
    let tcb_info_json = serde_json::to_string(&tcb_info)?;
    let qe_identity_json = serde_json::to_string(&qe_identity)?;
    let tcb_signing_key = signing_key_from_secret(TCB_SIGNER_SK)?;
    let tcb_info_signature = sign_raw_p256(&tcb_signing_key, tcb_info_json.as_bytes());
    let qe_identity_signature = sign_raw_p256(&tcb_signing_key, qe_identity_json.as_bytes());

    let pck_chain_pem = format!("{}{}", pck_cert.pem(), root.pem());
    let tcb_signer_chain_pem = format!("{}{}{}", tcb_signer.pem(), tcb_ca.pem(), root.pem());

    let collateral = QuoteCollateralV3 {
        pck_crl_issuer_chain: format!("{}{}", tcb_ca.pem(), root.pem()),
        root_ca_crl: root_crl.der().to_vec(),
        pck_crl: pck_crl.der().to_vec(),
        tcb_info_issuer_chain: tcb_signer_chain_pem.clone(),
        tcb_info: tcb_info_json.clone(),
        tcb_info_signature,
        qe_identity_issuer_chain: tcb_signer_chain_pem.clone(),
        qe_identity: qe_identity_json.clone(),
        qe_identity_signature,
        pck_certificate_chain: Some(pck_chain_pem.clone()),
    };

    validate_fixture_set(
        &collateral,
        &pck_cert,
        &tcb_signer,
        &tcb_info,
        &qe_identity,
        &pck_extension,
    )?;

    let manifest = FixtureManifest {
        fmspc: hex::encode_upper(pck_extension.fmspc),
        pce_id_hex: hex::encode_upper(&pck_extension.pce_id),
        pce_svn: pck_extension.pce_svn,
        cpu_svn_hex: hex::encode_upper(pck_extension.cpu_svn),
        ppid_hex: hex::encode_upper(&pck_extension.ppid),
        qe_isvsvn: QE_ISVSVN,
        issuer_common_names: IssuerNames {
            root_ca: ROOT_CA_CN.to_string(),
            tcb_signing_ca: TCB_CA_CN.to_string(),
            tcb_signer: TCB_SIGNER_CN.to_string(),
            pck: PCK_CN.to_string(),
        },
        files: OutputFiles {
            collateral: COLLATERAL_BASENAME.to_string(),
            manifest: MANIFEST_BASENAME.to_string(),
            root_ca_der: ROOT_CA_DER_BASENAME.to_string(),
            root_ca_pem: ROOT_CA_PEM_BASENAME.to_string(),
            root_ca_key_pem: ROOT_CA_KEY_BASENAME.to_string(),
            tcb_signer_chain_pem: TCB_SIGNER_CHAIN_BASENAME.to_string(),
            pck_chain_pem: PCK_CHAIN_BASENAME.to_string(),
            pck_key_pem: PCK_KEY_BASENAME.to_string(),
            root_crl_der: ROOT_CRL_DER_BASENAME.to_string(),
            pck_crl_der: PCK_CRL_DER_BASENAME.to_string(),
            tcb_info_json: TCB_INFO_JSON_BASENAME.to_string(),
            qe_identity_json: QE_IDENTITY_JSON_BASENAME.to_string(),
        },
    };

    write(output_dir.join(COLLATERAL_BASENAME), serde_saphyr::to_string(&collateral)?)?;
    write(output_dir.join(MANIFEST_BASENAME), serde_json::to_string_pretty(&manifest)?)?;
    write(output_dir.join(ROOT_CA_DER_BASENAME), root.der().as_ref())?;
    write(output_dir.join(ROOT_CA_PEM_BASENAME), root.pem())?;
    write(
        output_dir.join(ROOT_CA_KEY_BASENAME),
        key_pair_from_secret(ROOT_CA_SK)?.serialize_pem(),
    )?;
    write(output_dir.join(TCB_SIGNER_CHAIN_BASENAME), tcb_signer_chain_pem)?;
    write(output_dir.join(PCK_CHAIN_BASENAME), pck_chain_pem)?;
    write(
        output_dir.join(PCK_KEY_BASENAME),
        SecretKey::from_slice(&PCK_SK)?.to_pkcs8_pem(Default::default())?,
    )?;
    write(output_dir.join(ROOT_CRL_DER_BASENAME), root_crl.der().as_ref())?;
    write(output_dir.join(PCK_CRL_DER_BASENAME), pck_crl.der().as_ref())?;
    write(output_dir.join(TCB_INFO_JSON_BASENAME), format!("{tcb_info_json}\n"))?;
    write(output_dir.join(QE_IDENTITY_JSON_BASENAME), format!("{qe_identity_json}\n"))?;

    Ok(())
}

/// Build mock TCB info aligned with the generated PCK extension values
fn mock_tcb_info(
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    pck_extension: &PckExtension,
) -> TcbInfo {
    TcbInfo {
        id: "TDX".to_string(),
        version: 3,
        issue_date: not_before.format(&time::format_description::well_known::Rfc3339).unwrap(),
        next_update: not_after.format(&time::format_description::well_known::Rfc3339).unwrap(),
        fmspc: hex::encode_upper(pck_extension.fmspc),
        pce_id: hex::encode_upper(&pck_extension.pce_id),
        tcb_type: 0,
        tcb_evaluation_data_number: 1,
        tcb_levels: vec![TcbLevel {
            tcb: Tcb {
                sgx_components: pck_extension
                    .cpu_svn
                    .into_iter()
                    .map(|svn| TcbComponents { svn })
                    .collect(),
                tdx_components: TDX_TCB_SVN.into_iter().map(|svn| TcbComponents { svn }).collect(),
                pce_svn: pck_extension.pce_svn,
            },
            tcb_date: not_before.format(&time::format_description::well_known::Rfc3339).unwrap(),
            tcb_status: TcbStatus::UpToDate,
            advisory_ids: Vec::new(),
        }],
    }
}

/// Verify that the generated PKI and collateral set is internally
/// consistent
fn validate_fixture_set(
    collateral: &QuoteCollateralV3,
    pck_cert: &rcgen::Certificate,
    tcb_signer: &rcgen::Certificate,
    tcb_info: &TcbInfo,
    qe_identity: &MockQeIdentity,
    pck_extension: &PckExtension,
) -> Result<(), Box<dyn std::error::Error>> {
    let parsed_pck = parse_pck_extension(pck_cert.der().as_ref())?;
    if parsed_pck.fmspc != pck_extension.fmspc {
        return Err("generated PCK FMSPC mismatch".into());
    }
    if parsed_pck.cpu_svn != pck_extension.cpu_svn {
        return Err("generated PCK CPU SVN mismatch".into());
    }
    if parsed_pck.pce_svn != pck_extension.pce_svn {
        return Err("generated PCK PCE SVN mismatch".into());
    }
    if parsed_pck.ppid != pck_extension.ppid {
        return Err("generated PCK PPID mismatch".into());
    }

    let _parsed_tcb_signer = x509_parser::parse_x509_certificate(tcb_signer.der().as_ref())
        .map_err(|_| "failed to parse generated TCB signer certificate")?;
    let parsed_collateral: QuoteCollateralV3 =
        serde_saphyr::from_str(&serde_saphyr::to_string(collateral)?)?;
    if parsed_collateral.tcb_info != collateral.tcb_info {
        return Err("collateral serialization round-trip mismatch".into());
    }

    let parsed_tcb: TcbInfo = serde_json::from_str(&collateral.tcb_info)?;
    let parsed_qe: MockQeIdentity = serde_json::from_str(&collateral.qe_identity)?;
    if parsed_tcb.fmspc != tcb_info.fmspc || parsed_qe.id != qe_identity.id {
        return Err("collateral JSON payload mismatch".into());
    }

    Ok(())
}

/// QE TCB payload carrying the mock ISV SVN
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MockQeTcb {
    isvsvn: u16,
}

/// One QE identity TCB level entry
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MockQeTcbLevel {
    tcb: MockQeTcb,
    tcb_date: String,
    tcb_status: TcbStatus,
    #[serde(rename = "advisoryIDs", default)]
    advisory_ids: Vec<String>,
}

/// Minimal QE identity shape used for serialized mock collateral
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct MockQeIdentity {
    id: String,
    version: u8,
    issue_date: String,
    next_update: String,
    tcb_evaluation_data_number: u32,
    miscselect: String,
    #[serde(rename = "miscselectMask")]
    miscselect_mask: String,
    attributes: String,
    #[serde(rename = "attributesMask")]
    attributes_mask: String,
    mrsigner: String,
    isvprodid: u16,
    tcb_levels: Vec<MockQeTcbLevel>,
}

/// Build mock QE identity collateral with stable, permissive values
fn mock_qe_identity(not_before: OffsetDateTime, not_after: OffsetDateTime) -> MockQeIdentity {
    MockQeIdentity {
        id: "TD_QE".to_string(),
        version: 2,
        issue_date: not_before.format(&time::format_description::well_known::Rfc3339).unwrap(),
        next_update: not_after.format(&time::format_description::well_known::Rfc3339).unwrap(),
        tcb_evaluation_data_number: 1,
        miscselect: hex::encode_upper(QE_MISCSELECT),
        miscselect_mask: hex::encode_upper(QE_MISCSELECT_MASK),
        attributes: hex::encode_upper(QE_ATTRIBUTES),
        attributes_mask: hex::encode_upper(QE_ATTRIBUTES_MASK),
        mrsigner: hex::encode_upper(QE_MRSIGNER),
        isvprodid: QE_ISVPRODID,
        tcb_levels: vec![MockQeTcbLevel {
            tcb: MockQeTcb { isvsvn: QE_ISVSVN },
            tcb_date: not_before.format(&time::format_description::well_known::Rfc3339).unwrap(),
            tcb_status: TcbStatus::UpToDate,
            advisory_ids: Vec::new(),
        }],
    }
}

/// Resolve the workspace root from this crate location
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir")
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Build CA certificate parameters for one mock issuer
fn ca_params(
    common_name: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    serial: u64,
) -> Result<CertificateParams, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.serial_number = Some(SerialNumber::from(serial));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::CrlSign,
    ];
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.distinguished_name.push(DnType::CommonName, common_name);
    Ok(params)
}

/// Build end-entity certificate parameters for the mock signer and PCK
/// certs
fn end_entity_params(
    common_name: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    serial: u64,
) -> Result<CertificateParams, Box<dyn std::error::Error>> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.not_before = not_before;
    params.not_after = not_after;
    params.serial_number = Some(SerialNumber::from(serial));
    params.is_ca = IsCa::ExplicitNoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.use_authority_key_identifier_extension = true;
    params.key_identifier_method = KeyIdMethod::Sha256;
    params.distinguished_name.push(DnType::CommonName, common_name);
    Ok(params)
}

/// CLI entrypoint for refreshing deterministic mock DCAP fixtures
fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("refresh-dcap-fixtures") => {
            refresh_dcap_fixtures()?;
        }
        Some(other) => {
            eprintln!("Unknown command: {other}");
            eprintln!("Usage: cargo run -p mock-tdx -- refresh-dcap-fixtures");
            std::process::exit(2);
        }
        None => {
            eprintln!("Usage: cargo run -p mock-tdx -- refresh-dcap-fixtures");
            std::process::exit(2);
        }
    }

    Ok(())
}
