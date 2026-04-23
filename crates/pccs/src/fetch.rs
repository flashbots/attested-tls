//! HTTP layer for DCAP collateral retrieval from PCCS or Intel PCS.
//!
//! `dcap-qvl` 0.4 demoted the fmspc-keyed collateral API to `pub(crate)`
//! and exposes only [`CollateralClient::fetch(&quote)`]. Our cache is keyed
//! on `(fmspc, ca)` and runs before any quote is available (startup
//! pre-warm and background refresh), so we reimplement the well-known PCCS
//! HTTP protocol locally.
//!
//! The `tcbInfo` and `enclaveIdentity` fields are deserialised through
//! [`serde_json::value::RawValue`] so the exact bytes Intel signed survive
//! into [`QuoteCollateralV3`] regardless of which serde_json `Map` backing
//! ends up selected. Phala's upstream fetcher uses a plain
//! [`serde_json::Value`] and relies on the `preserve_order` feature being
//! enabled on `serde_json` (which dcap-qvl requests, and Cargo feature
//! unification then extends to every dependent crate). `RawValue` removes
//! that dependency on workspace-level feature flags.

use dcap_qvl::{QuoteCollateralV3, quote::EncryptedPpidParams};
use serde_json::value::RawValue;
use x509_parser::{
    certificate::X509Certificate,
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    pem::Pem,
    prelude::FromDer,
};

use crate::{PCS_URL, PccsError};

/// Fetches TDX collateral (PCK CRL, TCB info, QE identity, root CA CRL) for
/// a given FMSPC / CA pair.
pub(super) async fn fetch_collateral(
    client: &reqwest::Client,
    url: &str,
    fmspc: String,
    ca: &'static str,
) -> Result<QuoteCollateralV3, PccsError> {
    let endpoints = PcsEndpoints::new(url, false, fmspc, ca);

    let response = checked_get(client, &endpoints.url_pckcrl()).await?;
    let pck_crl_issuer_chain = get_header(&response, "SGX-PCK-CRL-Issuer-Chain")?;
    let pck_crl = response.bytes().await?.to_vec();

    let response = checked_get(client, &endpoints.url_tcb()).await?;
    let tcb_info_issuer_chain = get_header(&response, "SGX-TCB-Info-Issuer-Chain")
        .or_else(|_| get_header(&response, "TCB-Info-Issuer-Chain"))?;
    let raw_tcb_info = response.text().await?;

    let response = checked_get(client, &endpoints.url_qe_identity()).await?;
    let qe_identity_issuer_chain = get_header(&response, "SGX-Enclave-Identity-Issuer-Chain")?;
    let raw_qe_identity = response.text().await?;

    let root_ca_crl = fetch_root_ca_crl(client, &endpoints, &qe_identity_issuer_chain).await?;

    let tcb_resp: TcbInfoResponse<'_> = serde_json::from_str(&raw_tcb_info)
        .map_err(|e| PccsError::PccsCollateralParse(format!("TCB info response JSON: {e}")))?;
    let tcb_info = tcb_resp.tcb_info.get().to_owned();
    let tcb_info_signature = hex::decode(&tcb_resp.signature).map_err(|e| {
        PccsError::PccsCollateralParse(format!("TCB info signature is not valid hex: {e}"))
    })?;

    let qe_resp: QeIdentityResponse<'_> = serde_json::from_str(&raw_qe_identity)
        .map_err(|e| PccsError::PccsCollateralParse(format!("QE identity response JSON: {e}")))?;
    let qe_identity = qe_resp.enclave_identity.get().to_owned();
    let qe_identity_signature = hex::decode(&qe_resp.signature).map_err(|e| {
        PccsError::PccsCollateralParse(format!("QE identity signature is not valid hex: {e}"))
    })?;

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info,
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity,
        qe_identity_signature,
        pck_certificate_chain: None,
    })
}

/// Fetches the quote-specific PCK certificate chain from PCCS / PCS for
/// quotes whose certification data does not embed it.
pub(super) async fn fetch_pck_certificate(
    client: &reqwest::Client,
    pccs_url: &str,
    qeid: &[u8],
    params: &EncryptedPpidParams,
) -> Result<String, PccsError> {
    let qeid = hex::encode_upper(qeid);
    let encrypted_ppid = hex::encode_upper(&params.encrypted_ppid);
    let cpusvn = hex::encode_upper(params.cpusvn);
    let pcesvn = hex::encode_upper(params.pcesvn.to_le_bytes());
    let pceid = hex::encode_upper(params.pceid);

    let base_url = pccs_url
        .trim_end_matches('/')
        .trim_end_matches("/sgx/certification/v4")
        .trim_end_matches("/tdx/certification/v4");
    let url = format!(
        "{base_url}/sgx/certification/v4/pckcert?qeid={qeid}&encrypted_ppid={encrypted_ppid}&cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}"
    );
    let response = checked_get(client, &url).await?;

    if let Some(tcbm) = response.headers().get("SGX-TCBm") {
        let tcbm_str = tcbm.to_str().map_err(|e| {
            PccsError::PccsCollateralParse(format!(
                "SGX-TCBm header contains invalid characters: {e}"
            ))
        })?;
        let tcbm_bytes = hex::decode(tcbm_str).map_err(|e| {
            PccsError::PccsCollateralParse(format!("SGX-TCBm header is not valid hex: {e}"))
        })?;
        if tcbm_bytes.len() < 18 {
            return Err(PccsError::PccsCollateralParse(
                "SGX-TCBm header too short: expected 18 bytes".to_string(),
            ));
        }
        let matched_cpusvn = <[u8; 16]>::try_from(&tcbm_bytes[..16]).map_err(|_| {
            PccsError::PccsCollateralParse(
                "Failed to parse cpusvn from SGX-TCBm header".to_string(),
            )
        })?;
        let matched_pcesvn = u16::from_le_bytes([tcbm_bytes[16], tcbm_bytes[17]]);
        if matched_cpusvn != params.cpusvn || matched_pcesvn != params.pcesvn {
            return Err(PccsError::PccsFetch(format!(
                "TCB level mismatch: platform TCB (cpusvn={}, pcesvn={}) matched lower registered TCB (cpusvn={}, pcesvn={})",
                hex::encode(params.cpusvn),
                params.pcesvn,
                hex::encode(matched_cpusvn),
                matched_pcesvn
            )));
        }
    }

    let pck_cert_chain = get_header(&response, "SGX-PCK-Certificate-Issuer-Chain")?;
    let pck_cert = response.text().await?;
    Ok(format!("{pck_cert}\n{pck_cert_chain}"))
}

/// TCB info envelope. `tcb_info` is borrowed as [`RawValue`] so the exact
/// bytes Intel signed round-trip into [`QuoteCollateralV3::tcb_info`].
#[derive(serde::Deserialize)]
struct TcbInfoResponse<'a> {
    #[serde(rename = "tcbInfo", borrow)]
    tcb_info: &'a RawValue,
    signature: String,
}

/// QE identity envelope. Same byte-preservation constraint as
/// [`TcbInfoResponse`].
#[derive(serde::Deserialize)]
struct QeIdentityResponse<'a> {
    #[serde(rename = "enclaveIdentity", borrow)]
    enclave_identity: &'a RawValue,
    signature: String,
}

/// PCCS / PCS endpoint builder. Centralises the `/{tee}/certification/v4/…`
/// path construction so individual call sites stay readable.
struct PcsEndpoints {
    base_url: String,
    tee: &'static str,
    fmspc: String,
    ca: String,
}

impl PcsEndpoints {
    fn new(base_url: &str, for_sgx: bool, fmspc: String, ca: &str) -> Self {
        let tee = if for_sgx { "sgx" } else { "tdx" };
        let base_url = base_url
            .trim_end_matches('/')
            .trim_end_matches("/sgx/certification/v4")
            .trim_end_matches("/tdx/certification/v4")
            .to_owned();
        Self { base_url, tee, fmspc, ca: ca.to_owned() }
    }

    fn is_pcs(&self) -> bool {
        self.base_url.starts_with(PCS_URL)
    }

    fn url_pckcrl(&self) -> String {
        self.mk_url("sgx", &format!("pckcrl?ca={}&encoding=der", self.ca))
    }

    fn url_rootcacrl(&self) -> String {
        self.mk_url("sgx", "rootcacrl")
    }

    fn url_tcb(&self) -> String {
        self.mk_url(self.tee, &format!("tcb?fmspc={}", self.fmspc))
    }

    fn url_qe_identity(&self) -> String {
        self.mk_url(self.tee, "qe/identity?update=standard")
    }

    fn mk_url(&self, tee: &str, path: &str) -> String {
        format!("{}/{}/certification/v4/{}", self.base_url, tee, path)
    }
}

/// Reads and URL-decodes a required PCCS response header.
fn get_header(response: &reqwest::Response, name: &str) -> Result<String, PccsError> {
    let value = response.headers().get(name).ok_or_else(|| {
        PccsError::PccsCollateralParse(format!("Missing required response header: {name}"))
    })?;
    let value = value.to_str().map_err(|e| {
        PccsError::PccsCollateralParse(format!(
            "Response header {name} contains invalid characters: {e}"
        ))
    })?;
    urlencoding::decode(value).map(|decoded| decoded.into_owned()).map_err(|e| {
        PccsError::PccsCollateralParse(format!("Failed to URL-decode response header {name}: {e}"))
    })
}

/// GETs a URL and rejects non-2xx responses.
async fn checked_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response, PccsError> {
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(PccsError::PccsFetch(format!("Failed to fetch {url}: {}", response.status())));
    }
    Ok(response)
}

/// GETs a URL and returns the body bytes.
async fn http_get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, PccsError> {
    Ok(checked_get(client, url).await?.bytes().await?.to_vec())
}

/// Fetches the Intel SGX root CA CRL.
///
/// PCCS caches expose a convenience `/sgx/certification/v4/rootcacrl`
/// endpoint (hex-encoded DER). Intel PCS does not, so for PCS we fall back
/// to extracting the CRL distribution point URI from the root certificate
/// at the end of the QE identity issuer chain.
async fn fetch_root_ca_crl(
    client: &reqwest::Client,
    endpoints: &PcsEndpoints,
    qe_identity_issuer_chain: &str,
) -> Result<Vec<u8>, PccsError> {
    if !endpoints.is_pcs() &&
        let Ok(root_ca_crl_hex) = http_get_bytes(client, &endpoints.url_rootcacrl()).await
    {
        let hex_str = std::str::from_utf8(&root_ca_crl_hex).map_err(|e| {
            PccsError::PccsCollateralParse(format!("Failed to convert root CA CRL to UTF-8: {e}"))
        })?;
        let root_ca_crl = hex::decode(hex_str).map_err(|e| {
            PccsError::PccsCollateralParse(format!("Failed to decode hex-encoded root CA CRL: {e}"))
        })?;
        return Ok(root_ca_crl);
    }

    let root_cert_der = extract_last_pem_certificate(qe_identity_issuer_chain.as_bytes())?;
    let crl_url = extract_crl_distribution_point(&root_cert_der)?;
    http_get_bytes(client, &crl_url).await
}

fn extract_last_pem_certificate(pem_chain: &[u8]) -> Result<Vec<u8>, PccsError> {
    let mut last_certificate = None;
    for item in Pem::iter_from_buffer(pem_chain) {
        let pem = item.map_err(|e| {
            PccsError::PccsCollateralParse(format!("Failed to parse PEM in issuer chain: {e}"))
        })?;
        if pem.label == "CERTIFICATE" {
            last_certificate = Some(pem.contents);
        }
    }
    last_certificate.ok_or_else(|| {
        PccsError::PccsCollateralParse("No certificate found in issuer chain".to_string())
    })
}

fn extract_crl_distribution_point(cert_der: &[u8]) -> Result<String, PccsError> {
    let (_, cert) = X509Certificate::from_der(cert_der).map_err(|e| {
        PccsError::PccsCollateralParse(format!("Failed to parse root certificate: {e}"))
    })?;
    for extension in cert.extensions() {
        if let ParsedExtension::CRLDistributionPoints(points) = extension.parsed_extension() {
            for point in points.iter() {
                let Some(distribution_point) = &point.distribution_point else {
                    continue;
                };
                let DistributionPointName::FullName(names) = distribution_point else {
                    continue;
                };
                for name in names.iter() {
                    if let GeneralName::URI(uri) = name {
                        return Ok(uri.to_string());
                    }
                }
            }
        }
    }
    Err(PccsError::PccsCollateralParse(
        "Could not find CRL distribution point in root certificate".to_string(),
    ))
}
