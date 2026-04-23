use dcap_qvl::QuoteCollateralV3;
use x509_parser::{
    certificate::X509Certificate,
    extensions::{DistributionPointName, GeneralName, ParsedExtension},
    pem::Pem,
    prelude::FromDer,
};

use crate::{PCS_URL, PccsError};

/// Fetches collateral from PCCS for a given FMSPC and CA
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

    let tcb_info_resp: TcbInfoResponse = serde_json::from_str(&raw_tcb_info).map_err(|e| {
        PccsError::PccsCollateralParse(format!("TCB Info should be valid JSON: {e}"))
    })?;
    let tcb_info_signature = hex::decode(&tcb_info_resp.signature).map_err(|e| {
        PccsError::PccsCollateralParse(format!("TCB Info signature must be valid hex: {e}"))
    })?;

    let qe_identity_resp: QeIdentityResponse =
        serde_json::from_str(&raw_qe_identity).map_err(|e| {
            PccsError::PccsCollateralParse(format!("QE Identity should be valid JSON: {e}"))
        })?;
    let qe_identity_signature = hex::decode(&qe_identity_resp.signature).map_err(|e| {
        PccsError::PccsCollateralParse(format!("QE Identity signature must be valid hex: {e}"))
    })?;

    Ok(QuoteCollateralV3 {
        pck_crl_issuer_chain,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        tcb_info: tcb_info_resp.tcb_info.to_string(),
        tcb_info_signature,
        qe_identity_issuer_chain,
        qe_identity: qe_identity_resp.enclave_identity.to_string(),
        qe_identity_signature,
        pck_certificate_chain: None,
    })
}

/// Minimal shape of a TCB info response from PCCS/PCS
#[derive(Debug, serde::Deserialize)]
struct TcbInfoResponse {
    #[serde(rename = "tcbInfo")]
    tcb_info: serde_json::Value,
    signature: String,
}

/// Minimal shape of a QE identity response from PCCS/PCS
#[derive(Debug, serde::Deserialize)]
struct QeIdentityResponse {
    #[serde(rename = "enclaveIdentity")]
    enclave_identity: serde_json::Value,
    signature: String,
}

/// PCCS/PCS URLs derived from a base URL, CA, and TEE type
struct PcsEndpoints {
    base_url: String,
    tee: &'static str,
    fmspc: String,
    ca: String,
}

impl PcsEndpoints {
    /// Builds the PCCS/PCS endpoint set for a given FMSPC and CA
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

/// Reads and URL-decodes a required response header
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

/// Sends a GET request and rejects non-success status codes
async fn checked_get(client: &reqwest::Client, url: &str) -> Result<reqwest::Response, PccsError> {
    let response = client.get(url).send().await?;
    if !response.status().is_success() {
        return Err(PccsError::PccsFetch(format!("Failed to fetch {url}: {}", response.status())));
    }
    Ok(response)
}

/// Fetches a URL and returns the response body as bytes
async fn http_get_bytes(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, PccsError> {
    Ok(checked_get(client, url).await?.bytes().await?.to_vec())
}

/// Fetches the root CA CRL from PCCS or falls back to the issuer-chain CRL
/// URL
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

/// Extracts the last certificate from a PEM issuer chain
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

/// Extracts the first CRL distribution point URI from a root certificate
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
