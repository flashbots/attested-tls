//! Generation of Microsoft Azure vTPM attestation evidence on an Azure TDX
//! CVM: reads the HCL report and quote from the vTPM, fetches the TDX quote
//! from the IMDS, and follows the AK certificate's AIA URLs to include the
//! observed issuer intermediates in the evidence.
mod nv_index;

use std::{io::Read, time::Duration};

use az_cvm_vtpm::hcl;
use az_tdx_vtpm::{imds, vtpm};
use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};
use reqwest::header::CONTENT_TYPE;
use x509_parser::{extensions::GeneralName, prelude::*};

use super::{
    AttestationDocument,
    MAX_EVIDENCE_AK_INTERMEDIATE_CERTIFICATES,
    MaaError,
    TpmAttest,
    ak_certificate::verify_ak_cert_with_azure_roots,
    ensure_azure_attestation_payload_size,
    tpm_quote::TpmQuote,
};

/// Used in attestation type detection to check if we are on Azure
const AZURE_METADATA_API: &str = "http://169.254.169.254/metadata/instance";

/// The NV index where we expect to be able to read the AK certificate from
/// the vTPM
const TPM_AK_CERT_IDX: u32 = 0x1C101D0;

/// id-ad-caIssuers access method OID used in X.509 Authority Information
/// Access extensions to point to issuer certificate URLs.
///
/// Defined by RFC 5280 as `{ id-ad 2 }`, where `id-ad` is
/// `1.3.6.1.5.5.7.48`. https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1
const AIA_CA_ISSUERS_ACCESS_METHOD_OID: &str = "1.3.6.1.5.5.7.48.2";

/// Generate a TDX attestation on Azure.
///
/// This may perform network calls. Azure's IMDS is queried for the TDX
/// quote, and the vTPM AK certificate's Authority Information Access (AIA)
/// CA Issuers URLs are followed to include the observed issuer
/// intermediates in the evidence.
///
/// The intermediates are included as untrusted evidence so verifiers do not
/// need network access or AIA-fetching logic. This keeps verification
/// deterministic and easier to reuse in constrained verifier environments
/// such as TEEs, onchain verification, or zero-knowledge proof generation.
pub fn create_azure_attestation(input_data: [u8; 64]) -> Result<Vec<u8>, MaaError> {
    let hcl_report_bytes = vtpm::get_report_with_report_data(&input_data)?;

    let hcl = hcl::HclReport::new(hcl_report_bytes.clone())?;

    let td_report_from_hcl = hcl.try_into()?;

    // This makes a request to Azure Instance metadata service and gives us
    // a binary response
    let td_quote_bytes = imds::get_td_quote(&td_report_from_hcl)?;

    let ak_certificate_der = read_ak_certificate_from_tpm()?;
    let (remaining_bytes, ak_leaf_certificate) = X509Certificate::from_der(&ak_certificate_der)?;
    let leaf_len = ak_certificate_der.len() - remaining_bytes.len();
    let ak_leaf_certificate_der = &ak_certificate_der[..leaf_len];
    let now_secs = unix_time_now_secs()?;
    let ak_intermediate_certificates_der =
        fetch_ak_intermediates_from_aia(ak_leaf_certificate_der, &ak_leaf_certificate, now_secs)?;

    let tpm_attestation = TpmAttest {
        ak_certificate_pem: pem_rfc7468::encode_string(
            "CERTIFICATE",
            pem_rfc7468::LineEnding::default(),
            ak_leaf_certificate_der,
        )?,
        ak_intermediate_certificates_pem: ak_intermediate_certificates_der
            .iter()
            .map(|der| {
                pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::default(), der)
            })
            .collect::<Result<Vec<_>, _>>()?,
        quote: (&vtpm::get_quote(&input_data[..32])?).try_into()?,
        event_log: Vec::new(),
        instance_info: None,
    };

    let attestation_document = AttestationDocument {
        tdx_quote_base64: BASE64_URL_SAFE.encode(&td_quote_bytes),
        hcl_report_base64: BASE64_URL_SAFE.encode(&hcl_report_bytes),
        tpm_attestation,
    };

    tracing::info!("Successfully generated azure attestation: {attestation_document:?}");
    let attestation_json = serde_json::to_vec(&attestation_document)?;
    // If this ever fails, then we have a problem and probably just need to
    // increase MAX_AZURE_ATTESTATION_PAYLOAD_SIZE
    ensure_azure_attestation_payload_size(&attestation_json)?;
    Ok(attestation_json)
}

/// Detect whether we are on Azure and can make an Azure vTPM attestation
pub fn detect_azure_cvm() -> Result<bool, MaaError> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_millis(200)).build();
    let resp = match agent.get(AZURE_METADATA_API).set("Metadata", "true").call() {
        Ok(resp) => resp,
        Err(err) => {
            tracing::debug!("Azure CVM detection failed: Azure metadata API request failed: {err}");
            return Ok(false);
        }
    };

    if resp.status() != 200 {
        tracing::debug!(
            "Azure CVM detection failed: metadata API returned non-success status: {}",
            resp.status()
        );
        return Ok(false);
    }

    // Ensure the response has a JSON content type
    let content_type = resp
        .header(CONTENT_TYPE.as_str())
        .map(|value| value.to_owned())
        .ok_or_else(|| MaaError::AzureMetadataApiNonJsonResponse { content_type: None })?;

    if !content_type.to_lowercase().starts_with("application/json") {
        return Err(MaaError::AzureMetadataApiNonJsonResponse { content_type: Some(content_type) });
    }

    match az_tdx_vtpm::is_tdx_cvm() {
        Ok(true) => Ok(true),
        Ok(false) => {
            tracing::debug!("Azure CVM detection failed: platform is not an Azure TDX CVM");
            Ok(false)
        }
        Err(err) => {
            tracing::debug!("Azure CVM detection failed: Azure TDX CVM probe failed: {err}");
            Ok(false)
        }
    }
}

/// Conversion from the quote type returned by the vTPM during evidence
/// generation. Going through the serde wire format guarantees the two
/// types serialize identically.
impl TryFrom<&vtpm::Quote> for TpmQuote {
    type Error = serde_json::Error;

    fn try_from(quote: &vtpm::Quote) -> Result<Self, Self::Error> {
        serde_json::from_value(serde_json::to_value(quote)?)
    }
}

fn unix_time_now_secs() -> Result<u64, MaaError> {
    Ok(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs())
}

/// Fetch intermediate certificates from the Authority Information Access
/// (AIA) CA Issuers URLs in the leaf and each fetched intermediate.
///
/// Azure vTPM AK intermediate CAs rotate and the public Trusted Launch FAQ
/// can lag behind the certificates observed in production. Microsoft
/// guidance is to build the chain from the CA Issuers URLs embedded in the
/// AK certificate's AIA extension; see:
/// https://learn.microsoft.com/en-us/answers/questions/5897616/download-intermediate-ca-cert-for-azure-cloud-virt
///
/// The fetched certificates are untrusted evidence. We stop as soon as the
/// fetched chain verifies against pinned Azure roots.
fn fetch_ak_intermediates_from_aia(
    ak_cert_der: &[u8],
    ak_cert: &X509Certificate<'_>,
    now_secs: u64,
) -> Result<Vec<Vec<u8>>, MaaError> {
    let mut intermediates = Vec::new();
    if verify_ak_cert_with_azure_roots(ak_cert_der, &intermediates, now_secs).is_ok() {
        return Ok(intermediates);
    }

    let mut issuer_urls = ca_issuers_urls(ak_cert);

    while !issuer_urls.is_empty() {
        let fetched_issuer = fetch_first_available_issuer(&issuer_urls)?;

        issuer_urls = fetched_issuer.ca_issuers_urls;
        intermediates.push(fetched_issuer.der);

        if verify_ak_cert_with_azure_roots(ak_cert_der, &intermediates, now_secs).is_ok() {
            return Ok(intermediates);
        } else if intermediates.len() == MAX_EVIDENCE_AK_INTERMEDIATE_CERTIFICATES {
            return Err(MaaError::AkIssuerChainTooDeep {
                max_depth: MAX_EVIDENCE_AK_INTERMEDIATE_CERTIFICATES,
            });
        }
    }

    Err(MaaError::AkIssuerChainIncomplete)
}

struct FetchedIssuer {
    der: Vec<u8>,
    ca_issuers_urls: Vec<String>,
}

fn fetch_first_available_issuer(urls: &[String]) -> Result<FetchedIssuer, MaaError> {
    let mut last_error = None;

    for url in urls {
        match fetch_issuer(url) {
            Ok(issuer) => return Ok(issuer),
            Err(err) => {
                tracing::debug!(
                    "Failed to fetch Azure vTPM AK issuer certificate from {url}: {err}"
                );
                last_error = Some(err);
            }
        }
    }

    Err(last_error.unwrap_or(MaaError::AkIssuerChainIncomplete))
}

fn fetch_issuer(url: &str) -> Result<FetchedIssuer, MaaError> {
    tracing::debug!("Fetching Azure vTPM AK issuer certificate from {url}");
    let der = fetch_certificate_der(url)?;
    let (remaining_bytes, cert) = X509Certificate::from_der(&der)?;
    let cert_len = der.len() - remaining_bytes.len();
    let ca_issuers_urls = ca_issuers_urls(&cert);

    Ok(FetchedIssuer { der: der[..cert_len].to_vec(), ca_issuers_urls })
}

/// Retrieve an AK certificate from the vTPM
fn read_ak_certificate_from_tpm() -> Result<Vec<u8>, tss_esapi::Error> {
    tracing::debug!("Reading AK certificate from vTPM");
    let mut context = nv_index::get_session_context()?;
    nv_index::read_nv_index(&mut context, TPM_AK_CERT_IDX)
}

fn ca_issuers_urls(cert: &X509Certificate<'_>) -> Vec<String> {
    cert.extensions()
        .iter()
        .filter_map(|extension| {
            let ParsedExtension::AuthorityInfoAccess(aia) = extension.parsed_extension() else {
                return None;
            };

            Some(aia.iter().filter_map(|desc| {
                if desc.access_method.to_id_string() != AIA_CA_ISSUERS_ACCESS_METHOD_OID {
                    return None;
                }

                let GeneralName::URI(uri) = &desc.access_location else {
                    return None;
                };

                Some((*uri).to_string())
            }))
        })
        .flatten()
        .collect()
}

fn fetch_certificate_der(url: &str) -> Result<Vec<u8>, MaaError> {
    #[cfg(test)]
    crate::install_test_crypto_provider();

    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(MaaError::UnsupportedAiaUrl { url: url.to_string() });
    }

    let response = ureq::get(url)
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|err| MaaError::AiaFetch { url: url.to_string(), source: Box::new(err) })?;

    let mut bytes = Vec::new();
    response.into_reader().take(1024 * 1024).read_to_end(&mut bytes)?;

    // RFC 5280 id-ad-caIssuers HTTP URLs are expected to serve DER-encoded
    // certificates. Accept explicit PEM armor as a lenient fallback for
    // endpoints that serve PEM anyway.
    if bytes.starts_with(b"-----BEGIN") {
        let (_type_label, der) = pem_rfc7468::decode_vec(&bytes)?;
        Ok(der)
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod test_utils {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};

    use super::{super::AttestationDocument, create_azure_attestation};
    use crate::dcap::PCS_URL;

    /// Capture a complete Azure TDX attestation fixture from inside an
    /// Azure TDX CVM.
    ///
    /// Run with:
    ///
    /// ```text
    /// cargo test -p attestation --features azure-attester capture_azure_fixture -- --ignored --nocapture
    /// ```
    ///
    /// This writes two timestamped YAML files:
    ///
    /// - `azure-tdx-with-ak-intermediates-<timestamp>.yaml`
    /// - `azure-collateral-with-ak-intermediates-<timestamp>.yaml`
    ///
    /// The first file is the full Azure attestation payload, including
    /// observed vTPM AK intermediate certificates. The second file is
    /// matching Intel DCAP collateral for the TDX quote embedded in
    /// that payload, so the fixture can be verified offline by tests.
    #[tokio::test]
    #[ignore = "requires an Azure TDX CVM with vTPM access"]
    async fn capture_azure_fixture() {
        let output_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("test-assets");
        std::fs::create_dir_all(&output_dir).unwrap();

        // Keep this aligned with existing Azure fixture tests, which use
        // zeroed report input data.
        let attestation_json = create_azure_attestation([0u8; 64]).unwrap();
        let attestation_document: AttestationDocument =
            serde_json::from_slice(&attestation_json).unwrap();

        let intermediate_count =
            attestation_document.tpm_attestation.ak_intermediate_certificates_pem.len();
        assert!(intermediate_count > 0, "captured attestation should include AK intermediates");

        let quote_bytes = BASE64_URL_SAFE.decode(&attestation_document.tdx_quote_base64).unwrap();
        let quote = dcap_qvl::quote::Quote::parse(&quote_bytes).unwrap();
        let ca = dcap_qvl::intel::quote_ca(&quote).unwrap().as_id_str();
        let fmspc = hex::encode_upper(dcap_qvl::intel::quote_fmspc(&quote).unwrap());
        let collateral = dcap_qvl::collateral::CollateralClient::with_default_http(PCS_URL)
            .unwrap()
            .fetch_for_fmspc_without_pck_chain(&fmspc, ca, false)
            .await
            .unwrap();

        let timestamp =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let attestation_path =
            output_dir.join(format!("azure-tdx-with-ak-intermediates-{timestamp}.yaml"));
        let collateral_path =
            output_dir.join(format!("azure-collateral-with-ak-intermediates-{timestamp}.yaml"));

        let mut serializer_options = serde_saphyr::SerializerOptions::default();
        // With compact list indentation enabled, serde_saphyr can emit an
        // indentless empty sequence after a nested block sequence, e.g.
        // `event_log:\n[]`, which its parser rejects. Disable compact list
        // indentation for fixture output so nested/empty sequences are
        // always indented under their mapping keys.
        serializer_options.compact_list_indent = false;
        std::fs::write(
            &attestation_path,
            serde_saphyr::to_string_with_options(&attestation_document, serializer_options)
                .unwrap(),
        )
        .unwrap();
        std::fs::write(&collateral_path, serde_saphyr::to_string(&collateral).unwrap()).unwrap();

        println!("wrote {}", attestation_path.display());
        println!("wrote {}", collateral_path.display());
        println!("quote fmspc={fmspc} ca={ca}");
        println!("ak_intermediate_certificates_pem entries={intermediate_count}");
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
        time::Duration,
    };

    use super::{super::ak_certificate::AZURE_VIRTUAL_TPM_ROOT_2023, *};

    /// The pure-Rust TPMS_ATTEST parser must agree with tss-esapi's
    /// unmarshalling on a real Azure vTPM quote.
    #[test]
    fn tpms_attest_parser_matches_tss_esapi() {
        use tss_esapi::{
            structures::{Attest, AttestInfo},
            traits::UnMarshall,
        };

        use crate::azure::tpms_attest::TpmsAttest;

        let fixture: &[u8] =
            include_bytes!("../../../test-assets/azure-tdx-with-ak-intermediates-1780922561.yaml");
        let document: serde_json::Value = serde_saphyr::from_slice(fixture).unwrap();
        let message: Vec<u8> =
            serde_json::from_value(document["tpm_attestation"]["quote"]["message"].clone())
                .unwrap();

        let attest = Attest::unmarshall(&message).unwrap();
        let AttestInfo::Quote { info } = attest.attested() else {
            panic!("fixture attestation is not a quote");
        };

        let parsed = TpmsAttest::parse(&message).unwrap();
        assert_eq!(parsed.extra_data(), attest.extra_data().as_slice());
        assert_eq!(parsed.pcr_digest(), info.pcr_digest().as_slice());

        // The selection decides which register each PCR value is attributed
        // to, so it is cross-checked as well. `PcrSlot` is a bit flag, so a
        // register's number is the position of its one bit. Sorted, because
        // agreement on the set is the claim being tested; our own ascending
        // order is pinned by the tests in `tpms_attest`.
        let mut tss_registers: Vec<u32> = info
            .pcr_selection()
            .get_selections()
            .iter()
            .flat_map(|selection| selection.selected())
            .map(|slot| (slot as u32).trailing_zeros())
            .collect();
        tss_registers.sort_unstable();
        assert_eq!(parsed.selected_pcrs(), tss_registers.as_slice());
    }

    #[test]
    fn fetch_first_available_issuer_tries_later_urls_after_failure() {
        let (_type_label, root_der) =
            pem_rfc7468::decode_vec(AZURE_VIRTUAL_TPM_ROOT_2023.as_bytes()).unwrap();
        let server_url = spawn_test_http_server(vec![
            ("/primary.cer", 500, b"unavailable".to_vec()),
            ("/secondary.cer", 200, root_der.clone()),
        ]);

        let fetched = fetch_first_available_issuer(&[
            format!("{server_url}/primary.cer"),
            format!("{server_url}/secondary.cer"),
        ])
        .unwrap();

        assert_eq!(fetched.der, root_der);
    }

    #[test]
    fn fetch_certificate_der_accepts_explicit_pem() {
        let (_type_label, root_der) =
            pem_rfc7468::decode_vec(AZURE_VIRTUAL_TPM_ROOT_2023.as_bytes()).unwrap();
        let server_url = spawn_test_http_server(vec![(
            "/root.pem",
            200,
            AZURE_VIRTUAL_TPM_ROOT_2023.as_bytes().to_vec(),
        )]);

        let fetched_der = fetch_certificate_der(&format!("{server_url}/root.pem")).unwrap();

        assert_eq!(fetched_der, root_der);
    }

    fn spawn_test_http_server(routes: Vec<(&'static str, u16, Vec<u8>)>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        thread::spawn(move || {
            for _ in 0..routes.len() {
                let (mut stream, _peer) = listener.accept().unwrap();
                stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

                let mut request = [0u8; 4096];
                let bytes_read = stream.read(&mut request).unwrap();
                let request = String::from_utf8_lossy(&request[..bytes_read]);
                let path = request_path(&request);

                let (status, body) = route_response(&routes, path);
                write_http_response(&mut stream, status, body);
            }
        });

        format!("http://{address}")
    }

    fn request_path(request: &str) -> &str {
        // HTTP/1.1 request line format is: `<method> <request-target>
        // <version>`. The local test server only needs the request
        // target, e.g. `/root.pem`.
        request.lines().next().and_then(|line| line.split_ascii_whitespace().nth(1)).unwrap_or("/")
    }

    fn route_response<'a>(
        routes: &'a [(&'static str, u16, Vec<u8>)],
        path: &str,
    ) -> (u16, &'a [u8]) {
        routes
            .iter()
            .find(|(route_path, _status, _body)| *route_path == path)
            .map_or((404, b"not found".as_slice()), |(_route_path, status, body)| {
                (*status, body.as_slice())
            })
    }

    fn write_http_response(stream: &mut impl Write, status: u16, body: &[u8]) {
        let headers = format!(
            "HTTP/1.1 {status} {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            status_text(status),
            body.len()
        );
        stream.write_all(headers.as_bytes()).unwrap();
        stream.write_all(body).unwrap();
    }

    fn status_text(status: u16) -> &'static str {
        match status {
            200 => "OK",
            500 => "Internal Server Error",
            _ => "Not Found",
        }
    }
}
