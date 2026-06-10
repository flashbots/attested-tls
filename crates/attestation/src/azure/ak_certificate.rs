//! Generation and verification of AK certificates from the vTPM
use std::{io::Read, time::Duration};

use once_cell::sync::Lazy;
use tokio_rustls::rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::EndEntityCert;
use x509_parser::{extensions::GeneralName, prelude::*};

use crate::azure::{MAX_EVIDENCE_AK_INTERMEDIATE_CERTIFICATES, MaaError, nv_index};

/// The NV index where we expect to be able to read the AK certificate from
/// the vTPM
const TPM_AK_CERT_IDX: u32 = 0x1C101D0;

/// id-ad-caIssuers access method OID used in X.509 Authority Information
/// Access extensions to point to issuer certificate URLs.
///
/// Defined by RFC 5280 as `{ id-ad 2 }`, where `id-ad` is
/// `1.3.6.1.5.5.7.48`. https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.2.1
const AIA_CA_ISSUERS_ACCESS_METHOD_OID: &str = "1.3.6.1.5.5.7.48.2";

// microsoftRSADevicesRoot2021 is the root CA certificate used to sign Azure
// TDX vTPM certificates. This is different from the AME root CA used by
// TrustedLaunch VMs. The certificate can be downloaded from:
// http://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Devices%20Root%20CA%202021.crt
const MICROSOFT_RSA_DEVICES_ROOT_2021: &str =
    include_str!("../../assets/microsoft-rsa-devices-root-ca-2021.pem");

// azureVirtualTPMRoot2023 is the root CA for Azure vTPM (used by both
// Trusted Launch and TDX) Source: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
// Valid until: 2048-06-01
const AZURE_VIRTUAL_TPM_ROOT_2023: &str =
    include_str!("../../assets/azure-virtual-tpm-root-2023.pem");

// globalVirtualTPMCA03 is the intermediate CA that issues TDX vTPM AK
// certificates Source: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
// Issuer: Azure Virtual TPM Root Certificate Authority 2023
// Valid: 2025-04-24 to 2027-04-24
const GLOBAL_VIRTUAL_TPMCA03_PEM: &str = include_str!("../../assets/global-virtual-tpm-ca-03.pem");

/// Legacy Azure intermediate certificates bundled with this crate.
///
/// Deprecated verification-only fallback: this is kept only for backwards
/// compatibility with older evidence that did not serialize AIA-fetched
/// intermediates. New Azure vTPM evidence should carry the AK issuer chain
/// fetched from AIA instead of relying on this bundled, eventually-stale
/// list.
///
/// Do not use this when generating new evidence or when deciding whether an
/// AIA-fetched issuer chain is complete. It should be removed once
/// supporting legacy evidence without `ak_intermediate_certificates_pem` is
/// no longer required.
static LEGACY_BUNDLED_AZURE_INTERMEDIATES: Lazy<Vec<CertificateDer<'static>>> = Lazy::new(|| {
    let (_type_label, cert_der) =
        pem_rfc7468::decode_vec(GLOBAL_VIRTUAL_TPMCA03_PEM.as_bytes()).expect("Cannot decode PEM");
    vec![CertificateDer::from(cert_der)]
});

/// The root anchors for azure
static AZURE_ROOT_ANCHORS: Lazy<Vec<TrustAnchor<'static>>> = Lazy::new(|| {
    vec![
        // Microsoft RSA Devices Root CA 2021 (older VMs)
        pem_to_trust_anchor(MICROSOFT_RSA_DEVICES_ROOT_2021),
        // Azure Virtual TPM Root CA 2023 (TDX + newer trusted launch)
        pem_to_trust_anchor(AZURE_VIRTUAL_TPM_ROOT_2023),
    ]
});

/// Verify an AK certificate against pinned Azure root CAs.
///
/// This includes `LEGACY_BUNDLED_AZURE_INTERMEDIATES` as a
/// verification-only fallback so older evidence captured before AIA-fetched
/// intermediates were serialized continues to verify.
pub(crate) fn verify_ak_cert_with_azure_roots(
    ak_cert_der: &[u8],
    intermediate_cert_ders: &[Vec<u8>],
    now_secs: u64,
) -> Result<(), MaaError> {
    verify_ak_cert_with_azure_roots_inner(ak_cert_der, intermediate_cert_ders, now_secs, true)
}

/// Verify an AK certificate against pinned Azure root CAs using only the
/// intermediates supplied by the caller.
///
/// This is used while following AIA URLs during evidence generation. After
/// each fetched issuer is appended, we call this to check whether the
/// fetched chain is already complete. It intentionally excludes the legacy
/// bundled intermediates, otherwise generation could stop early because a
/// hardcoded intermediate completed the path, and the serialized evidence
/// would still depend on that legacy fallback.
fn verify_ak_cert_with_provided_intermediates_only(
    ak_cert_der: &[u8],
    intermediate_cert_ders: &[Vec<u8>],
    now_secs: u64,
) -> Result<(), MaaError> {
    verify_ak_cert_with_azure_roots_inner(ak_cert_der, intermediate_cert_ders, now_secs, false)
}

fn verify_ak_cert_with_azure_roots_inner(
    ak_cert_der: &[u8],
    intermediate_cert_ders: &[Vec<u8>],
    now_secs: u64,
    include_legacy_bundled_intermediates: bool,
) -> Result<(), MaaError> {
    let ak_cert_der: CertificateDer = ak_cert_der.into();
    let end_entity_cert = EndEntityCert::try_from(&ak_cert_der)?;

    let mut intermediates = if include_legacy_bundled_intermediates {
        LEGACY_BUNDLED_AZURE_INTERMEDIATES.clone()
    } else {
        Vec::new()
    };
    intermediates.extend(intermediate_cert_ders.iter().cloned().map(CertificateDer::from));

    let now = UnixTime::since_unix_epoch(Duration::from_secs(now_secs));

    end_entity_cert.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &AZURE_ROOT_ANCHORS,
        &intermediates,
        now,
        AnyEku,
        None,
        None,
    )?;
    tracing::debug!("Successfully verified AK certificate from vTPM");

    Ok(())
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
pub(crate) fn fetch_ak_intermediates_from_aia(
    ak_cert_der: &[u8],
    ak_cert: &X509Certificate<'_>,
    now_secs: u64,
) -> Result<Vec<Vec<u8>>, MaaError> {
    let mut intermediates = Vec::new();
    if verify_ak_cert_with_provided_intermediates_only(ak_cert_der, &intermediates, now_secs)
        .is_ok()
    {
        return Ok(intermediates);
    }

    let mut issuer_urls = ca_issuers_urls(ak_cert);

    while !issuer_urls.is_empty() {
        let fetched_issuer = fetch_first_available_issuer(&issuer_urls)?;

        issuer_urls = fetched_issuer.ca_issuers_urls;
        intermediates.push(fetched_issuer.der);

        if verify_ak_cert_with_provided_intermediates_only(ak_cert_der, &intermediates, now_secs)
            .is_ok()
        {
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
pub(crate) fn read_ak_certificate_from_tpm() -> Result<Vec<u8>, tss_esapi::Error> {
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

/// Convert a PEM-encoded cert into a TrustAnchor
fn pem_to_trust_anchor(pem: &str) -> TrustAnchor<'static> {
    let (_type_label, der_vec) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
    // Leaking is ok here because plan is to set this up so it is only called
    // once
    let leaked: &'static [u8] = Box::leak(der_vec.into_boxed_slice());
    let cert_der: &'static CertificateDer<'static> =
        Box::leak(Box::new(CertificateDer::from(leaked)));
    webpki::anchor_from_trusted_cert(cert_der).expect("Failed to create trust anchor")
}

/// Allows any EKU - we could change this to only accept
/// 1.3.6.1.4.1.567.10.3.12 which is the EKU given in the AK certificate
struct AnyEku;

impl webpki::ExtendedKeyUsageValidator for AnyEku {
    fn validate(&self, _iter: webpki::KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
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

    use super::*;

    #[tokio::test]
    async fn root_should_be_fresh() {
        let response = reqwest::get(
            "http://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Devices%20Root%20CA%202021.crt",
        )
        .await
        .unwrap();
        let ca_der = response.bytes().await.unwrap();
        assert_eq!(
            pem_rfc7468::decode_vec(MICROSOFT_RSA_DEVICES_ROOT_2021.as_bytes()).unwrap().1,
            ca_der
        );
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
        // HTTP/1.1 request line format is: `<method> <request-target> <version>`.
        // The local test server only needs the request target, e.g. `/root.pem`.
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
