//! Generation and verification of AK certificates from the vTPM
use std::{io::Read, time::Duration};

use once_cell::sync::Lazy;
use tokio_rustls::rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::EndEntityCert;
use x509_parser::{extensions::GeneralName, prelude::*};

use crate::azure::{MaaError, nv_index};

/// The NV index where we expect to be able to read the AK certificate from
/// the vTPM
const TPM_AK_CERT_IDX: u32 = 0x1C101D0;

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

/// Azure intermediate certificates bundled with this crate.
///
/// This is kept only for backwards compatibility with older evidence that
/// did not serialize AIA-fetched intermediates. New Azure vTPM evidence
/// should carry the AK issuer chain fetched from AIA instead of relying on
/// this bundled, eventually-stale list.
static BUNDLED_AZURE_INTERMEDIATES: Lazy<Vec<CertificateDer<'static>>> = Lazy::new(|| {
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

/// Verify an AK certificate against azure root CA
pub(crate) fn verify_ak_cert_with_azure_roots(
    ak_cert_der: &[u8],
    intermediate_cert_ders: &[Vec<u8>],
    now_secs: u64,
) -> Result<(), MaaError> {
    let ak_cert_der: CertificateDer = ak_cert_der.into();
    let end_entity_cert = EndEntityCert::try_from(&ak_cert_der)?;

    let mut intermediates = BUNDLED_AZURE_INTERMEDIATES.clone();
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
/// The fetched certificates are untrusted evidence. Verification still pins
/// the Azure vTPM root in `verify_ak_cert_with_azure_roots`.
pub(crate) fn fetch_ak_intermediates_from_aia(
    ak_cert: &X509Certificate<'_>,
) -> Result<Vec<Vec<u8>>, MaaError> {
    const MAX_AIA_DEPTH: usize = 6;

    let mut intermediates = Vec::new();
    let mut issuer_url = first_ca_issuers_url(ak_cert);

    for _ in 0..MAX_AIA_DEPTH {
        let Some(url) = issuer_url else {
            break;
        };

        tracing::debug!("Fetching Azure vTPM AK issuer certificate from {url}");
        let issuer_der = fetch_certificate_der(&url)?;
        let (_, issuer_cert) = X509Certificate::from_der(&issuer_der)?;

        // Stop before adding the self-signed root. The root is already pinned
        // in AZURE_ROOT_ANCHORS and should not come from untrusted evidence.
        if issuer_cert.subject() == issuer_cert.issuer() {
            break;
        }

        issuer_url = first_ca_issuers_url(&issuer_cert);
        intermediates.push(issuer_der);
    }

    Ok(intermediates)
}

/// Retrieve an AK certificate from the vTPM
pub(crate) fn read_ak_certificate_from_tpm() -> Result<Vec<u8>, tss_esapi::Error> {
    tracing::debug!("Reading AK certificate from vTPM");
    let mut context = nv_index::get_session_context()?;
    nv_index::read_nv_index(&mut context, TPM_AK_CERT_IDX)
}

fn first_ca_issuers_url(cert: &X509Certificate<'_>) -> Option<String> {
    cert.extensions().iter().find_map(|extension| {
        let ParsedExtension::AuthorityInfoAccess(aia) = extension.parsed_extension() else {
            return None;
        };

        aia.iter().find_map(|desc| {
            if desc.access_method.to_id_string() != "1.3.6.1.5.5.7.48.2" {
                return None;
            }

            let GeneralName::URI(uri) = &desc.access_location else {
                return None;
            };

            Some((*uri).to_string())
        })
    })
}

fn fetch_certificate_der(url: &str) -> Result<Vec<u8>, MaaError> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(MaaError::UnsupportedAiaUrl { url: url.to_string() });
    }

    let response = ureq::get(url)
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|err| MaaError::AiaFetch { url: url.to_string(), source: err })?;

    let mut bytes = Vec::new();
    response.into_reader().take(1024 * 1024).read_to_end(&mut bytes)?;

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
