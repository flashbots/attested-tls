//! Verification of vTPM AK certificates against pinned Azure root CAs
use std::time::Duration;

use once_cell::sync::Lazy;
use tokio_rustls::rustls::pki_types::{CertificateDer, TrustAnchor, UnixTime};
use webpki::EndEntityCert;

use crate::azure::MaaError;

// microsoftRSADevicesRoot2021 is the root CA certificate used to sign Azure
// TDX vTPM certificates. This is different from the AME root CA used by
// TrustedLaunch VMs. The certificate can be downloaded from:
// http://www.microsoft.com/pkiops/certs/Microsoft%20RSA%20Devices%20Root%20CA%202021.crt
const MICROSOFT_RSA_DEVICES_ROOT_2021: &str =
    include_str!("../../assets/microsoft-rsa-devices-root-ca-2021.pem");

// azureVirtualTPMRoot2023 is the root CA for Azure vTPM (used by both
// Trusted Launch and TDX) Source: https://learn.microsoft.com/en-us/azure/virtual-machines/trusted-launch-faq
// Valid until: 2048-06-01
pub(super) const AZURE_VIRTUAL_TPM_ROOT_2023: &str =
    include_str!("../../assets/azure-virtual-tpm-root-2023.pem");

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
/// `intermediate_cert_ders` are untrusted evidence from the attestation (or
/// fetched from AIA during generation); verification pins the Azure roots.
pub(crate) fn verify_ak_cert_with_azure_roots(
    ak_cert_der: &[u8],
    intermediate_cert_ders: &[Vec<u8>],
    now_secs: u64,
) -> Result<(), MaaError> {
    let ak_cert_der: CertificateDer = ak_cert_der.into();
    let end_entity_cert = EndEntityCert::try_from(&ak_cert_der)?;
    let intermediates: Vec<_> =
        intermediate_cert_ders.iter().cloned().map(CertificateDer::from).collect();
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

/// Convert a PEM-encoded cert into a TrustAnchor
fn pem_to_trust_anchor(pem: &str) -> TrustAnchor<'static> {
    let (_type_label, der_vec) = pem_rfc7468::decode_vec(pem.as_bytes()).unwrap();
    // Leaking is ok here because plan is to set this up so it is only
    // called once
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
    use std::sync::OnceLock;

    use super::*;

    static TEST_CRYPTO_PROVIDER: OnceLock<()> = OnceLock::new();

    fn install_test_crypto_provider() {
        TEST_CRYPTO_PROVIDER.get_or_init(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[tokio::test]
    async fn root_should_be_fresh() {
        install_test_crypto_provider();

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
}
