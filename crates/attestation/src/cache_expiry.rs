//! Conservative cache deadlines, derived from the material already
//! verified. These helpers do not establish trust or replace signature
//! verification.

use dcap_qvl::{QuoteCollateralV3, quote::Quote};
use x509_parser::{
    asn1_rs::Err as ParseError,
    error::X509Error,
    pem::Pem,
    prelude::{FromDer, X509Certificate},
};

use crate::dcap::DcapVerificationError;

/// Given a der-encoded x509 certificate, return the expiry date in seconds
pub(crate) fn certificate_not_after(der: &[u8]) -> Result<u64, ParseError<X509Error>> {
    let (_, cert) = X509Certificate::from_der(der)?;
    // An already-expired, unused certificate may be present in a verified
    // chain. It disables caching rather than introducing a new trust rule.
    Ok(u64::try_from(cert.validity().not_after.timestamp()).unwrap_or(0))
}

fn pem_chain_not_after(chain: &str) -> Result<u64, DcapVerificationError> {
    let mut earliest = None;
    for pem in Pem::iter_from_buffer(chain.as_bytes()) {
        let pem = pem?;
        if pem.label != "CERTIFICATE" {
            return Err(DcapVerificationError::UnexpectedPemLabel(pem.label));
        }
        let expiry = certificate_not_after(&pem.contents)?;
        earliest = Some(earliest.map_or(expiry, |previous: u64| previous.min(expiry)));
    }
    earliest.ok_or(DcapVerificationError::EmptyCertificateChain)
}

/// Given a TDX quote and associated collateral, return the earliest
/// associated expiry date
pub(crate) fn dcap_cache_expires_at(
    collateral: &QuoteCollateralV3,
    quote: &Quote,
) -> Result<u64, DcapVerificationError> {
    let mut expiry = pccs::collateral_next_update(collateral)?;
    for chain in [
        &collateral.tcb_info_issuer_chain,
        &collateral.qe_identity_issuer_chain,
        &collateral.pck_crl_issuer_chain,
    ] {
        expiry = expiry.min(pem_chain_not_after(chain)?);
    }

    // Match dcap-qvl's chain selection: collateral takes precedence.
    if let Some(chain) = &collateral.pck_certificate_chain {
        expiry = expiry.min(pem_chain_not_after(chain)?);
    } else {
        let chain = dcap_qvl::intel::extract_cert_chain(quote)?;
        if chain.is_empty() {
            return Err(DcapVerificationError::EmptyCertificateChain);
        }
        for certificate in chain {
            expiry = expiry.min(certificate_not_after(&certificate)?);
        }
    }
    Ok(expiry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn certificate(expiry: i64) -> rcgen::Certificate {
        let mut params = rcgen::CertificateParams::new(vec!["test".into()]).unwrap();
        params.not_before = time::OffsetDateTime::from_unix_timestamp(expiry - 100).unwrap();
        params.not_after = time::OffsetDateTime::from_unix_timestamp(expiry).unwrap();
        params.self_signed(&rcgen::KeyPair::generate().unwrap()).unwrap()
    }

    #[test]
    fn each_certificate_chain_can_limit_the_deadline() {
        let quote = Quote::parse(&mock_tdx::generate_mock_tdx_quote([0; 64]).unwrap()).unwrap();
        let baseline = mock_tdx::mock_collateral();
        let initial_expiry = dcap_cache_expires_at(&baseline, &quote).unwrap();
        let earlier = initial_expiry - 100;
        let short_chain = certificate(earlier as i64).pem();
        for chain in 0..4 {
            let mut collateral = baseline.clone();
            match chain {
                0 => collateral.tcb_info_issuer_chain = short_chain.clone(),
                1 => collateral.qe_identity_issuer_chain = short_chain.clone(),
                2 => collateral.pck_crl_issuer_chain = short_chain.clone(),
                _ => collateral.pck_certificate_chain = Some(short_chain.clone()),
            }
            assert_eq!(dcap_cache_expires_at(&collateral, &quote).unwrap(), earlier);
        }
    }

    #[test]
    fn pck_chain_in_collateral_takes_precedence_over_quote() {
        let mut quote = Quote::parse(&mock_tdx::generate_mock_tdx_quote([0; 64]).unwrap()).unwrap();
        let mut auth = quote.auth_data.clone().into_v3();
        auth.certification_data.body.data = certificate(1000).pem().into_bytes();
        quote.auth_data = dcap_qvl::quote::AuthData::V3(auth);
        let mut collateral = mock_tdx::mock_collateral();
        collateral.pck_certificate_chain = None;
        assert_eq!(dcap_cache_expires_at(&collateral, &quote).unwrap(), 1000);
        collateral.pck_certificate_chain = Some(certificate(2000).pem());
        assert_eq!(dcap_cache_expires_at(&collateral, &quote).unwrap(), 2000);
    }

    #[test]
    fn pem_chain_uses_earliest_certificate_and_rejects_bad_input() {
        let chain = format!("{}{}", certificate(2000).pem(), certificate(1000).pem());
        assert_eq!(pem_chain_not_after(&chain).unwrap(), 1000);
        assert!(matches!(
            pem_chain_not_after(""),
            Err(DcapVerificationError::EmptyCertificateChain)
        ));
        assert!(matches!(
            pem_chain_not_after("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"),
            Err(DcapVerificationError::Pem(_))
        ));
        assert!(matches!(
            pem_chain_not_after("-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----"),
            Err(DcapVerificationError::X509Parse(_))
        ));
        let wrong_label = certificate(1000).pem().replace("CERTIFICATE", "PUBLIC KEY");
        assert!(matches!(pem_chain_not_after(&wrong_label),
            Err(DcapVerificationError::UnexpectedPemLabel(label)) if label == "PUBLIC KEY"));
        assert!(certificate_not_after(b"invalid DER").is_err());
        assert_eq!(certificate_not_after(certificate(-1).der()).unwrap(), 0);
    }
}
