//! Portable verification of Azure vTPM quotes.
//!
//! A vTPM quote is a signed, marshalled `TPMS_ATTEST` structure together
//! with the PCR values it attests to. Verifying one is pure computation:
//! an RSA signature check over the message, a nonce comparison against
//! the `extraData` field, and a SHA-256 digest comparison against the
//! attested `pcrDigest`. This module owns that verification so it needs
//! no TPM stack; only evidence generation (reading the vTPM on an Azure
//! CVM) goes through `az_tdx_vtpm`.
//!
//! The verification logic is adapted from az-cvm-vtpm's `vtpm::verify`
//! (<https://github.com/kinvolk/azure-cvm-tooling>, Copyright (c)
//! Microsoft Corporation, MIT license), with the `TPMS_ATTEST` field
//! extraction done by the `tpms_attest` parser instead of tss-esapi. It is
//! vendored because az-cvm-vtpm's verifier feature currently requires its
//! TPM device support (tss-esapi links the native tpm2-tss libraries,
//! making such builds Linux-only). Tracked upstream as
//! <https://github.com/kinvolk/azure-cvm-tooling/issues/95>; if upstream
//! decouples verification from the TPM stack, this module and
//! [`super::tpms_attest`] can be retired in favour of depending on
//! az-cvm-vtpm's verifier again.

use openssl::{
    hash::MessageDigest,
    pkey::{PKey, Public},
    sha::Sha256,
    sign::Verifier,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::tpms_attest::{AttestError, TpmsAttest};

/// An error when verifying a vTPM quote
#[derive(Error, Debug)]
pub enum TpmQuoteError {
    #[error("TPMS_ATTEST parse: {0}")]
    Attest(#[from] AttestError),
    #[error("OpenSSL: {0}")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    #[error("quote is not signed by key")]
    SignatureMismatch,
    #[error("nonce mismatch")]
    NonceMismatch,
    #[error("PCR digest does not match PCR values")]
    PcrMismatch,
    #[error("quote attests {selected} PCR(s) but carries {carried} value(s)")]
    PcrCountMismatch { selected: usize, carried: usize },
}

/// A vTPM quote: AK signature, marshalled `TPMS_ATTEST` message, and the
/// attested sha256 PCR values.
///
/// The field names and types match `az_tdx_vtpm::vtpm::Quote`, keeping
/// the serde_json wire format of attestation evidence identical.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct TpmQuote {
    signature: Vec<u8>,
    message: Vec<u8>,
    pcrs: Vec<[u8; 32]>,
}

impl TpmQuote {
    /// Verify the quote's signature, nonce, and PCR digest, and return its
    /// sha256 PCR values paired with the registers they measure.
    ///
    /// The registers are the ones the quote's `pcrSelect` bitmap names.
    pub(super) fn verify(
        &self,
        pub_key: &PKey<Public>,
        nonce: &[u8],
    ) -> Result<Vec<(u32, [u8; 32])>, TpmQuoteError> {
        self.verify_signature(pub_key)?;

        let attest = TpmsAttest::parse(&self.message)?;
        if attest.extra_data() != nonce {
            return Err(TpmQuoteError::NonceMismatch);
        }

        self.verify_pcrs(&attest)?;
        self.pair_with_registers(&attest)
    }

    /// The same pairing [`TpmQuote::verify`] returns, without performing
    /// any of the verification: no signature, no nonce, no digest over the
    /// values.
    pub(super) fn indexed_pcrs_unverified(&self) -> Result<Vec<(u32, [u8; 32])>, TpmQuoteError> {
        let attest = TpmsAttest::parse(&self.message)?;
        self.pair_with_registers(&attest)
    }

    /// Pair each value with the register the quote attests it for.
    ///
    /// A quote's value list has to fill its attested selection exactly:
    /// anything else cannot be paired with it, and pairing a prefix would
    /// hand a policy values from registers it did not ask about.
    fn pair_with_registers(
        &self,
        attest: &TpmsAttest,
    ) -> Result<Vec<(u32, [u8; 32])>, TpmQuoteError> {
        self.check_pcr_count(attest)?;
        Ok(attest.selected_pcrs().iter().copied().zip(self.pcrs.iter().copied()).collect())
    }

    /// A quote's value list has to fill its attested selection exactly.
    fn check_pcr_count(&self, attest: &TpmsAttest) -> Result<(), TpmQuoteError> {
        let selected = attest.selected_pcrs().len();
        if selected != self.pcrs.len() {
            return Err(TpmQuoteError::PcrCountMismatch { selected, carried: self.pcrs.len() });
        }
        Ok(())
    }

    /// Verify the quote's signature (SHA-256 RSA) over the message
    fn verify_signature(&self, pub_key: &PKey<Public>) -> Result<(), TpmQuoteError> {
        let mut verifier = Verifier::new(MessageDigest::sha256(), pub_key)?;
        verifier.update(&self.message)?;
        if !verifier.verify(&self.signature)? {
            return Err(TpmQuoteError::SignatureMismatch);
        }
        Ok(())
    }

    /// Verify that the attested PCR digest matches the digest of the
    /// bundled PCR values
    fn verify_pcrs(&self, attest: &TpmsAttest) -> Result<(), TpmQuoteError> {
        // The digest below is taken over the whole value list, so a list
        // of the wrong length fails there too; checking the count first
        // names the actual complaint.
        self.check_pcr_count(attest)?;
        let mut hasher = Sha256::new();
        for pcr in &self.pcrs {
            hasher.update(pcr);
        }
        let digest = hasher.finish();
        if digest[..] != *attest.pcr_digest() {
            return Err(TpmQuoteError::PcrMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        AttestationType,
        azure::tpms_attest::test_support::{SHA256_BANK, build_attest, pcr_bitmap},
        measurements::{
            ExpectedMeasurements,
            MeasurementPolicy,
            MeasurementRecord,
            MultiMeasurements,
        },
    };

    const FIXTURE: &[u8] =
        include_bytes!("../../test-assets/azure-tdx-with-ak-intermediates-1780922561.yaml");

    fn fixture_quote_value() -> serde_json::Value {
        let document: serde_json::Value = serde_saphyr::from_slice(FIXTURE).unwrap();
        document["tpm_attestation"]["quote"].clone()
    }

    /// The wire format must be identical to the `az_tdx_vtpm::vtpm::Quote`
    /// serialization captured in the fixture: evidence produced before and
    /// after this type verifies the same.
    #[test]
    fn wire_format_round_trips_against_fixture() {
        let quote_value = fixture_quote_value();
        let quote: TpmQuote = serde_json::from_value(quote_value.clone()).unwrap();
        assert_eq!(serde_json::to_value(&quote).unwrap(), quote_value);
    }

    /// The registers come from the quote, not from list position. Azure
    /// selects PCRs 0-23 in one SHA-256 bank, so the fixture's values pair
    /// with 0..=23 — and `pcr4` in a measurement policy means register 4
    /// because the quote says so, not because it is the fifth value.
    #[test]
    fn values_pair_with_the_registers_the_quote_selects() {
        let quote: TpmQuote = serde_json::from_value(fixture_quote_value()).unwrap();
        let attest = TpmsAttest::parse(&quote.message).unwrap();

        let expected: Vec<u32> = (0..24).collect();
        assert_eq!(attest.selected_pcrs(), expected.as_slice());

        let indexed = quote.indexed_pcrs_unverified().unwrap();
        assert_eq!(indexed.len(), 24);
        for (position, (register, value)) in indexed.iter().enumerate() {
            assert_eq!(*register, position as u32);
            assert_eq!(value, &quote.pcrs[position]);
        }
    }

    /// A measurement policy pinning the given registers to the given
    /// values, and nothing else.
    fn azure_policy(expected: &[(u32, [u8; 32])]) -> MeasurementPolicy {
        MeasurementPolicy {
            accepted_measurements: vec![MeasurementRecord {
                measurement_id: "test image".to_string(),
                attestation_type: AttestationType::AzureTdx,
                measurements: ExpectedMeasurements::Azure(
                    expected.iter().map(|(register, value)| (*register, vec![*value])).collect(),
                ),
            }],
        }
    }

    /// A quote over `selection`, carrying those registers' values from
    /// `machine`, with the pcrDigest a vTPM signs over them.
    fn quote_over(selection: &[u32], machine: &[[u8; 32]]) -> TpmQuote {
        let pcrs: Vec<[u8; 32]> =
            selection.iter().map(|register| machine[*register as usize]).collect();
        let mut hasher = Sha256::new();
        for pcr in &pcrs {
            hasher.update(pcr);
        }
        let bitmap = pcr_bitmap(selection);
        let message = build_attest(b"nonce", &[(SHA256_BANK, &bitmap)], &hasher.finish());
        TpmQuote { signature: Vec::new(), message, pcrs }
    }

    /// Labelling a quote's values by their position in the list, as if the
    /// first were PCR0 and the next PCR1, and so on.
    fn labelled_by_position(quote: &TpmQuote) -> MultiMeasurements {
        MultiMeasurements::Azure(
            quote
                .pcrs
                .iter()
                .copied()
                .enumerate()
                .map(|(position, value)| (position as u32, value))
                .collect(),
        )
    }

    /// A machine the policy refuses, whose honest evidence position-based
    /// labelling accepts.
    ///
    /// The machine loaded something the policy forbids, which extended PCRs
    /// 13 and 15 away from zero. The policy pins PCRs 0-7 to the image and
    /// requires 13 and 15 to still be zero. Azure leaves PCRs 16 and 23 at
    /// zero — the fixture shows both — so the machine quotes the selection
    /// `0..=12, 16, 17, 23`: sixteen of its own unaltered PCR values, over
    /// a digest its vTPM will sign. It forges nothing.
    ///
    /// Counted off by position, the fourteenth value is PCR16's zero and
    /// the sixteenth is PCR23's zero, and the policy's `pcr13` and `pcr15`
    /// are satisfied by registers it never asked about. Read off the
    /// quote's own `pcrSelect`, 13 and 15 are not attested at all.
    #[test]
    fn a_subset_selection_cannot_pass_one_register_off_as_another() {
        let fixture: TpmQuote = serde_json::from_value(fixture_quote_value()).unwrap();
        let mut machine = fixture.pcrs;
        machine[13] = [0x13; 32];
        machine[15] = [0x15; 32];

        let mut pinned: Vec<(u32, [u8; 32])> =
            (0..8).map(|register| (register, machine[register as usize])).collect();
        pinned.push((13, [0; 32]));
        pinned.push((15, [0; 32]));
        let policy = azure_policy(&pinned);

        // Quoting every register describes the machine as it is, and the
        // policy refuses it — under either labelling, since a full
        // selection makes the two agree.
        let full = quote_over(&(0..24).collect::<Vec<u32>>(), &machine);
        let full_measurements =
            MultiMeasurements::from_indexed_pcrs(full.indexed_pcrs_unverified().unwrap());
        assert_eq!(full_measurements, labelled_by_position(&full));
        assert!(
            policy.check_measurement(&full_measurements, None).is_err(),
            "the machine is not one the policy accepts: {full_measurements:?}"
        );

        // The same machine, quoting a subset.
        let mut selection: Vec<u32> = (0..=12).collect();
        selection.extend([16, 17, 23]);
        let crafted = quote_over(&selection, &machine);

        // Nothing about this quote is malformed: the digest covers exactly
        // the values it carries, which are the machine's own.
        let attest = TpmsAttest::parse(&crafted.message).unwrap();
        crafted.verify_pcrs(&attest).unwrap();

        // Labelled by position, it satisfies a policy that has to refuse
        // it. This is the bypass.
        let by_position = labelled_by_position(&crafted);
        policy
            .check_measurement(&by_position, None)
            .expect("position labelling is what the bypass relies on");

        // Labelled by the registers the quote attests, PCR13 and PCR15 are
        // absent and the policy has nothing to accept.
        let by_selection =
            MultiMeasurements::from_indexed_pcrs(crafted.indexed_pcrs_unverified().unwrap());
        assert!(
            policy.check_measurement(&by_selection, None).is_err(),
            "policy accepted a machine whose PCR13 and PCR15 it never saw: {by_selection:?}"
        );
        assert_eq!(
            by_selection,
            MultiMeasurements::Azure(
                selection
                    .iter()
                    .map(|register| (*register, machine[*register as usize]))
                    .collect::<HashMap<_, _>>()
            )
        );
    }

    /// A quote whose value list does not fill its attested selection cannot
    /// be paired with it, so it fails rather than pairing a prefix.
    #[test]
    fn a_short_value_list_is_refused() {
        let mut quote: TpmQuote = serde_json::from_value(fixture_quote_value()).unwrap();
        quote.pcrs.pop();

        let err = quote.indexed_pcrs_unverified().unwrap_err();
        assert!(
            matches!(err, TpmQuoteError::PcrCountMismatch { selected: 24, carried: 23 }),
            "{err:?}"
        );

        let attest = TpmsAttest::parse(&quote.message).unwrap();
        assert!(matches!(
            quote.verify_pcrs(&attest).unwrap_err(),
            TpmQuoteError::PcrCountMismatch { .. }
        ));
    }

    #[test]
    fn verify_pcrs_accepts_fixture_and_rejects_tampered_pcr() {
        let mut quote: TpmQuote = serde_json::from_value(fixture_quote_value()).unwrap();

        let attest = TpmsAttest::parse(&quote.message).unwrap();
        quote.verify_pcrs(&attest).unwrap();

        quote.pcrs[0][0] ^= 0x01;
        let err = quote.verify_pcrs(&attest).unwrap_err();
        assert!(matches!(err, TpmQuoteError::PcrMismatch));
    }

    #[test]
    fn verify_rejects_corrupted_signature() {
        let hcl_report_base64 = {
            let document: serde_json::Value = serde_saphyr::from_slice(FIXTURE).unwrap();
            document["hcl_report_base64"].as_str().unwrap().to_string()
        };
        let mut quote: TpmQuote = serde_json::from_value(fixture_quote_value()).unwrap();

        use base64::{Engine as _, engine::general_purpose::URL_SAFE as BASE64_URL_SAFE};
        let hcl_report_bytes = BASE64_URL_SAFE.decode(hcl_report_base64).unwrap();
        let hcl_report = az_cvm_vtpm::hcl::HclReport::new(hcl_report_bytes).unwrap();
        let ak_pub_der = hcl_report.ak_pub().unwrap().key.try_to_der().unwrap();
        let pub_key = PKey::public_key_from_der(&ak_pub_der).unwrap();

        let nonce = quote_nonce(&quote);
        quote.verify(&pub_key, &nonce).unwrap();

        quote.signature.reverse();
        let err = quote.verify(&pub_key, &nonce).unwrap_err();
        assert!(matches!(err, TpmQuoteError::SignatureMismatch));
    }

    fn quote_nonce(quote: &TpmQuote) -> Vec<u8> {
        TpmsAttest::parse(&quote.message).unwrap().extra_data().to_vec()
    }
}
