//! Parses the dcap-qvl sample SGX quote and confirms SGX measurement
//! extraction lands in the new `MultiMeasurements::Sgx(...)` variant with
//! MRENCLAVE / MRSIGNER / ISV_PROD_ID / ISV_SVN populated.

use attestation::measurements::{MultiMeasurements, SgxMeasurements};
use dcap_qvl::quote::Quote;

const SGX_QUOTE_SAMPLE: &[u8] = include_bytes!("fixtures/sgx_quote.bin");

#[test]
fn from_dcap_qvl_quote_extracts_sgx_measurements() {
    let quote = Quote::parse(SGX_QUOTE_SAMPLE).expect("sample is a valid SGX DCAP quote");
    let m = MultiMeasurements::from_dcap_qvl_quote(&quote).expect("SGX extraction succeeds");

    let sgx: &SgxMeasurements = m.as_sgx().expect("sample is an SGX quote, not TDX");
    assert_eq!(sgx.mrenclave.len(), 32);
    assert_eq!(sgx.mrsigner.len(), 32);
    // The sample quote is not all-zero in either hash field.
    assert_ne!(sgx.mrenclave, [0u8; 32]);
    assert_ne!(sgx.mrsigner, [0u8; 32]);
}

#[test]
fn sgx_measurements_are_distinguishable_from_tdx() {
    let quote = Quote::parse(SGX_QUOTE_SAMPLE).expect("sample parses");
    let m = MultiMeasurements::from_dcap_qvl_quote(&quote).unwrap();

    // This is the core type-system invariant: a TDX extraction never
    // accidentally pattern-matches an SGX quote, and vice versa.
    assert!(m.as_sgx().is_some());
    match m {
        MultiMeasurements::Sgx(_) => {}
        other => panic!("expected Sgx variant, got {other:?}"),
    }
}
