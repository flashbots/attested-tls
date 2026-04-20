//! Real-hardware smoke test for SGX Gramine quote generation.
//!
//! This test only runs with `--ignored` on a machine where the current
//! process is executing inside a Gramine-SGX enclave — i.e. on Moe's SGX
//! box. On any other host, `/dev/attestation/*` does not exist and the
//! generator returns a file-not-found error; we leave the test ignored so
//! `cargo test` on developer workstations stays green.
//!
//! Run on an SGX-capable host:
//!     cargo test -p attestation --features sgx --test sgx_generator --
//! --ignored

#![cfg(all(target_os = "linux", feature = "sgx"))]

use attestation::dcap::create_sgx_gramine_attestation;

#[test]
#[ignore = "requires Gramine-SGX runtime (/dev/attestation/*) — not available on dev workstations"]
fn gramine_sgx_generator_produces_a_non_trivial_quote() {
    let report_data = [0x42u8; 64];
    let quote = create_sgx_gramine_attestation(report_data)
        .expect("SGX Gramine quote generation succeeds under Gramine-SGX");
    assert!(
        quote.len() > 512,
        "quote suspiciously small ({} bytes); a real SGX DCAP quote is ~4.5KB",
        quote.len()
    );
}
