# mock-tdx

`mock-tdx` generates deterministic mock TDX DCAP artifacts for tests and
development on non-TDX hardware.

It provides:

- a small fixture generator for a mock DCAP trust chain and collateral
- a quote generator that emits mock TDX DCAP quotes with caller-supplied
  `report_data`
- checked-in mock collateral, root certificates, CRLs, and signing material
  under `test-assets/generated-dcap`

The generated quotes are shaped so they can be parsed and verified with
`dcap-qvl` using the mock root of trust bundled with this crate.

This crate is intended for tests and local development. It does not provide
production attestation material.

To refresh the checked-in fixtures:

```bash
cargo run -p mock-tdx -- refresh-dcap-fixtures
```
