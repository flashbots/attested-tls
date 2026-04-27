# mock-tdx

`mock-tdx` generates deterministic mock TDX DCAP artifacts for tests and
development on non-TDX hardware. It plays the role of Intel so we can
mock the complete DCAP workflow.

It provides:

- A small fixture generator for a mock DCAP trust chain and collateral
- A quote generator for mock TDX DCAP quotes with caller-supplied
  `report_data`
- Checked-in mock collateral, root certificate, and PCK certificate chain
  and key under `assets`
- A mock PCS server

The generated quotes are shaped so they can be parsed and verified with
`dcap-qvl` using the mock root of trust bundled with this crate.

This crate is intended for tests and local development. It does not provide
production attestation material.

To refresh the checked-in fixtures:

```bash
cargo run -p mock-tdx -- refresh-dcap-fixtures
```
