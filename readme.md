# attested-tls

Primitives for attested tls channels.

Provided crates:

- [`attested-tls`](./crates/attested-tls) - WIP - provides attested TLS via X509
  Certificate extensions and a custom certificate verifier.
- [`nested-tls`](./crates/nested-tls) - provides two TLS sessions, such that
  that outer session can be used for a CA signed certificate and the inner
  session for attestation.
- [`attestation`](./crates/attestation) - provides attestation generation,
  verification and measurement handling.
- [`mock-tdx`](./crates/mock-tdx) - generates deterministic mock TDX DCAP
  quotes, collateral, and trust roots for tests and development on non-TDX
  hardware.

The included `shell.nix` file can be used with `nix-shell`, `direnv`, or `nix
develop` to add the dependencies needed by the optional `azure` feature of the
`attestation` crate on Linux.  See the 
[`attestation` crate readme](./crates/attestation) for details.
