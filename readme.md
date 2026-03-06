# attested-tls

Primitives for attested tls channels.

Provided crates:

- [`attested-tls`](./crates/attested-tls) - WIP - provides attested TLS via X509 Certificate extensions and a custom certificate verifier
- [`nested-tls``](./crates/nested-tls) - WIP - provides two TLS sessions, such that that outer session can be used for a CA signed certificate and the inner session for attestation 
- [attestation](./crates/attestation) - provides attestation generation, verification and measurement handling
