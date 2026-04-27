# attested-tls

Attested TLS primitives built on `rustls`.

This crate provides two components:

- `AttestedCertificateResolver`: issues TLS certificates which contain an
  embedded attestation and handles renewal. It implements
  [`rustls::server::ResolvesServerCert`](https://docs.rs/rustls/latest/rustls/server/trait.ResolvesServerCert.html)
  and [`rustls::client::ResolvesClientCert`](https://docs.rs/rustls/latest/rustls/client/trait.ResolvesClientCert.html).
- `AttestedCertificateVerifier`: verifies the TLS certificate and the embedded
  attestation during TLS handshake. It implements [`rustls::client::danger::ServerCertVerifier`](https://docs.rs/rustls/latest/rustls/client/danger/trait.ServerCertVerifier.html)
  and [`rustls::server::danger::ClientCertVerifier`](https://docs.rs/rustls/latest/rustls/server/danger/trait.ClientCertVerifier.html).

It supports both server and client TLS authentication, and can be used as the
inner attested session inside [`nested-tls`](../nested-tls).

## Protocol details

The resolver issues a short-lived X.509 leaf certificate whose attestation is
bound to:

- The certificate public key
- The certificate validity window (`not_before`, `not_after`)
- The certificate primary hostname (common name)

The binding is encoded as:

`SHA-512(public_key_der || not_before_unix_secs || not_after_unix_secs || common_name)`

That 64-byte hash is used as the attestation report data. The embedded
attestation is verified against the same recomputed value during certificate
verification.

The certificate resolver:

- Takes a single ECDSA P-256 keypair when constructed
- Issues either a self-signed leaf certificate or a leaf signed by a provided
  private CA
- Embeds attestation evidence into the certificate using the
  [`ra-tls`](https://github.com/Dstack-TEE/dstack/tree/master/ra-tls) crate
- Renews the certificate after two-thirds of its validity period has passed
- Reuses the same keypair for renewed certificates created by the same
  resolver instance

The certificate verifier:

- Optionally verifies the certificate chain against a provided `RootCertStore`
- For self-signed server certificates, verifies server name and certificate
  validity
- For self-signed client certificates, verifies certificate validity
- Extracts the embedded attestation from the certificate
- Recomputes the expected report data from the certificate contents
- Verifies the attestation through [`attestation`](../attestation)
- Caches successful attestation verifications until the certificate expires
  so repeated handshakes with the same certificate avoid repeating quote
  verification.

Both server-side and client-side attested certificates are supported.

## Certificate format

Certificates are issued with:

- Subject common name set to the configured primary hostname
- Subject alternative names containing the primary hostname plus any extra SANs
- Usable for both server and client auth

The attestation is embedded using the `ra-tls` certificate extension format.
When verifying a certificate, this crate first tries to parse the `ra-tls`
attestation payload directly. If that fails, it falls back to reading the
custom attestation extension OID and parsing the JSON payload stored there.

## Relationship to `nested-tls`

This crate does not implement an outer TLS session or any stream nesting by
itself.

If you want a standard CA-signed outer TLS session plus an inner attested
TLS session, use this crate together with [`nested-tls`](../nested-tls).
This is demonstrated in [tests/nested_tls.rs](./tests/nested_tls.rs).

## Runtime requirements

This crate expects to run in a Tokio runtime.
