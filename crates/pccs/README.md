# pccs

An internal Provisioning Certificate Caching Service implementation for DCAP
collateral fetching and caching.

This crate is used by attestation code that needs Intel TDX/SGX collateral such
as TCB info, QE identity, and certificate revocation lists.

It can:

- Fetch collateral from Intel PCS or a configured PCCS endpoint
- Cache collateral in-process
- Pre-warm the cache at startup
- Refresh cached collateral in the background before expiry

This is an alternative to Intel's reference PCCS server implementation which
can be embedded in Rust services that verify quotes.

For Intel's terminology and architecture, see the Intel documentation for the
[Provisioning Certificate Caching Service (PCCS)](https://cc-enabling.trustedservices.intel.com/intel-sgx-tdx-pccs/01/introduction/).

## Runtime Requirements

This crate expects to be used from within a Tokio runtime.

The above applies to startup pre-warm and proactive refresh. Synchronous cache
miss paths can fetch collateral directly, but they should be kept off hot
request paths unless the caller has a strict timeout.
