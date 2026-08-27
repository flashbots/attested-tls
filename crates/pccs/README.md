# pccs

A DCAP collateral client with optional in-process caching and proactive
refresh.

This crate is used by attestation verification code that needs Intel TDX/SGX
collateral such as TCB info, QE identity, and certificate revocation lists.

It can:

- Fetch collateral from Intel PCS or a configured PCCS endpoint
- Operate as a remote pass-through without caching
- Cache collateral lazily on demand
- Pre-warm and proactively refresh an in-process cache

The caching modes provide an embeddable alternative to deploying Intel's
reference PCCS server alongside services that verify quotes.

For Intel's terminology and architecture, see the Intel documentation for the
[Provisioning Certificate Caching Service (PCCS)](https://cc-enabling.trustedservices.intel.com/intel-sgx-tdx-pccs/01/introduction/).

## Modes

Every `Pccs` has a [`PccsMode`](src/lib.rs):

- `Remote` keeps no internal cache. Every `get_collateral()` call fetches from
  the configured endpoint. `get_collateral_sync()` returns `CacheDisabled`
  because it cannot perform asynchronous network I/O.
- `Lazy` starts with an empty cache. Asynchronous cache misses are fetched
  immediately; synchronous misses return an error and start a background
  fetch for a later attempt.
- `Prewarmed` starts the same cache and immediately begins pre-warming it with
  discovered TDX collateral. Call `ready()` to wait for that initial work.

The endpoint passed to `Pccs::new` may be Intel PCS or another PCCS-compatible
service. Passing `None` uses [`PCS_URL`](src/lib.rs), the Intel PCS default.

```rust,no_run
use pccs::{Pccs, PccsMode};

#[tokio::main]
async fn main() -> Result<(), pccs::PccsError> {
    let _remote = Pccs::new(None, PccsMode::Remote);
    let _lazy = Pccs::new(Some("https://pccs.example".into()), PccsMode::Lazy);
    let prewarmed = Pccs::new(None, PccsMode::Prewarmed);
    let _summary = prewarmed.ready().await?;

    Ok(())
}
```

`ready()` only waits for `Prewarmed` mode. It returns `PrewarmDisabled` for
`Remote` and `Lazy`. A successful pre-warm result includes failure counters;
it does not guarantee that every possible collateral item was cached.

## Runtime Requirements

Asynchronous collateral fetching requires a Tokio runtime. Constructing a
`Prewarmed` instance also requires an active runtime because it immediately
spawns the initial pre-warm task. Constructing `Remote` or `Lazy` does not
itself spawn a task.

`get_collateral_sync()` is available only with a cache (`Lazy` or
`Prewarmed`). A cache miss or expired entry may spawn a Tokio background task,
so applications that can encounter either condition must have an active
runtime.
