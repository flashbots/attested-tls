# Attestation provider service

Generates quotes and collects platform metadata in a privileged process so
applications can request attestations through a Unix socket without those
privileges.

Start the server with an explicit platform type:

```sh
attestation-provider-server server --server-attestation-type dcap-tdx
```

Use `gcp-tdx` on Google Cloud TDX, or `dcap-tdx` for generic TDX.
The legacy alias `qemu-tdx` selects `dcap-tdx`.
The server uses local ConfigFS or the local vSOCK quote service and can run
without IP networking. The `client` subcommand verifies received evidence
and may fetch verification collateral over the network.

Use `--socket-path` and provision its parent directory with the application's
access group and mode `2750`.

Use an absolute socket path without symlink directories or `..` components.
Every directory in the path must be owned by root or the service user and must
not be group/other writable. Sticky ancestors such as `/tmp` are allowed, but
the socket's immediate parent must never be group/other writable. For example,
use `/run/attestation-provider/attestation.sock` with a protected parent directory.

The service creates the socket with mode `0660`.

On normal shutdown (SIGINT or SIGTERM), the service removes its socket. After
an abrupt exit such as SIGKILL, the next startup removes a stale socket owned
by the service user if a connection probe returns connection refused. Active
sockets, symlinks, and other existing files are preserved.

The service holds an exclusive lock on `<socket-path>.lock` from before socket
cleanup until shutdown, preventing competing instances from removing each other's
sockets during startup. The lock file must be a regular file owned by the service
user and is created with mode `0600`. It remains on disk across restarts; do not
delete it while the service is running. SIGKILL releases the lock automatically.
