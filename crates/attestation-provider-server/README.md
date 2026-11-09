# Attestation provider service

Generates quotes and collects platform metadata in a privileged process so
applications can request attestations through a Unix socket without those
privileges.

Use `--socket-path` and provision its parent directory with the application's
access group and mode `2750`.

Use an absolute socket path without symlink directories or `..` components.
Every directory in the path must be owned by root or the service user and must
not be group/other writable. Sticky ancestors such as `/tmp` are allowed, but
the socket's immediate parent must never be group/other writable. For example,
use `/run/attestation-provider/attestation.sock` with a protected parent directory.

The service creates the socket with mode `0660`.
