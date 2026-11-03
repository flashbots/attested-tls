# Attestation provider service

Generates quotes and collects platform metadata in a privileged process so
applications can request attestations through a Unix socket without those
privileges.

Use `--socket-path` and provision its parent directory with the application's
access group and mode `2750`.

The service creates the socket with mode `0660`.
