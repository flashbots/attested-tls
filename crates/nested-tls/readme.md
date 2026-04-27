# nested-tls

Nested TLS primitives.

This crate provides wrappers around `rustls'` `Acceptor` and `Connector` for
running one TLS session inside another.

At a high level:

1. The client and server complete an outer TLS handshake over the underlying
   transport.
2. A second TLS handshake is then performed over the encrypted outer TLS
   stream.
3. The resulting stream can be used like a normal TLS stream.

The main types are:

- `client::NestingTlsConnector`, which performs the outer handshake and then
  the inner handshake on the client side
- `server::NestingTlsAcceptor`, which accepts the outer handshake and then the
  inner handshake on the server side

The crate also includes [Actix](https://actix.rs/) integration for both client
and server.

This crate does not define the authentication policy of either layer. It only
composes two `rustls` sessions. In this workspace, the proposed pattern is:

- outer TLS for conventional CA-signed certificates
- inner TLS for attested certificates via [`attested-tls`](../attested-tls)

After both handshakes complete, callers interact with the returned stream as a
single nested TLS connection.
