# Changelog

eider-tls's versions (semver). Before 1.0 the MAJOR.MINOR is the Eider toolchain's it goes
with (`eider` in eider.toml), the PATCH its own.

## 0.7.0

First version, for Eider 0.7 (`eider = "0.7"`): TLS 1.3 client and server (three AEAD suites, X25519 and
secp256r1, ed25519 and ecdsa_secp256r1_sha256, HelloRetryRequest, ALPN, SNI, client authentication, KeyUpdate,
close_notify), X.509 and PEM parsing, chain and host name verification, and a `Conn` that is a `stream.Reader`
and `stream.Writer`. Not done: RSA, P-384, resumption, 0-RTT, revocation; see the README.
