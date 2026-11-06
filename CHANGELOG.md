# Changelog

eider-tls's versions (semver). Before 1.0 the MAJOR.MINOR is the Eider toolchain's it goes
with (`eider` in eider.toml), the PATCH its own.

## 0.7.2

- RSA and P-384 (eider-lang#221, Eider 0.7.6): signature schemes rsa_pss_rsae_sha256/384/512, rsa_pkcs1_sha256/384/512
  (certificates only) and ecdsa_secp384r1_sha384; group secp384r1; chain verification for RSA (PKCS#1 v1.5 and PSS)
  and ECDSA-SHA256/384/512 signatures, RSA 2048-8192 and P-384 keys; RSA and P-384 server and client keys. 117 of the
  121 roots of the system CA bundle verify as trust anchors (3 before). Tests: tests/pki-rsa.sh fixtures,
  tests/sigs_test.ei, loopback and interop cases against OpenSSL in both directions.
- The crypto dependency is the toolchain's own package, `[deps.crypto] toolchain = true`, instead of a path
  dependency on a link to an eider-lang checkout (eider-lang#222; needs Eider 0.7.6, which ships `packages/crypto` and
  its backend). `scripts/env.sh` no longer makes `target/deps/crypto`; with an installed toolchain alone, `scripts/build.sh`
  and `scripts/test.sh` work. The first release carrying this requires Eider 0.7.6 or later.

## 0.7.1

- The tests and the README use `let mut` instead of the removed `var` (eider-lang#2, Eider 0.7.5; `let mut` is valid in 0.7 too). No change to the library.

## 0.7.0

First version, for Eider 0.7 (`eider = "0.7"`): TLS 1.3 client and server (three AEAD suites, X25519 and
secp256r1, ed25519 and ecdsa_secp256r1_sha256, HelloRetryRequest, ALPN, SNI, client authentication, KeyUpdate,
close_notify), X.509 and PEM parsing, chain and host name verification, and a `Conn` that is a `stream.Reader`
and `stream.Writer`. Not done: RSA, P-384, resumption, 0-RTT, revocation; see the README.
