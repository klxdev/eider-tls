# eider-tls

TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) for [Eider](https://github.com/klxdev/eider-lang),
written in Eider: the record layer, the key schedule, the client and server handshakes, and X.509 certificate
parsing and validation. The primitives (X25519, P-256, Ed25519, ECDSA, AES-GCM, ChaCha20-Poly1305, SHA-2, HMAC,
HKDF) come from eider-lang's `crypto` package over an audited libcrypto (AWS-LC by default); the protocol and
the parsers, where memory-safety bugs live in other TLS libraries, are Eider (eider-lang issue 29).

Status: version 0.7.0, the first release. It interoperates with OpenSSL 3.5 in both directions (below). It has
had no outside review or audit, and it is not yet used by eider-http (docs/http-integration.md
says how it will be). Read "Not done" before relying on it.

## Using it

The two snippets are sketches of the calls (not compiled as written); tests/interop_client.ei and tests/interop_server.ei are complete, working programs.

A client, over a TCP socket:

```eider
import std.net
import std.time
import tls
import tls.config
import tls.x509

fn fetch(addr: net.Addr) uses net, io, fs, clock {
    let roots = x509.system_store().unwrap()          // /etc/pki/tls/certs/ca-bundle.crt, /etc/ssl/certs/..., or x509.store_from_pem(text)
    let cfg = config.client_config("example.org", roots)   // verifies the certificate for this name; sends it as SNI
    let mut c = tls.dial(addr, cfg, time.after_ms(10000)).unwrap()
    c.send_by("GET / HTTP/1.0\r\n\r\n".bytes(), time.after_ms(5000)).unwrap()
    let reply = c.recv_by(65536, time.after_ms(5000)).unwrap()     // empty: the server's close_notify
    let z = c.close()
}
```

A server:

```eider
let id = config.identity_from_files("chain.pem", "key.pem").unwrap()   // leaf first; Ed25519 or P-256 key
let mut cfg = config.server_config(id)
cfg.alpn.push("http/1.1".bytes())
let listener = net.listener(net.ipv4(0, 0, 0, 0, 8443), false).unwrap()
let mut c = tls.accept_on(listener, cfg, time.after_ms(10000)).unwrap()
```

`tls.dial` and `tls.accept_on` are the TCP shortcuts. The real entry points work on any stream:
`client.connect(io, cfg, deadline)` and `server.accept(io, cfg, deadline)` take a `S: stream.Reader + stream.Writer`
(a `stream.Fd`, a wrapper, another connection) and return a `conn.Conn[S]`, which is a `stream.Reader` and
`stream.Writer` itself: code written for a `stream.Fd` (`stream.read_all`, `write_all`, `BufReader`) works on it.
`recv_by`/`send_by` take a deadline; a read that times out consumes nothing and leaves the connection usable
(`tests/loopback_test.ei`). `try_recv` and `ready_to_read` are for a transport that polls the socket itself.
`c.cipher_suite()`, `negotiated_alpn()`, `peer_certificates()` and `c.server_name` (what a client sent as SNI) report
what was negotiated.

Errors are `alert.Error`: a `kind` (`Protocol`, `Certificate`, `Io`, `PeerAlert`, `Truncated`, `Usage`), the alert
sent or received, and a message. A connection that ends without close_notify is `Truncated`, never a clean end.

`ClientConfig` has `verify = config.Insecure` for tests: it skips certificate validation (the CertificateVerify
signature and the Finished MAC are still checked). `server_name` is required with `Full` verification; there is no
way to forget to verify the host name.

## What it does

| | |
|---|---|
| Versions | TLS 1.3 only. A peer that offers nothing newer than 1.2 gets protocol_version. |
| Cipher suites | TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256 |
| Key exchange | X25519, secp256r1 and secp384r1; HelloRetryRequest both ways (client and server) |
| Signatures | ed25519, ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, rsa_pss_rsae_sha256/384/512 for the handshake; the same plus rsa_pkcs1_sha256/384/512 for certificates (client and server) |
| Certificates | X.509 v3 DER and PEM, strict parser (depth and length limits), chain building with backtracking, validity, basicConstraints, keyUsage, pathLen, extendedKeyUsage, unknown critical extensions refused, host names (SAN dNSName with `*` as the whole left label, SAN iPAddress; no CN fallback), trust stores from PEM or the system bundle |
| Extensions | server_name, ALPN, supported_groups, signature_algorithms, supported_versions, key_share, cookie (echoed) |
| Client authentication | the server can request or require a certificate (chain checked against a CA list); the client sends one if asked |
| After the handshake | KeyUpdate (both directions, automatic after 2^24 records or on request), close_notify, truncation detection, NewSessionTicket dropped |
| Hostile input | every parser returns an error instead of failing; sizes are bounded (records, messages 128 KiB, 16 certificates, 8-deep chains, 4096 PEM blocks) |

## What is tested

`sh scripts/test.sh` runs everything below (an installed Eider 0.7.6 or later is enough; `ASAN=1` also needs an eider-lang checkout, see "Developing"):

- **Interoperability with `openssl s_server` and `s_client` 3.5.8** (`tests/interop.sh`, 36 cases over loopback with
  the CA and certificates in `tests/pki`): all three suites, both groups, an Ed25519 leaf through an intermediate and
  a P-256 leaf, HelloRetryRequest in both directions, ALPN (match, no match), key updates while sending, wildcard
  and IP names, wrong name / untrusted root / expired / missing intermediate / client-only certificate rejected,
  client certificates (requested, required, missing, wrong CA), and a TLS 1.2-only peer refused.
- **The key schedule against a second implementation**: `tests/vectors/keysched.py` computes HKDF-Expand-Label,
  Derive-Secret, traffic keys, Finished and key updates with Python's `hmac` and `hashlib` for SHA-256 and SHA-384;
  `tests/keys_test.ei` must print the same bytes. The two values of RFC 8448 section 3 that need no handshake
  (the early secret `33ad0a1c...` and the first derived secret `6f2615a1...`) are among them. The full RFC 8448
  traces were not available offline, so they are not in the tests.
- **The record layer** under each suite: every bit of a record flipped (always rejected), replays, wrong keys,
  sequence numbers, padding, size limits, partial headers.
- **Handshake messages**: round trips, every proper prefix rejected, duplicate extensions, bad lengths,
  6000 damaged messages and random bytes of 600 lengths into 7 parsers.
- **Hostile certificates and files**: every prefix and every single-byte change, insertion and deletion of four
  real certificates, DER rule violations, time formats, PEM and key files; and the operating system's whole CA
  bundle parses.
- **Hostile peers** (`tests/hostile_peer_test.ei`): a server fed every prefix of a ClientHello, 400 damaged ones,
  150 random strings and crafted records; a client fed 30 crafted server flights and 300 damaged ServerHellos.
  Each ends in an error within its deadline.
- **Client and server against each other** in one process and over TCP (`tests/loopback_test.ei`,
  `tests/tcp_test.ei`): 40 scenarios, 3 MB transfers each way, a flipped bit anywhere in the first 700 bytes of a
  server flight (only the two legacy record version bytes, which TLS 1.3 says to ignore, are accepted).
- **Constant-time helpers** (`tests/ct_test.ei`): the answers on every edge, and the running time of `ct.eq` and
  `ct.eq_pure` with a difference at the first and at the last of 65536 bytes is within a factor of 4 (an early exit
  would differ by thousands).
- ThreadSanitizer on the tests that use threads, and AddressSanitizer + UBSan on all of them with the crypto
  backend built the same way (`ASAN=1 sh scripts/test.sh`).

## Security notes

- Secrets (MAC tags, Finished values) are compared with `ct.eq` (`CRYPTO_memcmp`). The code of this package
  branches only on public data: message types, lengths, extension lists, certificates. It was written to that
  rule and read for it; no tool checks it, and the timing test is a coarse one. Nothing here is audited.
- Secret bytes (keys, traffic secrets) live in ordinary Eider lists and are not zeroed when dropped (the crypto
  package has the same property). A process that is swapped, dumped or exploited can
  leak them.
- Certificate checks that are *not* done are listed below; the ones that are done fail closed (an extension this
  package does not process and that is marked critical, or name constraints, make the certificate unusable).
- Sending is not padded and records are not fragmented adaptively: traffic analysis sees record sizes.

## Not done

- **RSA and P-384, what is covered.** Signature schemes `rsa_pss_rsae_sha256/384/512` (CertificateVerify and
  certificates), `rsa_pkcs1_sha256/384/512` (certificates only, as RFC 8446 4.2.3 says: never in CertificateVerify)
  and `ecdsa_secp384r1_sha384`; group secp384r1; X.509 chains signed with sha256/384/512WithRSAEncryption,
  RSASSA-PSS (SHA-2 with MGF1 of the same hash) and ecdsa-with-SHA256/384/512 over P-256 and P-384; RSA keys of
  2048 to 8192 bits and P-384 keys, in certificates and as server and client keys (PKCS#8, PKCS#1 "RSA PRIVATE KEY",
  SEC1). The system CA bundle of this machine: 117 of its 121 roots now verify as trust anchors (key supported and
  own signature checked), by key RSA-4096 59, P-384 37, RSA-2048 21, P-256 3 (one root, P-521, is not usable);
  by signature algorithm rsa-pkcs1-SHA256 53, ecdsa-SHA384 34, rsa-pkcs1-SHA384 20, ecdsa-SHA256 6,
  rsa-pkcs1-SHA512 4, ecdsa-SHA512 1. Before, 3 of 121 were usable. `tests/roots_survey.ei` prints this.
- **Not supported in signatures and keys**: SHA-1 signatures (`sha1WithRSAEncryption`: the 3 remaining roots, and
  the old GoDaddy/ValiCert chains), RSA keys under 2048 bits, RSASSA-PSS-OID keys (`rsa_pss_pss_*` schemes), PSS
  with an MGF1 hash different from the signature hash, RSA key generation, secp521r1 (so the one P-521 root).
- **Other curves**: secp521r1, X448, ffdhe, ML-KEM hybrids.
- **Resumption and early data**: no PSK, no session tickets (a NewSessionTicket is parsed and dropped, the client
  offers no PSK, the server issues none), no 0-RTT (a server that receives early_data without a PSK ignores it; no
  early data is ever accepted or sent), no HelloRetryRequest cookies from the server (a client echoes one).
- **Revocation and transparency**: no CRL, OCSP or stapled responses (a status_request is not sent), no SCT checks.
- **PKIX details**: name constraints (rejected), certificate policies and policy mappings (ignored), EKU
  constraints on intermediates, issuer/subject matching is byte equality of the DER names (RFC 5280 asks for
  normalised comparison), no check that a trust anchor's own signature verifies (it is trusted by being in the
  store), no certificate pinning API (a store holding the exact leaf works as one).
- **Server**: one identity per configuration (no certificate choice by SNI; `Conn.server_name` is there to pick a
  configuration before the handshake, which needs the ClientHello read first: not implemented), no ALPN callback,
  no client certificate request on an established connection (post-handshake authentication).
- **Other extensions**: record_size_limit / max_fragment_length, certificate compression, Encrypted Client Hello,
  signature_algorithms_cert, status_request.
- **TLS 1.2 and earlier**, SSLv2 hellos: refused. No renegotiation (TLS 1.3 has none).
- **I/O model**: the handshake blocks the calling task up to its deadline (it is not a state machine you can
  suspend); after it, the sans-I/O core (`conn.ei`) can be driven by any readiness loop through `try_recv`,
  `ready_to_read` and the `..._by` calls.
- **The crypto dependency** is the toolchain's own package, `[deps.crypto] toolchain = true` (Eider 0.7.6 and later
  ship `packages/crypto` and the AWS-LC backend in the toolchain), so an installed toolchain is enough; a program
  that uses eider-tls does the same in its eider.toml (`[deps.crypto] toolchain = true`, `uses = ["io"]`).
- No benchmarks; the handshake costs two P-256/X25519 operations plus the signature in the provider and some
  list copying in Eider.

## Layout

```
tls.ei         dial, accept_on, the package overview
client.ei      the client handshake            server.ei   the server handshake
conn.ei        Conn[S]: records, buffers, KeyUpdate, close, Reader and Writer
handshake.ei   message framing, parsing, serializing   keys.ei  the key schedule and transcript
record.ei      AEAD records, framing, limits   suite.ei, kex.ei, config.ei, alert.ei, wire.ei, ct.ei
x509.ei        certificates, chains, host names, trust stores   asn1.ei, pem.ei, keyfile.ei
docs/design.md            how the pieces fit, and the decisions
docs/http-integration.md  how eider-http will use it (an adapter plan, not done)
tests/                    *_test.ei with their .out, interop.sh, pki/ (fixtures), vectors/
```

## Developing

```sh
sh scripts/build.sh                 # check every module (with the installed toolchain, or EIDER_TOOLCHAIN=...)
sh scripts/test.sh                  # build, run every test, interop against openssl, TSan
ASAN=1 sh scripts/test.sh           # and AddressSanitizer + UBSan (builds the crypto backend sanitized: an eider-lang checkout as the toolchain)
sh tests/pki.sh /tmp/pki            # regenerate the test PKI (needs openssl; tests/pki is committed, valid to 2036)
```

The toolchain is the installed one (`eider toolchain install 0.7`) or, for unreleased work, an eider-lang checkout:
`EIDER_TOOLCHAIN=~/workplace/eider-lang sh scripts/test.sh`. The tests fix
the clock they validate certificates at (`ClientConfig.now`), so they do not depend on the date; `tests/interop.sh`
uses the real clock, and the fixtures expire in November 2036.

Used by: nothing yet (eider-http, see docs/http-integration.md).
