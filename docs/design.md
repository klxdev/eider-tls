# Design

## Layers

1. `wire`, `ct`, `asn1`, `pem`: bounded readers and writers, constant-time helpers, a strict DER reader, PEM.
   Every read is checked against the remaining length and returns an `Option`/`Result`; nothing indexes a list
   with a length taken from the peer before checking it.
2. `suite`, `keys`, `record`, `kex`: the cipher suites, HKDF-Expand-Label and the key schedule, the AEAD record
   protector (nonce = IV xor sequence number, additional data = the record header, inner content type, 16384 byte
   plaintext limit, 2^24 record rekey threshold), key exchange and signatures (via the crypto package).
3. `handshake`: message framing (4 byte header, 128 KiB limit) and one parser and one serializer per message.
   Parsers reject duplicate extensions and trailing bytes.
4. `x509`, `keyfile`, `config`: certificates, chain verification, private keys, the configuration types.
5. `conn`, `client`, `server`, `tls`: the connection and the two handshakes.

## Decisions

- **Sans-I/O core.** `Conn[S]` keeps an input buffer and an output buffer. `pop_record` takes one record from the
  input, `queue` seals application data into the output, `fail` records an alert and kills the connection.
  The blocking functions (`recv`, `send`, `close`) and the deadline functions (`*_by`) are thin loops around
  those. Reason: Eider traits carry capabilities (`Reader.read` is `uses io`, a deadline needs `clock`), and there
  is no capability polymorphism, so one body cannot serve both; the core uses neither.
- **Timeouts are not fatal on the read side**: a read that times out has consumed nothing it cannot keep in
  `inbuf`. A write that times out may have sent half a record, so it fails the connection.
- **Every failure to open a record is bad_record_mac**, whatever the cause (tag, padding, content type), as the
  RFC asks, so a peer learns nothing about which check failed.
- **Verification cannot be forgotten**: `client_config(name, roots)` takes the name and the trust store;
  `Insecure` is a separate, explicitly named value.
- **Fail closed in X.509**: unknown critical extensions, name constraints, unsupported signature algorithms and
  unsupported keys make a chain unusable. The chain search is depth first with backtracking over the store and
  the presented intermediates, depth at most 8.
- **Own DER reader**, strict: definite lengths only, minimal length encodings, no trailing data, booleans 0x00 or
  0xff, minimal integers, validated time strings.
- **HelloRetryRequest** is implemented in both roles; the transcript is restarted with the message_hash
  construction. A second HRR is an error.
- **Middlebox compatibility mode**: the client sends a legacy session id and a change_cipher_spec, the server
  tolerates one.

## Limits

Records 16384 plaintext / 16640 protected, handshake messages 128 KiB, 16 certificates per message, chain depth
8, 4096 PEM blocks per file.
