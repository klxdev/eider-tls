#!/usr/bin/env python3
"""Reference values for tests/keys_test.ei, computed with Python's hashlib and hmac, a second
implementation of RFC 8446 section 7.1 (HKDF-Expand-Label, Derive-Secret) and section 7.3
(traffic keys) that shares no code with the package. Run:

    python3 tests/vectors/keysched.py > tests/keys_test.out

The first two lines of each hash are the values RFC 8448 section 3 ("Simple 1-RTT Handshake")
prints for the SHA-256 key schedule with no PSK (the early secret and the first
"derived" secret); the rest follow the same construction from fixed inputs.
"""
import hashlib
import hmac
import struct


def extract(h, salt, ikm):
    hl = h().digest_size
    return hmac.new(salt if salt else b"\0" * hl, ikm, h).digest()


def expand(h, prk, info, length):
    out = b""
    t = b""
    i = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), h).digest()
        out += t
        i += 1
    return out[:length]


def expand_label(h, secret, label, ctx, length):
    full = b"tls13 " + label
    info = struct.pack(">H", length) + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return expand(h, secret, info, length)


def derive(h, secret, label, th):
    return expand_label(h, secret, label, th, h().digest_size)


def show(name, b):
    print(name, b.hex())


for hname, h, klen in (("sha256", hashlib.sha256, 16), ("sha384", hashlib.sha384, 32), ("sha256-chacha", hashlib.sha256, 32)):
    hl = h().digest_size
    print("== " + hname)
    ecdhe = bytes(range(32))
    early = extract(h, b"", b"\0" * hl)
    show("early", early)
    empty = h(b"").digest()
    d1 = derive(h, early, b"derived", empty)
    show("derived", d1)
    hs = extract(h, d1, ecdhe)
    show("handshake", hs)
    th1 = h(b"client hello|server hello").digest()
    c_hs = derive(h, hs, b"c hs traffic", th1)
    s_hs = derive(h, hs, b"s hs traffic", th1)
    show("c_hs", c_hs)
    show("s_hs", s_hs)
    show("c_hs_key", expand_label(h, c_hs, b"key", b"", klen))
    show("c_hs_iv", expand_label(h, c_hs, b"iv", b"", 12))
    show("s_hs_key", expand_label(h, s_hs, b"key", b"", klen))
    show("s_hs_iv", expand_label(h, s_hs, b"iv", b"", 12))
    fk = expand_label(h, s_hs, b"finished", b"", hl)
    th2 = h(b"client hello|server hello|ee|cert|cv").digest()
    show("server_finished", hmac.new(fk, th2, h).digest())
    d2 = derive(h, hs, b"derived", empty)
    master = extract(h, d2, b"\0" * hl)
    show("master", master)
    th3 = h(b"client hello|server hello|ee|cert|cv|fin").digest()
    c_ap = derive(h, master, b"c ap traffic", th3)
    s_ap = derive(h, master, b"s ap traffic", th3)
    show("c_ap", c_ap)
    show("s_ap", s_ap)
    show("c_ap_key", expand_label(h, c_ap, b"key", b"", klen))
    show("c_ap_iv", expand_label(h, c_ap, b"iv", b"", 12))
    show("c_ap_next", expand_label(h, c_ap, b"traffic upd", b"", hl))
    content = b" " * 64 + b"TLS 1.3, server CertificateVerify" + b"\0" + th2
    show("cv_content_sha256", hashlib.sha256(content).digest())
