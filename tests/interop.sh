#!/bin/sh
# Interoperability with the system's `openssl`, in both directions, over loopback:
#
#   sh tests/interop.sh <dir with the built iclient and iserver>
#
# - the Eider client (tests/interop_client.ei) against `openssl s_server`, and
# - the Eider server (tests/interop_server.ei) against `openssl s_client`,
#
# with the certificates in tests/pki (a P-256 root, an Ed25519 intermediate, Ed25519 and P-256
# leaves). Prints `ok   interop: <case>` or `FAIL interop: <case>`; exits 1 on a failure and
# 0 when everything passed or when there is no openssl (`skip`).
here=$(cd "$(dirname "$0")/.." && pwd -P)
bin=$1
P=$here/tests/pki
if ! command -v openssl >/dev/null 2>&1; then
  echo "skip interop: no openssl on the PATH"
  exit 0
fi
[ -x "$bin/iclient" ] && [ -x "$bin/iserver" ] || { echo "FAIL interop: $bin has no iclient and iserver"; exit 1; }
T=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$T"' EXIT
fail=0
port=$(( 20000 + $$ % 20000 ))
n=0

check() { # name, output file, pattern...
  name=$1; out=$2; shift 2
  for pat in "$@"; do
    if ! grep -q -- "$pat" "$out"; then
      echo "FAIL interop: $name (missing: $pat)"; sed 's/^/    | /' "$out" | head -20; fail=1; return
    fi
  done
  echo "ok   interop: $name"
}

absent() { # name, output file, pattern: the pattern must not appear
  if grep -q -- "$3" "$2"; then echo "FAIL interop: $1 (unexpected: $3)"; sed 's/^/    | /' "$2" | head -20; fail=1; else echo "ok   interop: $1"; fi
}

wait_for() { # file, pattern
  i=0
  while [ $i -lt 100 ]; do
    grep -q -- "$2" "$1" 2>/dev/null && return 0
    sleep 0.1; i=$((i + 1))
  done
  return 1
}

# ---- the Eider client against openssl s_server: client <name> <s_server args> -- <client args>
client() {
  name=$1; shift
  n=$((n + 1)); port=$((port + 1))
  sargs=""
  while [ "$1" != "--" ]; do sargs="$sargs $1"; shift; done
  shift
  # shellcheck disable=SC2086
  openssl s_server -accept $port -www -naccept 1 $sargs > "$T/s$n.log" 2>&1 &
  spid=$!
  wait_for "$T/s$n.log" ACCEPT || { echo "FAIL interop: $name (s_server did not start)"; cat "$T/s$n.log"; fail=1; return 1; }
  "$bin/iclient" $port "${CA:-$P/root.pem}" "$@" > "$T/c$n.out" 2>&1
  echo "exit $?" >> "$T/c$n.out"
  kill $spid 2>/dev/null; wait $spid 2>/dev/null
  cur=$T/c$n.out
}

# ---- the Eider server against openssl s_client: server <name> <server args> -- <s_client args>
server() {
  name=$1; shift
  n=$((n + 1)); port=$((port + 1))
  sargs=""
  while [ "$1" != "--" ]; do sargs="$sargs $1"; shift; done
  shift
  # shellcheck disable=SC2086
  "$bin/iserver" $port $sargs > "$T/s$n.log" 2>&1 &
  spid=$!
  wait_for "$T/s$n.log" listening || { echo "FAIL interop: $name (iserver did not start)"; cat "$T/s$n.log"; fail=1; return 1; }
  printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client -connect 127.0.0.1:$port "$@" > "$T/c$n.out" 2>&1
  echo "exit $?" >> "$T/c$n.out"
  wait $spid 2>/dev/null
  cat "$T/s$n.log" >> "$T/c$n.out"
  cur=$T/c$n.out
}

SC="-CAfile $P/root.pem -verify_return_error -ign_eof"

# ======== client against s_server
client "client / s_server, Ed25519 leaf via intermediate, TLS_AES_128_GCM_SHA256, X25519" -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost && check "$name" "$cur" "connected TLS_AES_128_GCM_SHA256" "alpn none" "clean close" "Cipher *: *TLS_AES_128_GCM_SHA256" "exit 0"
client "client / s_server, TLS_AES_256_GCM_SHA384" -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost suites=aes256 && check "$name" "$cur" "connected TLS_AES_256_GCM_SHA384" "clean close"
client "client / s_server, TLS_CHACHA20_POLY1305_SHA256" -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost suites=chacha && check "$name" "$cur" "connected TLS_CHACHA20_POLY1305_SHA256" "clean close"
client "client / s_server, ECDSA P-256 leaf" -cert $P/ec.pem -key $P/ec.key -- localhost && check "$name" "$cur" "connected TLS_AES_128_GCM_SHA256" "clean close"
client "client / s_server, secp256r1 key exchange" -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost groups=p256 && check "$name" "$cur" "connected" "clean close"
client "client / s_server, HelloRetryRequest (share for P-256, server wants X25519)" -groups X25519 -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost groups=both share=p256 && check "$name" "$cur" "connected" "hello retry" "clean close"
client "client / s_server, HelloRetryRequest (share for X25519, server wants P-256)" -groups P-256 -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost groups=both share=x25519 && check "$name" "$cur" "connected" "hello retry" "clean close"
client "client / s_server, ALPN http/1.1" -alpn h2,http/1.1 -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost alpn=http/1.1 && check "$name" "$cur" "alpn http/1.1" "clean close"
client "client / s_server, ALPN: no protocol in common" -alpn h2 -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost alpn=spdy/3 && check "$name" "$cur" "handshake failed" "no_application_protocol"
client "client / s_server, key updates while sending" -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost rekey=1 && check "$name" "$cur" "connected" "key updates sent [1-9]" "clean close" "exit 0"
client "client / s_server, wildcard name" -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- www.example.test && check "$name" "$cur" "connected" "clean close"
client "client / s_server, wrong host name" -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- wrong.example && check "$name" "$cur" "handshake failed: tls: certificate is not valid for the host name" "exit 2"
client "client / s_server, untrusted issuer" -cert $P/ec.pem -key $P/ec.key -- localhost && true
n=$((n + 1)); port=$((port + 1))
openssl s_server -accept $port -www -naccept 1 -cert $P/ec.pem -key $P/ec.key > "$T/s$n.log" 2>&1 &
spid=$!
wait_for "$T/s$n.log" ACCEPT
"$bin/iclient" $port "$P/other-root.pem" localhost > "$T/c$n.out" 2>&1; echo "exit $?" >> "$T/c$n.out"
kill $spid 2>/dev/null; wait $spid 2>/dev/null
check "client / s_server, root not in the trust store" "$T/c$n.out" "handshake failed: tls: unable to find a trusted issuer" "exit 2"
client "client / s_server, expired certificate" -cert $P/expired.pem -key $P/expired.key -- localhost && check "$name" "$cur" "handshake failed: tls: certificate has expired" "exit 2"
client "client / s_server, missing intermediate" -cert $P/ed.pem -key $P/ed.key -- localhost && check "$name" "$cur" "handshake failed: tls: unable to find a trusted issuer" "exit 2"
client "client / s_server, server certificate for clients only" -cert $P/noeku.pem -key $P/noeku.key -- localhost && check "$name" "$cur" "handshake failed: tls: certificate is not valid for this use\|handshake failed" "exit 2"
client "client / s_server, client certificate requested and sent" -Verify 1 -CAfile $P/root.pem -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost cert=$P/client.pem:$P/client.key && check "$name" "$cur" "connected" "clean close" "exit 0"
client "client / s_server, client certificate required but none configured" -Verify 1 -CAfile $P/root.pem -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost && check "$name" "$cur" "failed"
client "client / s_server, no ChaCha20 when only AES is offered by the server" -ciphersuites TLS_AES_128_GCM_SHA256 -cert $P/ed.pem -cert_chain $P/inter.pem -key $P/ed.key -- localhost suites=chacha && check "$name" "$cur" "handshake failed"

# ---- RSA and P-384 (certificates from tests/pki-rsa.sh; the Eider client trusts their roots through $CA)
CA=$P/rsa-root.pem
client "client / s_server, RSA-2048 leaf via an RSA intermediate, rsa_pss_rsae_sha256" -cert $P/rsa2048.pem -cert_chain $P/rsa-inter.pem -key $P/rsa2048.key -sigalgs RSA-PSS+SHA256 -- localhost && check "$name" "$cur" "connected" "clean close" "exit 0"
client "client / s_server, RSA-2048 leaf, rsa_pss_rsae_sha384" -cert $P/rsa2048.pem -cert_chain $P/rsa-inter.pem -key $P/rsa2048.key -sigalgs RSA-PSS+SHA384 -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, RSA-2048 leaf, rsa_pss_rsae_sha512" -cert $P/rsa2048.pem -cert_chain $P/rsa-inter.pem -key $P/rsa2048.key -sigalgs RSA-PSS+SHA512 -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, RSA-3072 leaf signed with sha384WithRSAEncryption" -cert $P/rsa3072.pem -key $P/rsa3072.key -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, RSA leaf signed with sha512WithRSAEncryption" -cert $P/rsa-sha512.pem -key $P/rsa-sha512.key -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, RSA leaf signed with RSASSA-PSS (sha256)" -cert $P/rsa-pss.pem -key $P/rsa-pss.key -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, RSA leaf signed with RSASSA-PSS (sha384)" -cert $P/rsa-pss384.pem -key $P/rsa-pss384.key -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, RSA-2048 leaf, the intermediate missing" -cert $P/rsa2048.pem -key $P/rsa2048.key -- localhost && check "$name" "$cur" "handshake failed: tls: unable to find a trusted issuer" "exit 2"
client "client / s_server, RSA leaf under a 1024-bit root is refused" -cert $P/rsa1024-leaf.pem -key $P/rsa1024-leaf.key -- localhost && check "$name" "$cur" "handshake failed" "exit 2"
client "client / s_server, RSA client certificate requested and sent" -Verify 1 -CAfile $P/rsa-root.pem -cert $P/rsa3072.pem -key $P/rsa3072.key -- localhost cert=$P/rsa-client.pem:$P/rsa-client.key && check "$name" "$cur" "connected" "clean close" "exit 0"
CA=$P/p384-root.pem
client "client / s_server, P-384 leaf, ecdsa_secp384r1_sha384" -cert $P/p384.pem -key $P/p384.key -- localhost && check "$name" "$cur" "connected" "clean close" "exit 0"
client "client / s_server, P-384 leaf, secp384r1 key exchange" -cert $P/p384.pem -key $P/p384.key -groups P-384 -- localhost groups=p384 && check "$name" "$cur" "connected" "clean close"
client "client / s_server, HelloRetryRequest into secp384r1" -groups P-384 -cert $P/p384.pem -key $P/p384.key -- localhost groups=all && check "$name" "$cur" "connected" "clean close"
client "client / s_server, P-256 leaf signed by a P-384 root (ecdsa-with-SHA384)" -cert $P/p256-by-p384.pem -key $P/p256-by-p384.key -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, P-256 leaf signed by a P-384 root (ecdsa-with-SHA512)" -cert $P/p256-sha512.pem -key $P/p256-sha512.key -- localhost && check "$name" "$cur" "connected" "clean close"
client "client / s_server, P-384 client certificate requested and sent" -Verify 1 -CAfile $P/p384-root.pem -cert $P/p384.pem -key $P/p384.key -- localhost cert=$P/p384-client.pem:$P/p384-client.key && check "$name" "$cur" "connected" "clean close" "exit 0"
CA=$P/p256-root.pem
client "client / s_server, P-384 leaf signed by a P-256 root (ecdsa-with-SHA256)" -cert $P/p384-by-p256.pem -key $P/p384-by-p256.key -- localhost && check "$name" "$cur" "connected" "clean close"
CA=

# ======== server against s_client
server "server / s_client, Ed25519 chain, AES-128-GCM" $P/edchain.pem $P/ed.key -- $SC -servername localhost -verify_hostname localhost -brief && check "$name" "$cur" "Protocol version: TLSv1.3" "Ciphersuite: TLS_AES_128_GCM_SHA256" "Verification: OK" "hello from eider tls" "sni localhost" "served TLS_AES_128_GCM_SHA256"
server "server / s_client, TLS_AES_256_GCM_SHA384" $P/edchain.pem $P/ed.key suites=aes256 -- $SC -servername localhost -brief -ciphersuites TLS_AES_256_GCM_SHA384 && check "$name" "$cur" "Ciphersuite: TLS_AES_256_GCM_SHA384" "Verification: OK" "hello from eider tls"
server "server / s_client, TLS_CHACHA20_POLY1305_SHA256" $P/edchain.pem $P/ed.key suites=chacha -- $SC -servername localhost -brief -ciphersuites TLS_CHACHA20_POLY1305_SHA256 && check "$name" "$cur" "Ciphersuite: TLS_CHACHA20_POLY1305_SHA256" "hello from eider tls"
server "server / s_client, ECDSA P-256 leaf" $P/ec.pem $P/ec.key -- $SC -servername localhost -verify_hostname localhost -brief && check "$name" "$cur" "Verification: OK" "Signature type: ecdsa_secp256r1_sha256" "hello from eider tls"
server "server / s_client, secp256r1 key exchange" $P/edchain.pem $P/ed.key -- $SC -servername localhost -brief -groups P-256 && check "$name" "$cur" "Verification: OK" "hello from eider tls"
server "server / s_client, HelloRetryRequest (client share P-256, server X25519 only)" $P/edchain.pem $P/ed.key groups=x25519 -- $SC -servername localhost -brief -groups P-256:X25519 && check "$name" "$cur" "Verification: OK" "hello from eider tls" "hello retry"
server "server / s_client, HelloRetryRequest (client share X25519, server P-256 only)" $P/edchain.pem $P/ed.key groups=p256 -- $SC -servername localhost -brief -groups X25519:P-256 && check "$name" "$cur" "Verification: OK" "hello from eider tls" "hello retry"
server "server / s_client, ALPN" $P/edchain.pem $P/ed.key alpn=h2,http/1.1 -- $SC -servername localhost -brief -alpn http/1.1 && check "$name" "$cur" "alpn http/1.1"
server "server / s_client, key updates while sending" $P/edchain.pem $P/ed.key rekey=1 -- $SC -servername localhost -brief && check "$name" "$cur" "hello from eider tls" "key updates sent [1-9]"
server "server / s_client, wildcard certificate name" $P/edchain.pem $P/ed.key -- $SC -servername www.example.test -verify_hostname www.example.test -brief && check "$name" "$cur" "Verification: OK" "sni www.example.test"
server "server / s_client, IP address in the certificate" $P/edchain.pem $P/ed.key -- $SC -verify_ip 127.0.0.1 -brief && check "$name" "$cur" "Verification: OK" "hello from eider tls"
server "server / s_client, wrong host name is rejected by the client" $P/edchain.pem $P/ed.key -- $SC -verify_hostname wrong.example -brief && absent "$name" "$cur" "hello from eider tls"
server "server / s_client, client certificate" $P/edchain.pem $P/ed.key clientca=$P/root.pem require=1 -- $SC -servername localhost -brief -cert $P/client.pem -key $P/client.key && check "$name" "$cur" "hello from eider tls" "client certificates [12]"
server "server / s_client, client certificate requested, none sent" $P/edchain.pem $P/ed.key clientca=$P/root.pem -- $SC -servername localhost -brief && check "$name" "$cur" "hello from eider tls" "client certificates 0"
server "server / s_client, client certificate required, none sent" $P/edchain.pem $P/ed.key clientca=$P/root.pem require=1 -- $SC -servername localhost -brief && absent "$name" "$cur" "hello from eider tls"
server "server / s_client, client certificate from another CA" $P/edchain.pem $P/ed.key clientca=$P/other-root.pem require=1 -- $SC -servername localhost -brief -cert $P/client.pem -key $P/client.key && absent "$name" "$cur" "hello from eider tls"
server "server / s_client, ALPN with nothing in common" $P/edchain.pem $P/ed.key alpn=h2 -- $SC -servername localhost -brief -alpn spdy/3 && absent "$name" "$cur" "hello from eider tls"
server "server / s_client, TLS 1.2 only client is refused" $P/edchain.pem $P/ed.key -- $SC -servername localhost -brief -tls1_2 && absent "$name" "$cur" "hello from eider tls"

# ---- RSA and P-384 servers
SCR="-CAfile $P/rsa-root.pem -verify_return_error -ign_eof"
SCP="-CAfile $P/p384-root.pem -verify_return_error -ign_eof"
server "server / s_client, RSA-2048 chain, rsa_pss_rsae_sha256" $P/rsa2048chain.pem $P/rsa2048.key -- $SCR -servername localhost -verify_hostname localhost -brief -sigalgs RSA-PSS+SHA256 && check "$name" "$cur" "Verification: OK" "Signature type: rsa_pss_rsae_sha256" "Hash used: SHA256" "hello from eider tls"
server "server / s_client, RSA-2048 chain, rsa_pss_rsae_sha384" $P/rsa2048chain.pem $P/rsa2048.key -- $SCR -servername localhost -brief -sigalgs RSA-PSS+SHA384 && check "$name" "$cur" "Verification: OK" "Signature type: rsa_pss_rsae_sha384" "Hash used: SHA384" "hello from eider tls"
server "server / s_client, RSA-2048 chain, rsa_pss_rsae_sha512" $P/rsa2048chain.pem $P/rsa2048.key -- $SCR -servername localhost -brief -sigalgs RSA-PSS+SHA512 && check "$name" "$cur" "Verification: OK" "Hash used: SHA512" "hello from eider tls"
server "server / s_client, RSA-3072 leaf (sha384WithRSAEncryption)" $P/rsa3072.pem $P/rsa3072.key -- $SCR -servername localhost -brief && check "$name" "$cur" "Verification: OK" "Signature type: rsa_pss_rsae_sha256" "hello from eider tls"
server "server / s_client, RSA key from a PKCS#1 file" $P/rsa2048chain.pem $P/rsa2048.pkcs1.key -- $SCR -servername localhost -brief && check "$name" "$cur" "Verification: OK" "hello from eider tls"
server "server / s_client, RSA leaf, TLS_AES_256_GCM_SHA384 and ChaCha20" $P/rsa2048chain.pem $P/rsa2048.key suites=chacha -- $SCR -servername localhost -brief -ciphersuites TLS_CHACHA20_POLY1305_SHA256 && check "$name" "$cur" "Ciphersuite: TLS_CHACHA20_POLY1305_SHA256" "hello from eider tls"
server "server / s_client, RSA leaf, a client that offers only ECDSA is refused" $P/rsa2048chain.pem $P/rsa2048.key -- $SCR -servername localhost -brief -sigalgs ECDSA+SHA256 && absent "$name" "$cur" "hello from eider tls"
server "server / s_client, P-384 leaf, ecdsa_secp384r1_sha384" $P/p384.pem $P/p384.key -- $SCP -servername localhost -verify_hostname localhost -brief && check "$name" "$cur" "Verification: OK" "Signature type: ecdsa_secp384r1_sha384" "hello from eider tls"
server "server / s_client, P-384 leaf from a SEC1 file" $P/p384.pem $P/p384.sec1.key -- $SCP -servername localhost -brief && check "$name" "$cur" "Verification: OK" "hello from eider tls"
server "server / s_client, P-384 leaf, secp384r1 key exchange" $P/p384.pem $P/p384.key -- $SCP -servername localhost -brief -groups P-384 && check "$name" "$cur" "Verification: OK" "Peer Temp Key: ECDH, secp384r1" "hello from eider tls"
server "server / s_client, HelloRetryRequest (client share X25519, server secp384r1 only)" $P/p384.pem $P/p384.key groups=p384 -- $SCP -servername localhost -brief -groups X25519:P-384 && check "$name" "$cur" "Verification: OK" "hello from eider tls" "hello retry"
server "server / s_client, P-256 leaf signed by a P-384 root" $P/p256-by-p384.pem $P/p256-by-p384.key -- $SCP -servername localhost -brief && check "$name" "$cur" "Verification: OK" "Signature type: ecdsa_secp256r1_sha256" "hello from eider tls"
server "server / s_client, RSA client certificate" $P/rsa2048chain.pem $P/rsa2048.key clientca=$P/rsa-root.pem require=1 -- $SCR -servername localhost -brief -cert $P/rsa-client.pem -key $P/rsa-client.key && check "$name" "$cur" "hello from eider tls" "client certificates [12]"
server "server / s_client, P-384 client certificate" $P/rsa2048chain.pem $P/rsa2048.key clientca=$P/p384-root.pem require=1 -- $SCR -servername localhost -brief -cert $P/p384-client.pem -key $P/p384-client.key && check "$name" "$cur" "hello from eider tls" "client certificates [12]"

[ $fail = 0 ] && echo "interop ok"
exit $fail
