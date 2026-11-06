#!/bin/sh
# eider-tls's tests.
#
#   sh scripts/test.sh             scripts/build.sh, then every test
#   NOBUILD=1 sh scripts/test.sh   skip scripts/build.sh (the locks are already fetched)
#
# Every tests/*.ei and examples/*/tests/*.ei is run with the toolchain's compiler (`eider run`) and its
# output compared with the .out next to it. The tests in TSAN (they use threads) are then
# built once under ThreadSanitizer and run once each, when $CC can build a TSan program
# (else `skip`). Then tests/interop.sh runs the Eider client and server against the system's
# `openssl s_server` and `s_client` (`skip` when there is no openssl). Prints `ok   <test>` or `FAIL <test>` with a diff, then `ALL OK`; exits 1
# on a failure, 2 when there is no usable toolchain (scripts/env.sh).
#
#   ASAN=1 sh scripts/test.sh      also run every test under AddressSanitizer and UBSan, with
#                                  the crypto backend built the same way (minutes; the timing
#                                  test is left out: a sanitizer makes timings meaningless)
TSAN="tests/loopback_test.ei tests/hostile_peer_test.ei tests/tcp_test.ei"
here=$(cd "$(dirname "$0")/.." && pwd -P)
if [ -z "$NOBUILD" ]; then
  sh "$here/scripts/build.sh" || exit $?
fi
. "$here/scripts/env.sh"
cd "$here" || exit 1
fail=0
for f in tests/*.ei examples/*/tests/*.ei; do
  [ -f "$f" ] && [ -f "${f%.ei}.out" ] || continue
  got=$(ei run "$f" 2>&1 < /dev/null)
  if [ "$got" = "$(cat "${f%.ei}.out")" ]; then echo "ok   $f"; else echo "FAIL $f"; echo "$got" | diff "${f%.ei}.out" - | head -10; fail=1; fi
done
# interoperability with the system's openssl, both directions
if command -v openssl >/dev/null 2>&1; then
  B=$(mktemp -d)
  if ei build tests/interop_client.ei -o "$B/iclient" > "$B/log" 2>&1 && ei build tests/interop_server.ei -o "$B/iserver" >> "$B/log" 2>&1; then
    sh tests/interop.sh "$B" || fail=1
  else
    echo "FAIL interop: build"; cat "$B/log"; fail=1
  fi
  rm -rf "$B"
else
  echo "skip interop: no openssl on the PATH"
fi
if [ -n "$TSAN" ]; then
  T=$(mktemp -d)
  trap 'rm -rf "$T"' EXIT
  printf 'int main(void) { return 0; }\n' > "$T/probe.c"
  if ${CC:-cc} -fsanitize=thread -o "$T/probe" "$T/probe.c" 2>/dev/null && "$T/probe"; then
    for f in $TSAN; do
      if ! (EIDER_CACHE=off EIDER_CFLAGS="-fsanitize=thread -g"; export EIDER_CACHE EIDER_CFLAGS; ei build "$f" -o "$T/t") > "$T/log" 2>&1; then
        echo "FAIL $f (tsan): build"; cat "$T/log"; fail=1; continue
      fi
      got=$(TSAN_OPTIONS="halt_on_error=1 exitcode=66" "$T/t" < /dev/null 2>&1)
      if [ "$got" = "$(cat "${f%.ei}.out")" ]; then echo "ok   $f (tsan)"; else echo "FAIL $f (tsan)"; echo "$got" | diff "${f%.ei}.out" - | head -20; fail=1; fi
    done
  else
    echo "skip tsan runs ($TSAN): ${CC:-cc} cannot build a -fsanitize=thread program"
  fi
fi
# the sanitized crypto backend is built by an eider-lang checkout's scripts/crypto-build.sh
if [ -n "$ASAN" ] && [ ! -f "$toolchain/scripts/crypto-build.sh" ]; then
  echo "skip asan runs: $toolchain is an installed toolchain (the sanitized crypto backend needs an eider-lang checkout: EIDER_TOOLCHAIN=...)"
  ASAN=
fi
if [ -n "$ASAN" ]; then
  A=$(mktemp -d)
  trap 'rm -rf "$A"' EXIT
  for f in tests/*_test.ei; do
    [ "$f" = tests/ct_test.ei ] && continue
    [ -f "${f%.ei}.out" ] || continue
    if ! (EIDER_CACHE=off EIDER_CRYPTO_SAN=1 EIDER_CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"; export EIDER_CACHE EIDER_CRYPTO_SAN EIDER_CFLAGS; ei build "$f" -o "$A/t") > "$A/log" 2>&1; then
      echo "FAIL $f (asan): build"; cat "$A/log"; fail=1; continue
    fi
    got=$(ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$A/t" < /dev/null 2>&1)
    if [ "$got" = "$(cat "${f%.ei}.out")" ]; then echo "ok   $f (asan+ubsan)"; else echo "FAIL $f (asan+ubsan)"; echo "$got" | diff "${f%.ei}.out" - | head -20; fail=1; fi
  done
fi
[ $fail = 0 ] && echo "ALL OK"
exit $fail
