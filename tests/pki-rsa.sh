#!/bin/sh
# Generates the RSA and P-384 test PKI with the system openssl into the directory $1 (the
# committed copies are in tests/pki; tests/pki.sh makes the Ed25519 / P-256 ones):
#
#   rsa-root.pem            self-signed RSA-3072 CA, sha384WithRSAEncryption (pathlen 1)
#   rsa-inter.pem           RSA-2048 intermediate signed by it with sha256WithRSAEncryption (pathlen 0)
#   rsa2048.pem/.key        RSA-2048 server leaf signed by the intermediate (SAN localhost, *.example.test, 127.0.0.1, ::1)
#   rsa2048chain.pem        rsa2048.pem followed by rsa-inter.pem
#   rsa3072.pem/.key        RSA-3072 leaf signed directly by the root with sha384WithRSAEncryption
#   rsa-sha512.pem/.key     RSA-2048 leaf signed by the root with sha512WithRSAEncryption
#   rsa-pss.pem/.key        RSA-2048 leaf signed by the root with RSASSA-PSS (sha256, MGF1 sha256, salt 32)
#   rsa-pss384.pem/.key     the same with sha384 and salt 48
#   rsa-pss-mgf1sha1.pem/.key   RSASSA-PSS with SHA-256 but MGF1 with SHA-1: not supported
#   rsa-client.pem/.key     RSA-2048 client-auth leaf signed by the root
#   p384-root.pem           self-signed P-384 CA, ecdsa-with-SHA384 (pathlen 1)
#   p384.pem/.key           P-384 server leaf signed by it with ecdsa-with-SHA384
#   p256-by-p384.pem/.key   P-256 leaf signed by the P-384 root with ecdsa-with-SHA384
#   p256-sha512.pem/.key    P-256 leaf signed by the P-384 root with ecdsa-with-SHA512
#   p256-root.pem           self-signed P-256 CA, ecdsa-with-SHA256
#   p384-by-p256.pem/.key   P-384 leaf signed by the P-256 root with ecdsa-with-SHA256
#   p384-client.pem/.key    P-384 client-auth leaf signed by the P-384 root
#   rsa2048.pkcs1.key, p384.sec1.key, p256-by-p384.sec1.key   the same keys as PKCS#1 / SEC1 PEM
#   rsa1024-root.pem        a self-signed 1024-bit RSA CA, with rsa1024-leaf.pem (RSA-2048) signed by it:
#                           a chain the key policy refuses
#
# Exit 0 when done, 3 when openssl is missing.
set -e
d=$1
command -v openssl >/dev/null 2>&1 || { echo "pki-rsa.sh: no openssl" >&2; exit 3; }
mkdir -p "$d"
cd "$d"
cat > ca.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = x
[root_ext]
basicConstraints = critical,CA:TRUE,pathlen:1
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
[inter_ext]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf_ext]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth,clientAuth
subjectAltName = DNS:localhost,DNS:*.example.test,IP:127.0.0.1,IP:::1
authorityKeyIdentifier = keyid
[client_ext]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:client.test
EOF
q="-batch"
rsakey() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:$2 -out "$1.key" 2>/dev/null; }
eckey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:$2 -pkeyopt ec_param_enc:named_curve -out "$1.key" 2>/dev/null; }
# leaf <name> <CA cert> <CA key> <ext> <digest> [more x509 options]
leaf() {
  n=$1; ca=$2; cak=$3; ext=$4; h=$5; shift 5
  openssl req $q -new -key "$n.key" -subj "/CN=localhost" -out "$n.csr"
  openssl x509 -req -in "$n.csr" -CA "$ca" -CAkey "$cak" -CAcreateserial -$h -not_before 20260101000000Z -not_after 20360101000000Z -extfile ca.cnf -extensions "$ext" "$@" -out "$n.pem" 2>/dev/null
}

# RSA
rsakey rsa-root 3072
openssl req $q -new -x509 -key rsa-root.key -sha384 -not_before 20260101000000Z -not_after 20360101000000Z -subj "/CN=Eider RSA Test Root" -config ca.cnf -extensions root_ext -out rsa-root.pem
rsakey rsa-inter 2048
openssl req $q -new -key rsa-inter.key -subj "/CN=Eider RSA Test Intermediate" -out rsa-inter.csr
openssl x509 -req -in rsa-inter.csr -CA rsa-root.pem -CAkey rsa-root.key -CAcreateserial -sha256 -not_before 20260101000000Z -not_after 20360101000000Z -extfile ca.cnf -extensions inter_ext -out rsa-inter.pem 2>/dev/null
rsakey rsa2048 2048; leaf rsa2048 rsa-inter.pem rsa-inter.key leaf_ext sha256
cat rsa2048.pem rsa-inter.pem > rsa2048chain.pem
rsakey rsa3072 3072; leaf rsa3072 rsa-root.pem rsa-root.key leaf_ext sha384
rsakey rsa-sha512 2048; leaf rsa-sha512 rsa-root.pem rsa-root.key leaf_ext sha512
rsakey rsa-pss 2048; leaf rsa-pss rsa-root.pem rsa-root.key leaf_ext sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256
rsakey rsa-pss384 2048; leaf rsa-pss384 rsa-root.pem rsa-root.key leaf_ext sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:48 -sigopt rsa_mgf1_md:sha384
rsakey rsa-pss-mgf1sha1 2048; leaf rsa-pss-mgf1sha1 rsa-root.pem rsa-root.key leaf_ext sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha1
rsakey rsa-client 2048; leaf rsa-client rsa-root.pem rsa-root.key client_ext sha256

# P-384 and P-256 under P-384 and P-256 roots
eckey p384-root secp384r1
openssl req $q -new -x509 -key p384-root.key -sha384 -not_before 20260101000000Z -not_after 20360101000000Z -subj "/CN=Eider P-384 Test Root" -config ca.cnf -extensions root_ext -out p384-root.pem
eckey p384 secp384r1; leaf p384 p384-root.pem p384-root.key leaf_ext sha384
eckey p256-by-p384 prime256v1; leaf p256-by-p384 p384-root.pem p384-root.key leaf_ext sha384
eckey p256-sha512 prime256v1; leaf p256-sha512 p384-root.pem p384-root.key leaf_ext sha512
eckey p384-client secp384r1; leaf p384-client p384-root.pem p384-root.key client_ext sha384
eckey p256-root prime256v1
openssl req $q -new -x509 -key p256-root.key -sha256 -not_before 20260101000000Z -not_after 20360101000000Z -subj "/CN=Eider P-256 Test Root" -config ca.cnf -extensions root_ext -out p256-root.pem
eckey p384-by-p256 secp384r1; leaf p384-by-p256 p256-root.pem p256-root.key leaf_ext sha256

# a root the key policy refuses
rsakey rsa1024-root 1024
openssl req $q -new -x509 -key rsa1024-root.key -sha256 -not_before 20260101000000Z -not_after 20360101000000Z -subj "/CN=Eider 1024-bit Root" -config ca.cnf -extensions root_ext -out rsa1024-root.pem
rsakey rsa1024-leaf 2048; leaf rsa1024-leaf rsa1024-root.pem rsa1024-root.key leaf_ext sha256
# the other private key encodings: PKCS#1 (RSA PRIVATE KEY) and SEC1 (EC PRIVATE KEY)
openssl rsa -in rsa2048.key -traditional -out rsa2048.pkcs1.key 2>/dev/null
openssl ec -in p384.key -out p384.sec1.key 2>/dev/null
openssl ec -in p256-by-p384.key -out p256-by-p384.sec1.key 2>/dev/null
rm -f ./*.csr ./*.srl ca.cnf
echo "pki-rsa ok"
