#!/bin/sh
# Generates a test PKI with the system openssl into the directory $1:
#
#   root.pem        self-signed ECDSA P-256 CA (pathlen 1)
#   inter.pem       intermediate CA (Ed25519 key, signed by the root, pathlen 0)
#   ed.pem/ed.key   server leaf with an Ed25519 key, signed by the intermediate
#                   (SAN: localhost, *.example.test, 127.0.0.1, ::1)
#   ec.pem/ec.key   server leaf with an ECDSA P-256 key, signed by the root, SAN localhost
#   edchain.pem     ed.pem followed by inter.pem
#   expired.pem/.key  a leaf whose validity ended in 2020
#   other-root.pem  a second, unrelated root
#   client.pem/.key client-auth leaf signed by the root
#   leafsigned.pem  a certificate signed by ed.pem, a leaf (so not a CA)
#   noeku.pem       a leaf for localhost with EKU clientAuth only (not valid for servers)
#
# Exit 0 when done, 3 when openssl is missing.
set -e
d=$1
command -v openssl >/dev/null 2>&1 || { echo "pki.sh: no openssl" >&2; exit 3; }
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
[noeku_ext]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = clientAuth
subjectAltName = DNS:localhost
EOF
q="-batch"
openssl ecparam -name prime256v1 -genkey -noout -out root.key
openssl req $q -new -x509 -key root.key -sha256 -days 3650 -subj "/CN=Eider Test Root" -config ca.cnf -extensions root_ext -out root.pem
openssl genpkey -algorithm ed25519 -out inter.key
openssl req $q -new -key inter.key -subj "/CN=Eider Test Intermediate" -out inter.csr
openssl x509 -req -in inter.csr -CA root.pem -CAkey root.key -CAcreateserial -sha256 -days 3650 -extfile ca.cnf -extensions inter_ext -out inter.pem 2>/dev/null
openssl genpkey -algorithm ed25519 -out ed.key
openssl req $q -new -key ed.key -subj "/CN=localhost" -out ed.csr
openssl x509 -req -in ed.csr -CA inter.pem -CAkey inter.key -CAcreateserial -days 3650 -extfile ca.cnf -extensions leaf_ext -out ed.pem 2>/dev/null
cat ed.pem inter.pem > edchain.pem
openssl ecparam -name prime256v1 -genkey -noout -out ec.key
openssl req $q -new -key ec.key -subj "/CN=localhost" -out ec.csr
openssl x509 -req -in ec.csr -CA root.pem -CAkey root.key -CAcreateserial -sha256 -days 3650 -extfile ca.cnf -extensions leaf_ext -out ec.pem 2>/dev/null
openssl genpkey -algorithm ed25519 -out expired.key
openssl req $q -new -key expired.key -subj "/CN=localhost" -out expired.csr
openssl x509 -req -in expired.csr -CA root.pem -CAkey root.key -CAcreateserial -sha256 -not_before 20190101000000Z -not_after 20200101000000Z -extfile ca.cnf -extensions leaf_ext -out expired.pem 2>/dev/null || {
  # older openssl: no -not_before; sign with the ca command
  echo "pki.sh: this openssl cannot set -not_before" >&2; exit 4
}
openssl ecparam -name prime256v1 -genkey -noout -out other-root.key
openssl req $q -new -x509 -key other-root.key -sha256 -days 3650 -subj "/CN=Other Root" -config ca.cnf -extensions root_ext -out other-root.pem
openssl genpkey -algorithm ed25519 -out client.key
openssl req $q -new -key client.key -subj "/CN=client" -out client.csr
openssl x509 -req -in client.csr -CA root.pem -CAkey root.key -CAcreateserial -sha256 -days 3650 -extfile ca.cnf -extensions client_ext -out client.pem 2>/dev/null
openssl genpkey -algorithm ed25519 -out noeku.key
openssl req $q -new -key noeku.key -subj "/CN=localhost" -out noeku.csr
openssl x509 -req -in noeku.csr -CA root.pem -CAkey root.key -CAcreateserial -sha256 -days 3650 -extfile ca.cnf -extensions noeku_ext -out noeku.pem 2>/dev/null
openssl genpkey -algorithm ed25519 -out leafsigned.key
openssl req $q -new -key leafsigned.key -subj "/CN=localhost" -out leafsigned.csr
openssl x509 -req -in leafsigned.csr -CA ed.pem -CAkey ed.key -CAcreateserial -days 3000 -out leafsigned.pem 2>/dev/null
echo "pki ok"
