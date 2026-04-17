#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"
# Prototype PKI via OpenSSL is acceptable for coursework; enterprise deployments should
# move certificate lifecycle management to AWS ACM, HashiCorp Vault, or equivalent.
rm -f ca.key ca.crt ca.srl server.key server.csr server.crt client.key client.csr client.crt
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=MedicalIoT Lab Root CA/O=Coursework/C=GB" -out ca.crt \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

openssl genrsa -out server.key 2048
openssl req -new -key server.key -subj "/CN=localhost/O=Coursework/C=GB" -out server.csr
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 \
  -extfile /dev/fd/3 3<<'EOF'
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
EOF

openssl genrsa -out client.key 2048
openssl req -new -key client.key -subj "/CN=cgm-edge-client/O=Coursework/C=GB" -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -out client.crt -days 825 -sha256 \
  -extfile /dev/fd/3 3<<'EOF'
extendedKeyUsage=clientAuth
keyUsage=digitalSignature
EOF

rm -f server.csr client.csr
chmod 600 ca.key server.key client.key
chmod 644 ca.crt server.crt client.crt
