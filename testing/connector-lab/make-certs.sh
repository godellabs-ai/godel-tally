#!/usr/bin/env bash
# Local lab CA + server certificate. Used only inside this test lab so the Tally
# collector's real HTTPS client can complete a real TLS handshake against locally
# hosted vendor-shaped endpoints. Nothing is installed into the system trust store.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p certs
cd certs

openssl req -x509 -newkey rsa:2048 -sha256 -days 30 -nodes \
  -keyout ca.key -out ca.pem \
  -subj "/CN=Gödel Tally Lab CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

cat > server.cnf <<'EOF'
[req]
distinguished_name = dn
req_extensions = ext
prompt = no
[dn]
CN = tally-lab
[ext]
subjectAltName = @alt
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
[alt]
DNS.1 = api.cloudflare.com
DNS.2 = api.nextdns.io
DNS.3 = litellm.lab
DNS.4 = k3s.lab
DNS.5 = localhost
IP.1 = 127.0.0.1
IP.2 = 127.0.0.77
IP.3 = 127.0.0.78
IP.4 = 127.0.0.79
EOF

openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -config server.cnf 2>/dev/null
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 30 -sha256 \
  -extfile server.cnf -extensions ext 2>/dev/null
cat server.pem ca.pem > server.fullchain.pem
chmod 644 server.key ca.pem server.pem server.fullchain.pem
echo "certs written:"
openssl x509 -in server.pem -noout -text | grep -A1 "Subject Alternative Name"
