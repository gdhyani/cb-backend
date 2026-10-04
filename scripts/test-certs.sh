#!/usr/bin/env sh
# Throwaway CA + localhost server certificate for the TLS test services (docker-compose.test.yml).
# Generated per machine/CI run into test-certs/ (gitignored); never committed.
set -eu
dir="$(dirname "$0")/../test-certs"
mkdir -p "$dir"
cd "$dir"
[ -f ca.pem ] && [ -f server.pem ] && exit 0
openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 7 -subj "/CN=cb test services CA" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 7 -extfile server.ext 2>/dev/null
chmod 644 ca.pem server.pem server.key
echo "test certificates in $dir"
