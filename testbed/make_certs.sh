#!/usr/bin/env bash
# Generate the certificate set described in testbed/manifest.json.
#
# Run inside WSL2 or any Linux/macOS shell with openssl >= 1.1 (ADR-0001).
#
#     bash testbed/make_certs.sh
#
# Produces testbed/certs/ with four scenarios:
#     valid                healthy baseline, P-256, proper chain
#     expiring             1024-bit RSA, SHA-1 signature, 9 days left
#     expired_selfsigned   expired 47 days ago, self-signed
#     missing_intermediate valid leaf, but the chain we serve omits the CA
#
# The expired certificate is produced by backdating the CA's clock with
# `-not_before` / `-not_after` via a config file, so no faketime is needed.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
mkdir -p "$DIR"
cd "$DIR"

echo "==> root CA"
openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days 3650 -out ca.crt \
  -subj "/C=IN/O=SecureMailScope Testbed/CN=SecureMailScope Test Root CA"

# --------------------------------------------------------------------------- #
echo "==> valid (healthy tier): P-256, SHA-256, 90 days"
openssl ecparam -name prime256v1 -genkey -noout -out valid.key
openssl req -new -key valid.key -out valid.csr -subj "/C=IN/CN=mail-healthy.test"
openssl x509 -req -in valid.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out valid.crt -days 90 -sha256 \
  -extfile <(printf "subjectAltName=DNS:mail-healthy.test\nbasicConstraints=CA:FALSE")
cat valid.crt ca.crt > valid.fullchain.pem

# --------------------------------------------------------------------------- #
echo "==> expiring (degraded tier): 1024-bit RSA, SHA-1, 9 days"
openssl genrsa -out expiring.key 1024
openssl req -new -key expiring.key -out expiring.csr -subj "/C=IN/CN=mail-degraded.test"
# SHA-1 signing is refused by default in OpenSSL 3; the legacy security level
# has to be lowered explicitly. This is the point of the test case.
openssl x509 -req -in expiring.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out expiring.crt -days 9 -sha1 \
  -extfile <(printf "subjectAltName=DNS:mail-degraded.test\nbasicConstraints=CA:FALSE") \
  2>/dev/null || {
    echo "    SHA-1 refused by this OpenSSL build; retrying at security level 0"
    OPENSSL_CONF=/dev/null openssl x509 -req -in expiring.csr -CA ca.crt -CAkey ca.key \
      -CAcreateserial -out expiring.crt -days 9 -sha1 \
      -extfile <(printf "subjectAltName=DNS:mail-degraded.test\nbasicConstraints=CA:FALSE")
  }
cat expiring.crt ca.crt > expiring.fullchain.pem

# --------------------------------------------------------------------------- #
echo "==> expired_selfsigned (compromised tier): expired 47 days ago"
# This SAME certificate is served on port 25 and on port 993. The two captures
# are the side-by-side that demonstrates USP-01, so do not regenerate one
# without the other.
NOT_BEFORE=$(date -u -d '412 days ago' +%Y%m%d%H%M%SZ 2>/dev/null \
             || date -u -v-412d +%Y%m%d%H%M%SZ)
NOT_AFTER=$(date -u -d '47 days ago' +%Y%m%d%H%M%SZ 2>/dev/null \
            || date -u -v-47d +%Y%m%d%H%M%SZ)

openssl genrsa -out expired.key 2048
openssl req -x509 -new -key expired.key -sha256 -out expired.crt \
  -subj "/C=IN/CN=mail-compromised.test" \
  -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
  -addext "subjectAltName=DNS:mail-compromised.test"

# --------------------------------------------------------------------------- #
echo "==> missing_intermediate: valid leaf, chain served without the CA"
openssl genrsa -out partial.key 2048
openssl req -new -key partial.key -out partial.csr -subj "/C=IN/CN=mail-partial.test"
openssl x509 -req -in partial.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out partial.crt -days 90 -sha256 \
  -extfile <(printf "subjectAltName=DNS:mail-partial.test\nbasicConstraints=CA:FALSE")
# Deliberately NOT concatenating ca.crt: that is the defect under test.

rm -f ./*.csr
echo
echo "done. certificates in $DIR"
openssl x509 -in expired.crt -noout -dates | sed 's/^/    expired.crt  /'
openssl x509 -in expiring.crt -noout -dates | sed 's/^/    expiring.crt /'
