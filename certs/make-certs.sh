#!/usr/bin/env bash
# Generates a TEST CA and two TEST signer certificates (.p12, password: changeit).
# NEVER use these in production. The CA goes to trust-test/ (trusted by the backend but never revocation-checked); the .p12 files get imported in the OS/browser store for AutoFirma.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p trust-test out
PASS=changeit

openssl req -x509 -newkey rsa:3072 -sha256 -days 3650 -nodes \
  -keyout out/ca.key -out trust-test/spike-test-ca.pem \
  -subj "/C=ES/O=Spike Test CA/CN=Spike Test CA (NOT FOR PRODUCTION)" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

make_signer() {  # $1=file-name  $2=common name  $3=serialNumber (like a NIF)
  openssl req -newkey rsa:2048 -nodes -keyout out/$1.key -out out/$1.csr \
    -subj "/C=ES/O=Spike Test/CN=$2/serialNumber=$3"
  printf "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\nextendedKeyUsage=emailProtection\n" > out/$1.ext
  openssl x509 -req -in out/$1.csr -CA trust-test/spike-test-ca.pem -CAkey out/ca.key -CAcreateserial \
    -out out/$1.pem -days 825 -sha256 -extfile out/$1.ext
  openssl pkcs12 -export -inkey out/$1.key -in out/$1.pem -certfile trust-test/spike-test-ca.pem \
    -name "$2" -out out/$1.p12 -passout pass:$PASS
}

make_signer signer-do "Test Drone Operator Signer" "IDCES-11111111H"
make_signer signer-io "Test Infrastructure Signer" "IDCES-22222222J"
echo "OK: trust-test/spike-test-ca.pem, out/signer-do.p12, out/signer-io.p12 (password: $PASS)"
