#!/usr/bin/env bash
# Downloads the PUBLIC CA certificates the backend trusts and checks them before installing:
#   certs/trust/      FNMT: AC RAIZ FNMT-RCM (root) + AC FNMT Usuarios (intermediate that issues citizen certificates)
#   certs/trust-tsa/  DigiCert Trusted Root G4 (root of the DigiCert time stamping authority)
# The roots are checked against their known SHA-256 fingerprints, the intermediate against its root.
# Add other CAs/TSAs by copying their PEM/CRT files into those folders (from the issuer's OFFICIAL site; never trust
# the chain embedded in a signed PDF).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p trust trust-tsa
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

FNMT_ROOT_SHA256="EB:C5:57:0C:29:01:8C:4D:67:B1:AA:12:7B:AF:12:F7:03:B4:61:1E:BC:17:B7:DA:B5:57:38:94:17:9B:93:FA"
DIGICERT_G4_SHA256="55:2F:7B:DC:F1:A7:AF:9E:6C:E6:72:01:7F:4F:12:AB:F7:72:40:C7:8E:76:1A:C2:03:D1:D9:D2:0A:C8:99:88"

fp() { openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2; }

curl -fsS -m 30 -o "$T/fnmt-root.crt"  https://www.cert.fnmt.es/certs/ACRAIZFNMTRCM.crt
curl -fsS -m 30 -o "$T/fnmt-usu.crt"   https://www.cert.fnmt.es/certs/ACUSU.crt
curl -fsS -m 30 -o "$T/digicert.crt"   https://cacerts.digicert.com/DigiCertTrustedRootG4.crt
for n in fnmt-root fnmt-usu digicert; do
  openssl x509 -inform DER -in "$T/$n.crt" -out "$T/$n.pem" 2>/dev/null || cp "$T/$n.crt" "$T/$n.pem"
done

[ "$(fp "$T/fnmt-root.pem")" = "$FNMT_ROOT_SHA256" ]  || { echo "FNMT root fingerprint MISMATCH"; exit 1; }
[ "$(fp "$T/digicert.pem")"  = "$DIGICERT_G4_SHA256" ] || { echo "DigiCert root fingerprint MISMATCH"; exit 1; }
openssl verify -CAfile "$T/fnmt-root.pem" "$T/fnmt-usu.pem" >/dev/null || { echo "FNMT intermediate does not chain to the root"; exit 1; }

cp "$T/fnmt-root.pem" trust/fnmt-ac-raiz.pem
cp "$T/fnmt-usu.pem"  trust/fnmt-ac-usuarios.pem
cp "$T/digicert.pem"  trust-tsa/digicert-trusted-root-g4.pem
echo "OK: trust/ (2 FNMT certificates) and trust-tsa/ (DigiCert Trusted Root G4) installed and verified."
