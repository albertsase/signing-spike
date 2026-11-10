#!/usr/bin/env bash
# Local OCSP test: a throw-away CA with a GOOD and a REVOKED certificate and a real OCSP responder (openssl ocsp).
# Expected: GOOD -> ok; REVOKED -> rejected; responder stopped (HARD) -> rejected; responder stopped (SOFT) -> accepted with warning.
# Builds the backend if needed and generates its own sample PDF.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT=9081
W="$(mktemp -d)"
[ -f "$ROOT/backend/target/cp.txt" ] || "$ROOT/build-backend.sh"
J8="${JAVA_HOME_8:-/usr/lib/jvm/java-8-openjdk-amd64}/bin/java"
CP="$ROOT/backend/target/classes:$(cat "$ROOT/backend/target/cp.txt")"
export JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
SRC_PDF="$W/sample.pdf"
"$J8" -cp "$CP" spike.SamplePdf "$SRC_PDF" >/dev/null 2>&1
OCSP_PID=""
trap '[ -n "$OCSP_PID" ] && kill "$OCSP_PID" 2>/dev/null || true' EXIT

cd "$W"
mkdir -p newcerts trust empty && : > index.txt && echo 1000 > serial
cat > ca.cnf <<CNF
[ ca ]
default_ca = CA_default
[ CA_default ]
database = $W/index.txt
new_certs_dir = $W/newcerts
serial = $W/serial
default_md = sha256
default_days = 30
unique_subject = no
policy = policy_any
x509_extensions = leaf_ext
[ policy_any ]
commonName = supplied
[ leaf_ext ]
basicConstraints = CA:FALSE
keyUsage = critical,digitalSignature,nonRepudiation
authorityInfoAccess = OCSP;URI:http://localhost:$PORT
CNF

openssl req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.pem -days 30 -subj "/CN=OCSP Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
cp ca.pem trust/

for n in good revoked; do
  openssl req -newkey rsa:2048 -nodes -keyout $n.key -out $n.csr -subj "/CN=ocsp-$n" 2>/dev/null
  openssl ca -config ca.cnf -batch -in $n.csr -out $n.pem -notext -cert ca.pem -keyfile ca.key 2>/dev/null
  openssl pkcs12 -export -inkey $n.key -in $n.pem -certfile ca.pem -name $n -out $n.p12 -passout pass:changeit
done
openssl ca -config ca.cnf -revoke revoked.pem -cert ca.pem -keyfile ca.key 2>/dev/null

for n in good revoked; do
  $J8 -cp "$CP" spike.DevSigner "$SRC_PDF" $n.pdf $n.p12 changeit "ocsp test" >/dev/null 2>&1
done

verify() {  # $1 = pdf, $2 = mode
  $J8 -cp "$CP" spike.VerifyCli "$1" "$W/trust" "$W/empty" "$2" 2>/dev/null \
    | python3 -c 'import sys,json; r=json.load(sys.stdin); s=r["signatures"][0]; print("  ok=%s revocation=%s" % (r["ok"], s["revocation"]))'
}

openssl ocsp -index index.txt -port $PORT -rsigner ca.pem -rkey ca.key -CA ca.pem -text >ocsp.log 2>&1 &
OCSP_PID=$!
sleep 1

echo "GOOD certificate, responder up   (expect ok=True, GOOD):";      verify good.pdf HARD
echo "REVOKED certificate, responder up (expect ok=False, REVOKED):"; verify revoked.pdf HARD
kill $OCSP_PID; wait $OCSP_PID 2>/dev/null || true; OCSP_PID=""
echo "GOOD certificate, responder DOWN, HARD (expect ok=False, UNKNOWN):"; verify good.pdf HARD
echo "GOOD certificate, responder DOWN, SOFT (expect ok=True, UNKNOWN accepted):"; verify good.pdf SOFT
