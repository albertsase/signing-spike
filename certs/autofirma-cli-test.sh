#!/usr/bin/env bash
# End-to-end test with the REAL AutoFirma (command-line mode) and the TEST certificates (no GUI, no PIN):
# creates a document, signs as DO and as IO with a VISIBLE signature in the role's frame, uploads each one for
# verification, and renders the result to PNG.  Needs: AutoFirma installed, certs/out/*.p12, pdftoppm (optional).
# The params must match AutoFirmaSigner.buildParams() in frontend/src/app/signing/signing.service.ts.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PORT="${PORT:-8081}"
W="$(mktemp -d)"; echo "work dir: $W"
[ -f "$ROOT/backend/target/cp.txt" ] || "$ROOT/build-backend.sh"
J8="${JAVA_HOME_8:-/usr/lib/jvm/java-8-openjdk-amd64}/bin/java"
CP="$ROOT/backend/target/classes:$(cat "$ROOT/backend/target/cp.txt")"
export JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
SRV_PID=""
trap '[ -n "$SRV_PID" ] && kill "$SRV_PID" 2>/dev/null || true' EXIT

(cd "$ROOT/backend" && PORT=$PORT DATA_DIR="$W/data" exec "$J8" -cp "$CP" spike.Main >"$W/server.log" 2>&1) &
SRV_PID=$!
for i in $(seq 1 20); do curl -s "localhost:$PORT/api/info" >/dev/null 2>&1 && break; sleep 1; done

B="http://localhost:$PORT/api"
curl -s -X POST "$B/documents" > "$W/doc.json"
ID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["id"])' "$W/doc.json")

sign_as() {  # $1=role  $2=p12  $3=version  $4=certificate filter (CN)
  local role="$1" p12="$2" ver="$3" filter="$4"
  curl -s "$B/documents/$ID/pdf" -o "$W/in.pdf"
  curl -s "$B/documents/$ID" > "$W/doc.json"
  python3 - "$W/doc.json" "$role" > "$W/params.txt" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1])); role = sys.argv[2]
b = next(s["box"] for s in doc["signers"] if s["role"] == role)
# The AutoFirma CLI wants the parameters separated by the literal two characters \n (the web client uses real newlines).
print("\\n".join([
  "alwaysCreateRevision=true",
  "signReason=Signature as " + role,
  "signaturePage=%d" % b["page"],
  "signaturePositionOnPageLowerLeftX=%d" % round(b["llx"]),
  "signaturePositionOnPageLowerLeftY=%d" % round(b["lly"]),
  "signaturePositionOnPageUpperRightX=%d" % round(b["urx"]),
  "signaturePositionOnPageUpperRightY=%d" % round(b["ury"]),
  "layer2Text=Firma (" + role + "): Firmado por $$SUBJECTCN$$ el $$SIGNDATE=dd/MM/yyyy HH:mm:ss z$$",
  "layer2FontFamily=1",
  "layer2FontSize=8",
]))
PY
  autofirma sign -i "$W/in.pdf" -o "$W/out-$role.pdf" -format pades -algorithm sha256 \
    -store "pkcs12:$p12" -password changeit -filter "$filter" -config "$(tr -d '\n' < "$W/params.txt")" \
    2>&1 | grep -v "Gtk-Message\|ProxyUtil\|No se usara proxy" | head -5 || true
  echo "--- $role: upload for verification"
  curl -s -X POST "$B/documents/$ID/sign?baseVersion=$ver" --data-binary @"$W/out-$role.pdf" -H 'Content-Type: application/pdf' \
    | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("error") or ("status=%s" % d["document"]["status"]), [(s["integrityOk"], s["chainOk"], s.get("revocation", "?")[:14], s.get("timestamp", "?")[:60], s.get("timestampTime"), s["coversWholeFile"]) for s in d.get("signatures", [])])'
}

sign_as DO "$ROOT/certs/out/signer-do.p12" 0 "subject.contains:Drone Operator"
sign_as IO "$ROOT/certs/out/signer-io.p12" 1 "subject.contains:Infrastructure"

curl -s "$B/documents/$ID/pdf" -o "$W/final.pdf"
cp "$W/final.pdf" "$W/../spike-final.pdf" 2>/dev/null || true
if command -v pdftoppm >/dev/null; then pdftoppm -r 80 -png -f 1 -l 1 "$W/final.pdf" "$W/final"; fi
command -v pdfsig >/dev/null && pdfsig "$W/final.pdf" | grep -E "Signature #|Common Name|Validation" || true
echo "Output dir: $W"
