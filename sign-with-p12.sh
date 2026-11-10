#!/usr/bin/env bash
# DEV ONLY: sign a PDF with a test .p12 (no AutoFirma needed).
# Usage: ./sign-with-p12.sh in.pdf out.pdf certs/out/signer-do.p12 [reason]
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
IN="$(realpath "$1")"; OUT="$(realpath -m "$2")"; P12="$(realpath "$3")"
[ -f "$ROOT/backend/target/cp.txt" ] || "$ROOT/build-backend.sh"
cd "$ROOT/backend"
export JAVA_HOME="${JAVA_HOME_8:-/usr/lib/jvm/java-8-openjdk-amd64}"
exec "$JAVA_HOME/bin/java" -cp "target/classes:$(cat target/cp.txt)" spike.DevSigner "$IN" "$OUT" "$P12" changeit "${4:-Test signature}"
