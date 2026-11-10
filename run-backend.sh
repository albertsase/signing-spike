#!/usr/bin/env bash
# Builds and runs the backend with a real JDK 8 (same as accord_backend).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
"$ROOT/build-backend.sh"
cd "$ROOT/backend"
export JAVA_HOME="${JAVA_HOME_8:-/usr/lib/jvm/java-8-openjdk-amd64}"
export JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
exec "$JAVA_HOME/bin/java" -cp "target/classes:$(cat target/cp.txt)" spike.Main
