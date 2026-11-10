#!/usr/bin/env bash
# Compiles the backend with a real JDK 8 (same as accord_backend) and writes backend/target/cp.txt (classpath).
# The other scripts call this automatically when cp.txt is missing.
set -euo pipefail
cd "$(dirname "$0")/backend"
export JAVA_HOME="${JAVA_HOME_8:-/usr/lib/jvm/java-8-openjdk-amd64}"
export JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8
[ -x "$JAVA_HOME/bin/java" ] || { echo "JDK 8 not found at $JAVA_HOME (set JAVA_HOME_8)"; exit 1; }
mvn -q package -DskipTests
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
echo "Backend built (JDK 8): backend/target"
