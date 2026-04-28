#!/bin/bash
set -e

JCDIR=/opt/java-chains

# ── Start java-chains in the background ──────────────────────────────────────
if [ -f "$JCDIR/java-chains.jar" ]; then
    echo "[entrypoint] Starting java-chains on :8011 (CHAINS_AUTH=false)..."
    CHAINS_AUTH=false \
    "$JCDIR/jdk/bin/java" -jar "$JCDIR/java-chains.jar" \
        --server.port=8011 \
        >> /var/log/java-chains.log 2>&1 &
    JC_PID=$!

    # Wait up to 30 s for java-chains to become responsive
    for i in $(seq 1 30); do
        if curl -fsS http://127.0.0.1:8011/version > /dev/null 2>&1; then
            echo "[entrypoint] java-chains ready (pid=$JC_PID)"
            break
        fi
        sleep 1
    done
else
    echo "[entrypoint] WARN: java-chains not found at $JCDIR/java-chains.jar — proxy chains unavailable"
fi

# ── Start bytecode-service sidecar ────────────────────────────────────────────
echo "[entrypoint] Starting bytecode-service sidecar..."
exec java \
    --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED \
    --add-opens java.base/java.lang=ALL-UNNAMED \
    --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
    --add-opens java.base/java.util=ALL-UNNAMED \
    -jar /app/bytecode-service-0.1.0.jar \
    "$@"
