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
    echo "[entrypoint] java-chains web bundle not found at $JCDIR/java-chains.jar; using embedded chains-core engine in sidecar"
fi

# ── Start bytecode-service sidecar ────────────────────────────────────────────
echo "[entrypoint] Starting bytecode-service sidecar..."
exec java \
    -Dorg.apache.commons.collections.enableUnsafeSerialization=true \
    --add-opens java.sql.rowset/com.sun.rowset=ALL-UNNAMED \
    --add-opens java.base/java.lang=ALL-UNNAMED \
    --add-opens java.base/java.lang.reflect=ALL-UNNAMED \
    --add-opens java.base/java.security=ALL-UNNAMED \
    --add-opens java.base/java.util=ALL-UNNAMED \
    --add-opens java.desktop/javax.swing=ALL-UNNAMED \
    --add-opens java.naming/javax.naming=ALL-UNNAMED \
    --add-opens java.naming/javax.naming.ldap=ALL-UNNAMED \
    --add-modules jdk.naming.rmi \
    --add-opens jdk.naming.rmi/com.sun.jndi.rmi.registry=ALL-UNNAMED \
    --add-opens java.rmi/java.rmi.server=ALL-UNNAMED \
    --add-opens java.rmi/sun.rmi.server=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xml.internal.serializer=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xpath.internal=ALL-UNNAMED \
    --add-opens java.xml/com.sun.org.apache.xpath.internal.objects=ALL-UNNAMED \
    --add-exports java.xml/com.sun.org.apache.bcel.internal.classfile=ALL-UNNAMED \
    --add-exports java.xml/com.sun.org.apache.bcel.internal.util=ALL-UNNAMED \
    --add-exports java.xml/com.sun.org.apache.xpath.internal.objects=ALL-UNNAMED \
    -Dspring.autoconfigure.exclude=org.springframework.boot.autoconfigure.groovy.template.GroovyTemplateAutoConfiguration \
    -Dloader.path=/app/libs/java-chains-deps,/app/libs/chains-jars \
    -cp /app/bytecode-service-0.1.0.jar \
    org.springframework.boot.loader.launch.PropertiesLauncher \
    "$@"
