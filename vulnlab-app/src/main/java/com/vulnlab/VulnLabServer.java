package com.vulnlab;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * Minimal vulnerable lab server — intentionally vulnerable for testing.
 * Endpoints:
 *   POST /deser      — Java ObjectInputStream deserialization (CC6/CB1/etc.)
 *   POST /fastjson   — Fastjson 1.2.24 JSON parse (JNDI RCE)
 *   POST /xstream    — XStream 1.4.17 XML parse (CVE-2021-39144)
 *   POST /hessian    — Hessian deserialization endpoint
 *   POST /hessian2   — Hessian2 deserialization endpoint
 *   GET  /log4shell  — Log4j2 JNDI via User-Agent header (CVE-2021-44228)
 *   GET  /health     — health check
 */
public class VulnLabServer {
    private static final Logger log = LogManager.getLogger(VulnLabServer.class);

    public static void main(String[] args) throws Exception {
        // Enable JNDI remote class loading for JNDI RCE chains
        System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
        System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
        System.setProperty("com.sun.jndi.ldap.object.trustSerialData", "true");
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8888;
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/deser",    new DeserHandler());
        server.createContext("/fastjson", new FastjsonHandler());
        server.createContext("/xstream",  new XStreamHandler());
        server.createContext("/hessian",  new HessianHandler(false));
        server.createContext("/hessian2", new HessianHandler(true));
        server.createContext("/log4shell", new Log4ShellHandler());
        server.createContext("/h2jdbc",   new H2JdbcHandler());
        server.createContext("/snakeyaml", new SnakeYAMLHandler());
        server.createContext("/check-rce", new CheckRceHandler());
        server.createContext("/health",   new HealthHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("[VulnLab] Listening on port " + port);
        System.out.println("  /deser      Java ObjectInputStream RCE (CC6/CB1/Hessian/C3P0 chains)");
        System.out.println("  /fastjson   Fastjson 1.2.24 JNDI RCE");
        System.out.println("  /xstream    XStream 1.4.17 RCE");
        System.out.println("  /hessian    Hessian deserialization");
        System.out.println("  /hessian2   Hessian2 deserialization");
        System.out.println("  /log4shell  Log4j2 CVE-2021-44228 via User-Agent");
        System.out.println("  /h2jdbc     H2 JDBC RUNSCRIPT RCE (jchains_h2_jdbc)");
        System.out.println("  /health     health check");
    }

    static byte[] readBody(HttpExchange ex) throws IOException {
        try (ByteArrayOutputStream buf = new ByteArrayOutputStream()) {
            byte[] chunk = new byte[4096];
            int n;
            while ((n = ex.getRequestBody().read(chunk)) != -1) buf.write(chunk, 0, n);
            return buf.toByteArray();
        }
    }

    static void respond(HttpExchange ex, int code, String body) throws IOException {
        byte[] b = body.getBytes("UTF-8");
        ex.sendResponseHeaders(code, b.length);
        ex.getResponseBody().write(b);
        ex.getResponseBody().close();
    }

    // ── Handlers ──────────────────────────────────────────────────────────────

    static class DeserHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            byte[] body = readBody(ex);
            System.out.println("[deser] Received " + body.length + " bytes from " + ex.getRemoteAddress());
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(body))) {
                Object obj = ois.readObject();
                // Trigger C3P0 chain: calling getConnection()/getPooledConnection() fires
                // parseUserOverridesAsString() → secondary deser. Run in background thread
                // so the HTTP response is not blocked by C3P0 pool-init timeout.
                if (obj instanceof javax.sql.DataSource) {
                    final javax.sql.DataSource ds = (javax.sql.DataSource) obj;
                    new Thread(() -> {
                        try { ds.getConnection(); } catch (Throwable ignored) {}
                    }, "c3p0-trigger").start();
                } else if (obj instanceof javax.sql.ConnectionPoolDataSource) {
                    // WrapperConnectionPoolDataSource implements ConnectionPoolDataSource, not DataSource
                    final javax.sql.ConnectionPoolDataSource cpds = (javax.sql.ConnectionPoolDataSource) obj;
                    new Thread(() -> {
                        try { cpds.getPooledConnection(); } catch (Throwable ignored) {}
                    }, "c3p0-trigger").start();
                }
                respond(ex, 200, "OK: " + (obj == null ? "null" : obj.getClass().getName()));
            } catch (Throwable t) {
                System.out.println("[deser] Exception: " + t.getMessage());
                respond(ex, 200, "EX: " + t.getMessage());
            }
        }
    }

    static class FastjsonHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            byte[] body = readBody(ex);
            String json = new String(body, "UTF-8");
            System.out.println("[fastjson] Received: " + json.substring(0, Math.min(json.length(), 200)));
            try {
                Object obj = com.alibaba.fastjson.JSON.parse(json); // parse() returns typed obj; parseObject() returns JSONObject wrapper — wont instanceof DataSource
                // Fix BCEL ClassLoader for fastjson_bcel chain: Fastjson on JDK 8u482 cannot instantiate
                // the internal BCEL ClassLoader via @type nesting, so we inject it manually via reflection.
                if (obj instanceof org.apache.commons.dbcp.BasicDataSource) {
                    org.apache.commons.dbcp.BasicDataSource bds = (org.apache.commons.dbcp.BasicDataSource) obj;
                    if (bds.getDriverClassName() != null && bds.getDriverClassName().startsWith("$$BCEL$$")) {
                        try {
                            Class<?> bcelCL = Class.forName("com.sun.org.apache.bcel.internal.util.ClassLoader");
                            bds.setDriverClassLoader((ClassLoader) bcelCL.newInstance());
                        } catch (Throwable ignored) {}
                    }
                }
                // Trigger C3P0 connection pool to execute H2 INIT script (fastjson_c3p0_h2 chain)
                if (obj instanceof javax.sql.DataSource) {
                    final javax.sql.DataSource ds = (javax.sql.DataSource) obj;
                    new Thread(() -> { try { ds.getConnection(); } catch (Throwable ignored) {} }, "fastjson-c3p0").start();
                } else if (obj instanceof javax.sql.ConnectionPoolDataSource) {
                    final javax.sql.ConnectionPoolDataSource cpds = (javax.sql.ConnectionPoolDataSource) obj;
                    new Thread(() -> { try { cpds.getPooledConnection(); } catch (Throwable ignored) {} }, "fastjson-c3p0").start();
                }
                respond(ex, 200, "OK: " + obj);
            } catch (Throwable t) {
                System.out.println("[fastjson] Exception: " + t.getMessage());
                respond(ex, 200, "EX: " + t.getMessage());
            }
        }
    }

    static class XStreamHandler implements HttpHandler {
        private final com.thoughtworks.xstream.XStream xs;
        XStreamHandler() {
            xs = new com.thoughtworks.xstream.XStream();
            // No security restrictions — intentionally vulnerable
        }
        public void handle(HttpExchange ex) throws IOException {
            byte[] body = readBody(ex);
            String xml = new String(body, "UTF-8");
            System.out.println("[xstream] Received " + body.length + " bytes");
            try {
                Object obj = xs.fromXML(xml);
                respond(ex, 200, "OK: " + obj);
            } catch (Throwable t) {
                System.out.println("[xstream] Exception: " + t.getMessage());
                respond(ex, 200, "EX: " + t.getMessage());
            }
        }
    }

    // Trigger lazy gadget values that are only activated by explicit access.
    // UIDefaults lazy values (SwingLazyValue/ProxyLazyValue) only fire on UIDefaults.get(key),
    // NOT on toString(). SignedObject secondary deserialization fires on getObject() call.
    // HashMap/TreeMap key chains fire on hashCode()/compareTo() during Map operations.
    static void triggerGadgets(Object obj) {
        if (obj == null) return;
        // Always trigger toString/hashCode — fires Rome/ObjectBean/ToStringBean gadgets
        try { obj.hashCode(); } catch (Throwable ignored) {}
        try { obj.toString(); } catch (Throwable ignored) {}
        if (obj instanceof javax.swing.UIDefaults) {
            javax.swing.UIDefaults ud = (javax.swing.UIDefaults) obj;
            for (Object k : new java.util.ArrayList<>(ud.keySet())) {
                try { ud.get(k); } catch (Throwable ignored) {}
            }
        }
        if (obj instanceof java.security.SignedObject) {
            try { ((java.security.SignedObject) obj).getObject(); } catch (Throwable ignored) {}
        }
        // Hessian may reconstruct UIDefaults$LazyValue as a live object but not inside a UIDefaults.
        // Call createValue() directly so SwingLazyValue/ProxyLazyValue gadgets fire.
        try {
            Class<?> lazyValueClass = Class.forName("javax.swing.UIDefaults$LazyValue");
            if (lazyValueClass.isInstance(obj)) {
                java.lang.reflect.Method cv = lazyValueClass.getDeclaredMethod("createValue", javax.swing.UIDefaults.class);
                cv.setAccessible(true);
                cv.invoke(obj, new javax.swing.UIDefaults());
            }
        } catch (Throwable ignored) {}
        if (obj instanceof java.util.Map) {
            java.util.Map<?,?> map = (java.util.Map<?,?>) obj;
            for (Object k : new java.util.ArrayList<>(map.keySet())) {
                try { k.hashCode(); } catch (Throwable ignored) {}
                try { k.toString(); } catch (Throwable ignored) {}
                triggerGadgets(k);  // UIDefaults/SignedObject may be nested as a MAP KEY
                Object v = null;
                try { v = map.get(k); } catch (Throwable ignored) {}
                if (v != null) triggerGadgets(v);
                // Hessian secondary/bcel: SwingLazyValue may be a MAP VALUE inside a nested Map.
                // Calling triggerGadgets(v) recurses but we also call createValue() directly here
                // for LazyValue instances found as values (complements the direct-object check above).
                if (v != null) {
                    try {
                        Class<?> lazyValueClass = Class.forName("javax.swing.UIDefaults$LazyValue");
                        if (lazyValueClass.isInstance(v)) {
                            java.lang.reflect.Method cv = lazyValueClass.getDeclaredMethod("createValue", javax.swing.UIDefaults.class);
                            cv.setAccessible(true);
                            cv.invoke(v, new javax.swing.UIDefaults());
                        }
                    } catch (Throwable ignored) {}
                }
            }
        }
        if (obj instanceof java.util.Collection) {
            for (Object item : (java.util.Collection<?>) obj) {
                triggerGadgets(item);
            }
        }
    }

    static class HessianHandler implements HttpHandler {
        private final boolean hessian2;
        HessianHandler(boolean hessian2) { this.hessian2 = hessian2; }

        private com.caucho.hessian.io.AbstractHessianInput newInput(byte[] body) {
            ByteArrayInputStream bais = new ByteArrayInputStream(body);
            return hessian2
                ? new com.caucho.hessian.io.Hessian2Input(bais)
                : new com.caucho.hessian.io.HessianInput(bais);
        }

        // java-chains wraps gadgets in a Hessian RPC call frame (method call + args).
        // Try readMethod() + readObject() first; if that fails, fall back to raw readObject().
        private Object deserHessian(byte[] body) throws Exception {
            try {
                com.caucho.hessian.io.AbstractHessianInput rpc = newInput(body);
                rpc.readMethod();
                return rpc.readObject();
            } catch (Throwable ignored) {}
            return newInput(body).readObject();
        }

        public void handle(HttpExchange ex) throws IOException {
            byte[] body = readBody(ex);
            System.out.println("[hessian" + (hessian2?"2":"") + "] Received " + body.length + " bytes from " + ex.getRemoteAddress());
            try {
                Object obj = deserHessian(body);
                if (obj instanceof javax.sql.DataSource) {
                    final javax.sql.DataSource ds = (javax.sql.DataSource) obj;
                    new Thread(() -> { try { ds.getConnection(); } catch (Throwable ignored) {} }, "c3p0-trigger").start();
                } else if (obj instanceof javax.sql.ConnectionPoolDataSource) {
                    final javax.sql.ConnectionPoolDataSource cpds = (javax.sql.ConnectionPoolDataSource) obj;
                    new Thread(() -> { try { cpds.getPooledConnection(); } catch (Throwable ignored) {} }, "c3p0-trigger").start();
                }
                // Trigger lazy values (UIDefaults, SignedObject) that toString() doesn't activate
                final Object triggerObj = obj;
                new Thread(() -> triggerGadgets(triggerObj), "hessian-trigger").start();
                respond(ex, 200, "OK: " + obj);
            } catch (Throwable t) {
                System.out.println("[hessian] Exception: " + t.getMessage());
                respond(ex, 200, "EX: " + t.getMessage());
            }
        }
    }

    static class Log4ShellHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String ua = ex.getRequestHeaders().getFirst("User-Agent");
            if (ua == null) ua = "(no user-agent)";
            System.out.println("[log4shell] User-Agent: " + ua);
            log.error("User-Agent: {}", ua);  // Triggers Log4Shell if UA contains ${jndi:...}
            respond(ex, 200, "Logged: " + ua);
        }
    }

    static class H2JdbcHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            byte[] body = readBody(ex);
            String jdbcUrl = new String(body, "UTF-8").trim();
            // Accept JSON: {"url":"jdbc:h2:..."} or raw URL
            if (jdbcUrl.startsWith("{")) {
                try {
                    com.alibaba.fastjson.JSONObject obj = com.alibaba.fastjson.JSON.parseObject(jdbcUrl);
                    jdbcUrl = obj.getString("url");
                } catch (Throwable ignored) {}
            }
            System.out.println("[h2jdbc] Connecting to: " + jdbcUrl);
            final String url = jdbcUrl;
            // Connect in background — H2 INIT scripts may block
            new Thread(() -> {
                try {
                    Class.forName("org.h2.Driver");
                    java.sql.Connection c = java.sql.DriverManager.getConnection(url, "sa", "");
                    c.close();
                } catch (Throwable t) {
                    System.out.println("[h2jdbc] Exception: " + t.getMessage());
                }
            }, "h2jdbc-trigger").start();
            respond(ex, 200, "OK");
        }
    }

    static class CheckRceHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String query = ex.getRequestURI().getQuery();
            String prefix = (query != null && query.startsWith("f=")) ? query.substring(2) : "";
            // List files in /tmp matching oobx_* prefix
            java.io.File tmp = new java.io.File("/tmp");
            java.io.File[] files = tmp.listFiles();
            java.util.List<String> found = new java.util.ArrayList<>();
            if (files != null) {
                for (java.io.File f : files) {
                    if (f.getName().startsWith("oobx_") &&
                        (prefix.isEmpty() || f.getName().startsWith("oobx_" + prefix))) {
                        found.add(f.getName());
                    }
                }
            }
            respond(ex, 200, "{\"rce_files\":" + found.toString().replace("[","[\"").replace("]","\"]").replace(", ","\",\"") + ",\"count\":" + found.size() + "}");
        }
    }

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            respond(ex, 200, "{\"status\":\"ok\",\"endpoints\":[\"/deser\",\"/fastjson\",\"/xstream\",\"/hessian\",\"/hessian2\",\"/log4shell\",\"/h2jdbc\",\"/check-rce\"]}");
        }
    }
    static class SnakeYAMLHandler implements com.sun.net.httpserver.HttpHandler {
        public void handle(com.sun.net.httpserver.HttpExchange ex) throws java.io.IOException {
            byte[] body = readBody(ex);
            String yaml = new String(body, "UTF-8");
            System.out.println("[snakeyaml] Received: " + yaml.substring(0, Math.min(yaml.length(), 200)));
            try {
                Object obj = new org.yaml.snakeyaml.Yaml().load(yaml);
                respond(ex, 200, "OK: " + (obj == null ? "null" : obj.getClass().getName()));
            } catch (Throwable t) {
                System.out.println("[snakeyaml] Exception: " + t.getMessage());
                respond(ex, 200, "EX: " + t.getMessage());
            }
        }
    }
}
