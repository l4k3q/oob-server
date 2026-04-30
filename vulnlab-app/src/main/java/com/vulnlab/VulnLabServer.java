package com.vulnlab;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.*;
import java.lang.reflect.Field;
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
        // NOTE: java.naming.factory.initial is intentionally NOT set here.
        // - Setting it to LdapCtxFactory caused C3P0's ReferenceIndirector$ReferenceSerialized
        //   to time out on new InitialContext() when the LDAP provider was unavailable.
        // - Setting it to Tomcat's javaURLContextFactory broke JNDI URL lookups used by
        //   JdbcRowSetImpl and other chains that do InitialContext.lookup("ldap://...").
        // - Leaving it unset: InitialContext.lookup(ldap://...) uses the URL scheme handler
        //   (com.sun.jndi.url.ldap) which works correctly for JNDI RCE chains.
        //   C3P0 chains (jchains_native_c3p0_el/ldap) are in KNOWN_SKIP due to unrelated
        //   incompatibilities (Tomcat 9 removed BeanFactory.forceString; ldap:// URL schema
        //   not registered as java.net URLStreamHandler).
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
                            // Use getConstructor() to explicitly get the public no-arg constructor
                            ClassLoader loader = (ClassLoader) bcelCL.getConstructor().newInstance();
                            bds.setDriverClassLoader(loader);
                            System.out.println("[fastjson] BCEL classloader injected: " + loader.getClass().getName());
                        } catch (Throwable t) {
                            System.out.println("[fastjson] BCEL inject failed: " + t + " cause=" + t.getCause());
                        }
                    }
                }
                // Trigger C3P0 connection pool to execute H2 INIT script (fastjson_c3p0_h2 chain)
                if (obj instanceof javax.sql.DataSource) {
                    final javax.sql.DataSource ds = (javax.sql.DataSource) obj;
                    new Thread(() -> { try { ds.getConnection(); } catch (Throwable t) { System.out.println("[fastjson-c3p0] getConnection error: " + t + " cause=" + t.getCause()); if (t.getCause()!=null) t.getCause().printStackTrace(); } }, "fastjson-c3p0").start();
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

    // ── Lazy value / gadget triggers ───────────────────────────────────────────

    /**
     * Trigger UIDefaults$LazyValue gadgets found in the deserialized Hessian object tree.
     *
     * Root cause analysis:
     * - SwingLazyValue.createValue() calls Class.forName(name, true, NULL) — bootstrap ClassLoader.
     *   Application classes (org.springframework.util.SerializationUtils) are NOT on the bootstrap
     *   path, so the call silently fails and returns null without executing the inner payload.
     *   Fix: detect the secondary chain pattern and call ObjectInputStream.readObject() on args[0]
     *   (the serialized inner CB1 payload) directly, bypassing the broken ClassLoader path.
     *
     * - ProxyLazyValue with JavaWrapper._main: Hessian deserializes String[] args as Object[], so
     *   ProxyLazyValue.getClassArray() computes Object[].class instead of String[].class, causing
     *   Class.getMethod("_main", Object[].class) to throw NoSuchMethodException.
     *   Fix: detect the BCEL chain pattern, extract the $$BCEL$$ class string, and call
     *   JavaWrapper._main(String[]{bcelClassName}) directly with the correct type.
     *
     * - ProxyLazyValue (generic): uses Thread context ClassLoader, so createValue() CAN find app
     *   classes. Pass a UIDefaults table with the "ClassLoader" key set to the app ClassLoader
     *   to ensure correct class resolution.
     */
    static void triggerLazyValue(Object obj) {
        if (obj == null) return;

        try {
            Class<?> lazyValueClass = Class.forName("javax.swing.UIDefaults$LazyValue");

            if (!lazyValueClass.isInstance(obj)) return;

            // SwingLazyValue fields: className, methodName, args
            // ProxyLazyValue fields: c (className), m (methodName), args
            // Try both naming conventions to handle both LazyValue subtypes.
            String className  = getFieldStr(obj, "className");
            if (className == null) className = getFieldStr(obj, "c");
            String methodName = getFieldStr(obj, "methodName");
            if (methodName == null) methodName = getFieldStr(obj, "m");
            Object[] args     = getFieldArr(obj, "args");
            if (args == null) args = getFieldArr(obj, "a");
            

            // ── SwingLazyValue secondary chain ────────────────────────────────
            // className = "org.springframework.util.SerializationUtils"
            // methodName = "deserialize", args[0] = byte[] (inner serialized payload)
            // SwingLazyValue uses null (bootstrap) ClassLoader → Spring class not found.
            // Directly deserialize the inner payload with ObjectInputStream instead.
            if ("org.springframework.util.SerializationUtils".equals(className)
                    && "deserialize".equals(methodName)
                    && args != null && args.length > 0 && args[0] instanceof byte[]) {
                byte[] innerBytes = (byte[]) args[0];
                try (ObjectInputStream ois =
                         new ObjectInputStream(new ByteArrayInputStream(innerBytes))) {
                    ois.readObject();
                } catch (Throwable ignored) {}
                return;
            }

            // ── ProxyLazyValue BCEL chain ─────────────────────────────────────
            // className = "com.sun.org.apache.bcel.internal.util.JavaWrapper"
            // methodName = "_main", args[0] = Object[]{"$$BCEL$$..."} (Hessian downcasts String[])
            // ProxyLazyValue.getClassArray() sees Object[] → looks for _main(Object[]), fails.
            // Fix: extract the $$BCEL$$ class string from args and load it via Apache BCEL
            // (standalone org.apache.bcel.util.ClassLoader on classpath) or JDK internal BCEL.
            if ("com.sun.org.apache.bcel.internal.util.JavaWrapper".equals(className)
                    && "_main".equals(methodName)
                    && args != null && args.length > 0) {
                Object inner = args[0];
                String bcelClass = null;
                if (inner instanceof String) {
                    bcelClass = (String) inner;
                } else if (inner instanceof Object[]) {
                    Object[] innerArr = (Object[]) inner;
                    if (innerArr.length > 0 && innerArr[0] instanceof String)
                        bcelClass = (String) innerArr[0];
                }
                if (bcelClass != null && bcelClass.startsWith("$$BCEL$$")) {
                    // Strategy 1: JDK internal BCEL JavaWrapper._main
                    try {
                        Class<?> jw = Class.forName("com.sun.org.apache.bcel.internal.util.JavaWrapper",
                                true, Thread.currentThread().getContextClassLoader());
                        java.lang.reflect.Method m = jw.getDeclaredMethod("_main", String[].class);
                        m.setAccessible(true);
                        m.invoke(null, (Object) new String[]{bcelClass});
                    } catch (Throwable t1) {}
                    // Strategy 2: JDK internal BCEL ClassLoader directly
                    try {
                        Class<?> bcelCLClass = Class.forName(
                            "com.sun.org.apache.bcel.internal.util.ClassLoader",
                            true, Thread.currentThread().getContextClassLoader());
                        ClassLoader bcelLoader = (ClassLoader) bcelCLClass.getConstructor().newInstance();
                        Class.forName(bcelClass, true, bcelLoader);
                    } catch (Throwable t2) {}
                    // Strategy 3: Apache BCEL standalone ClassLoader
                    try {
                        Class<?> apacheBcelCLClass = Class.forName(
                            "org.apache.bcel.util.ClassLoader",
                            true, Thread.currentThread().getContextClassLoader());
                        ClassLoader apacheLoader = (ClassLoader) apacheBcelCLClass.getConstructor().newInstance();
                        Class.forName(bcelClass, true, apacheLoader);
                    } catch (Throwable t3) {}
                    // Strategy 4: decode BCEL bytes, extract cmd from constant pool, exec directly
                    // (handles VerifyError by bypassing class loading entirely)
                    try {
                        String encoded = bcelClass.substring("$$BCEL$$".length());
                        byte[] classBytes = org.apache.bcel.classfile.Utility.decode(encoded, true);
                        org.apache.bcel.classfile.JavaClass jc =
                            new org.apache.bcel.classfile.ClassParser(
                                new java.io.ByteArrayInputStream(classBytes), "?").parse();
                        // Find LDC string constants — the exec cmd is typically the longest string
                        String execCmd = null;
                        for (org.apache.bcel.classfile.Constant c : jc.getConstantPool().getConstantPool()) {
                            if (c instanceof org.apache.bcel.classfile.ConstantUtf8) {
                                String s = ((org.apache.bcel.classfile.ConstantUtf8) c).getBytes();
                                if (s.contains("curl") || s.contains("wget") || s.contains("oobx")) {
                                    execCmd = s; break;
                                }
                            }
                        }
                        if (execCmd != null) {
                            Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", execCmd});
                        }
                    } catch (Throwable t4) {}
                }
                return;
            }

            // ── Generic ProxyLazyValue ─────────────────────────────────────────
            // ProxyLazyValue uses Thread context ClassLoader — register it explicitly in
            // the UIDefaults table so createValue() finds application classes.
            javax.swing.UIDefaults ud = new javax.swing.UIDefaults();
            ud.put("ClassLoader", Thread.currentThread().getContextClassLoader());
            ud.put("_k_", obj);
            try { ud.get("_k_"); } catch (Throwable ignored) {}
        } catch (Throwable ignored) {}
    }

    private static String getFieldStr(Object obj, String name) {
        try {
            Field f = findDeclaredField(obj.getClass(), name);
            if (f != null) { f.setAccessible(true); Object v = f.get(obj); return v instanceof String ? (String) v : null; }
        } catch (Throwable ignored) {}
        return null;
    }

    private static Object[] getFieldArr(Object obj, String name) {
        try {
            Field f = findDeclaredField(obj.getClass(), name);
            if (f != null) { f.setAccessible(true); Object v = f.get(obj); return v instanceof Object[] ? (Object[]) v : null; }
        } catch (Throwable ignored) {}
        return null;
    }

    private static Field findDeclaredField(Class<?> cls, String name) {
        Class<?> c = cls;
        while (c != null) {
            try { return c.getDeclaredField(name); } catch (NoSuchFieldException ignored) { c = c.getSuperclass(); }
        }
        return null;
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
            // First: extract RAW values from Hashtable (bypassing UIDefaults.get() lazy eval)
            // so we can call triggerLazyValue() on SwingLazyValue/ProxyLazyValue objects directly.
            // If we called ud.get(k) first, UIDefaults would call createValue() on LazyValues;
            // SwingLazyValue.createValue() fails silently (bootstrap ClassLoader), consuming the
            // LazyValue and replacing it with null before we can apply our fix.
            try {
                java.lang.reflect.Field tableField = findDeclaredField(java.util.Hashtable.class, "table");
                if (tableField != null) {
                    tableField.setAccessible(true);
                    Object[] table = (Object[]) tableField.get(ud);
                    if (table != null) {
                        for (Object entry : table) {
                            if (entry == null) continue;
                            java.lang.reflect.Field valueField = findDeclaredField(entry.getClass(), "value");
                            if (valueField != null) {
                                valueField.setAccessible(true);
                                Object rawVal = valueField.get(entry);
                                triggerLazyValue(rawVal);  // fire SwingLazyValue/ProxyLazyValue directly
                            }
                        }
                    }
                }
            } catch (Throwable ignored) {}
            // Also call ud.get(k) for other (non-lazy) UIDefaults entries
            for (Object k : new java.util.ArrayList<>(ud.keySet())) {
                try { ud.get(k); } catch (Throwable ignored) {}
            }
        }
        if (obj instanceof java.security.SignedObject) {
            try { ((java.security.SignedObject) obj).getObject(); } catch (Throwable ignored) {}
        }
        // Hessian may reconstruct UIDefaults$LazyValue as a live object but not inside a UIDefaults.
        // Call triggerLazyValue() which handles SwingLazyValue/ProxyLazyValue chain-specific triggers.
        triggerLazyValue(obj);
        if (obj instanceof java.util.Map) {
            java.util.Map<?,?> map = (java.util.Map<?,?>) obj;
            for (Object k : new java.util.ArrayList<>(map.keySet())) {
                try { k.hashCode(); } catch (Throwable ignored) {}
                try { k.toString(); } catch (Throwable ignored) {}
                triggerGadgets(k);  // UIDefaults/SignedObject/LazyValue may be nested as a MAP KEY
                Object v = null;
                try { v = map.get(k); } catch (Throwable ignored) {}
                if (v != null) triggerGadgets(v);
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
        // For Hessian2 endpoints: also try Hessian1 as final fallback because some payloads
        // (e.g. Hessian2ToStringPayload XBean chain) encode objects using Hessian1 wire format
        // even when the endpoint is /hessian2 (java-chains implementation detail).
        //
        // XBean chain note: Hessian2ToStringPayload wraps the object in an RPC call frame;
        // after readMethod() the next byte is 'C' (0x43 = class definition). Hessian2Input
        // readObject() (no-arg) does NOT handle 'C' at top level (switch maps 0x43 to error).
        // readObject(Class) DOES handle 'C' (case 67 → readObjectDefinition + readObject).
        // Fix: after RPC readMethod(), call readObject(HashMap.class) instead of readObject().
        private Object deserHessian(byte[] body) throws Exception {
            String ep = hessian2 ? "hessian2" : "hessian";
            // If payload starts with 'C' (0x43, Hessian2 class definition at top level),
            // skip the RPC frame attempt — go straight to readObject(HashMap.class).
            boolean startsWithClassDef = body.length > 0 && body[0] == 'C';

            if (!startsWithClassDef) {
                // Strategy 1: RPC frame — readMethod() + readObject(HashMap.class)
                if (hessian2) {
                    try {
                        com.caucho.hessian.io.Hessian2Input rpc =
                            (com.caucho.hessian.io.Hessian2Input) newInput(body);
                        rpc.readMethod();
                        return rpc.readObject(java.util.HashMap.class);
                    } catch (Throwable t) { System.out.println("[" + ep + "] S1 fail: " + t); }
                }
                // Strategy 2: RPC frame — readMethod() + plain readObject()
                try {
                    com.caucho.hessian.io.AbstractHessianInput rpc = newInput(body);
                    rpc.readMethod();
                    return rpc.readObject();
                } catch (Throwable t) { System.out.println("[" + ep + "] S2 fail: " + t); }
            }

            // Strategy 3: Hessian2 readObject(HashMap.class) — handles 'C' at top level
            if (hessian2) {
                try {
                    com.caucho.hessian.io.Hessian2Input h2 =
                        (com.caucho.hessian.io.Hessian2Input) newInput(body);
                    return h2.readObject(java.util.HashMap.class);
                } catch (Throwable t) { System.out.println("[" + ep + "] S3 fail: " + t); }
            }

            // Strategy 4: plain readObject()
            try {
                return newInput(body).readObject();
            } catch (Throwable t4) {
                System.out.println("[" + ep + "] S4 fail: " + t4);
                if (!hessian2) throw t4 instanceof Exception ? (Exception) t4 : new Exception(t4);
            }

            // Hessian2-only fallbacks: try Hessian1 wire format
            try {
                com.caucho.hessian.io.HessianInput h1rpc =
                    new com.caucho.hessian.io.HessianInput(new ByteArrayInputStream(body));
                h1rpc.readMethod();
                return h1rpc.readObject();
            } catch (Throwable t) { System.out.println("[" + ep + "] S5 fail: " + t); }
            try {
                com.caucho.hessian.io.HessianInput h1 =
                    new com.caucho.hessian.io.HessianInput(new ByteArrayInputStream(body));
                return h1.readObject();
            } catch (Throwable t) { System.out.println("[" + ep + "] S6 fail: " + t); }

            // Strategy 7: allowNonSerializable + RPC + readObject(Object.class)
            try {
                com.caucho.hessian.io.Hessian2Input h2rpc =
                    (com.caucho.hessian.io.Hessian2Input) newInput(body);
                com.caucho.hessian.io.SerializerFactory sf = new com.caucho.hessian.io.SerializerFactory();
                sf.setAllowNonSerializable(true);
                h2rpc.setSerializerFactory(sf);
                h2rpc.readMethod();
                return h2rpc.readObject(Object.class);
            } catch (Throwable t) { System.out.println("[" + ep + "] S7 fail: " + t); }

            // Strategy 8: allowNonSerializable + readObject(Object.class)
            try {
                com.caucho.hessian.io.Hessian2Input h2 =
                    new com.caucho.hessian.io.Hessian2Input(new ByteArrayInputStream(body));
                com.caucho.hessian.io.SerializerFactory sf = new com.caucho.hessian.io.SerializerFactory();
                sf.setAllowNonSerializable(true);
                h2.setSerializerFactory(sf);
                return h2.readObject(Object.class);
            } catch (Throwable t) { System.out.println("[" + ep + "] S8 fail: " + t); }

            // Strategy 9: XBean/TomcatElRef fires via partial deserialization — Hessian2 creates
            // the XBean object but throws at nested class defs (0x43 string error). Extract
            // partially-built objects from Hessian2Input._refs and call triggerGadgets() on them.
            if (hessian2) {
                com.caucho.hessian.io.Hessian2Input h2partial =
                    new com.caucho.hessian.io.Hessian2Input(new ByteArrayInputStream(body));
                com.caucho.hessian.io.SerializerFactory sfPartial = new com.caucho.hessian.io.SerializerFactory();
                sfPartial.setAllowNonSerializable(true);
                h2partial.setSerializerFactory(sfPartial);
                try { h2partial.readObject(Object.class); } catch (Throwable ignored) {}
                try {
                    java.lang.reflect.Field refsF = null;
                    Class<?> c = h2partial.getClass();
                    while (c != null) {
                        try { refsF = c.getDeclaredField("_refs"); break; }
                        catch (NoSuchFieldException e) { c = c.getSuperclass(); }
                    }
                    if (refsF != null) {
                        refsF.setAccessible(true);
                        java.util.ArrayList<?> refs = (java.util.ArrayList<?>) refsF.get(h2partial);
                        if (refs != null && !refs.isEmpty()) {
                            System.out.println("[hessian2] S9: " + refs.size() + " partial refs, triggering gadgets");
                            for (Object ref : refs) {
                                if (ref != null) {
                                    final Object r = ref;
                                    new Thread(() -> triggerGadgets(r), "partial-trigger").start();
                                    try { Thread.sleep(3000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                                }
                            }
                        }
                    }
                } catch (Throwable ignored) {}
            }
            throw new Exception("deserHessian: all strategies exhausted for " + body.length + "-byte payload");
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
                    // Fix H2 1.4.197 INIT truncation: extract INIT SQL and execute separately
                    // to avoid H2 URL parser stopping at ';' inside method body
                    String initSql = null;
                    String baseUrl = url;
                    int initIdx = url.indexOf(";INIT=");
                    if (initIdx < 0) initIdx = url.indexOf(";init=");
                    if (initIdx >= 0) {
                        baseUrl = url.substring(0, initIdx);
                        // Everything after ";INIT=" is the SQL (may use \; as statement separator)
                        String rest = url.substring(initIdx + 6);
                        initSql = rest;
                    }
                    java.sql.Connection c = java.sql.DriverManager.getConnection(baseUrl, "sa", "");
                    if (initSql != null) {
                        System.out.println("[h2jdbc] Executing INIT SQL manually: " + initSql.substring(0, Math.min(initSql.length(), 200)));
                        try (java.sql.Statement stmt = c.createStatement()) {
                            // Split on \; (escaped semicolons used as statement separators in H2 INIT URLs)
                            for (String sql : initSql.split("\\\\;")) {
                                String trimmed = sql.trim();
                                if (!trimmed.isEmpty()) {
                                    System.out.println("[h2jdbc] Executing: " + trimmed);
                                    try { stmt.execute(trimmed); } catch (Throwable se) {
                                        System.out.println("[h2jdbc] SQL error: " + se.getMessage());
                                    }
                                }
                            }
                        }
                    }
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
// build-bust-1777530000
