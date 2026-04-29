package com.vulnlab.shiro;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.Executors;

/**
 * Self-written Shiro RememberMe deserialization vulnerability target.
 *
 * Simulates the Apache Shiro rememberMe cookie processing bug:
 *   CBC mode (CVE-2016-4437 / Shiro ≤1.2.4) — POST /login
 *   GCM mode (CVE-2020-11989 / Shiro ≤1.6.0) — POST /login-gcm
 *
 * Classpath: CC3.2.1 + BeanUtils1.9.4 for gadget chains.
 * Default key: kPH+bIxk5D2deZiIxcaaaA== (Shiro 1.2.4 hardcoded key)
 */
public class ShiroVulnApp {

    static final byte[] DEFAULT_KEY = Base64.getDecoder().decode(
        System.getenv().getOrDefault("SHIRO_KEY", "kPH+bIxk5D2deZiIxcaaaA=="));

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getenv().getOrDefault("PORT", "8080"));
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/login",     new RememberMeHandler("CBC"));
        server.createContext("/login-gcm", new RememberMeHandler("GCM"));
        server.createContext("/health",    new HealthHandler());
        server.createContext("/check-rce", new CheckRceHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("[ShiroVuln] Listening on port " + port);
        System.out.println("  POST /login      AES-CBC rememberMe (CVE-2016-4437)");
        System.out.println("  POST /login-gcm  AES-GCM rememberMe (CVE-2020-11989)");
    }

    static class RememberMeHandler implements HttpHandler {
        private final String mode;

        RememberMeHandler(String mode) { this.mode = mode; }

        @Override
        public void handle(HttpExchange ex) throws IOException {
            // Consume POST body (ignore content)
            InputStream bodyStream = ex.getRequestBody();
            byte[] buf = new byte[4096];
            while (bodyStream.read(buf) != -1) { /* drain */ }

            String rememberMe = extractCookie(ex.getRequestHeaders().getFirst("Cookie"), "rememberMe");

            if (rememberMe != null && !rememberMe.isEmpty()) {
                processRememberMe(rememberMe);
            }
            // Always return 302 redirect — mimics Shiro login page behavior
            ex.getResponseHeaders().add("Location", "/");
            ex.sendResponseHeaders(302, -1);
        }

        private void processRememberMe(String cookieValue) {
            try {
                byte[] decoded = Base64.getDecoder().decode(cookieValue);
                if (decoded.length < 17) {
                    System.out.println("[shiro-" + mode + "] Cookie too short: " + decoded.length);
                    return;
                }
                byte[] iv         = Arrays.copyOf(decoded, 16);
                byte[] ciphertext = Arrays.copyOfRange(decoded, 16, decoded.length);

                byte[] plaintext = "GCM".equals(mode)
                    ? decryptGCM(ciphertext, DEFAULT_KEY, iv)
                    : decryptCBC(ciphertext, DEFAULT_KEY, iv);

                System.out.println("[shiro-" + mode + "] Decrypted " + plaintext.length + " bytes → deserializing");
                try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(plaintext))) {
                    Object obj = ois.readObject();
                    System.out.println("[shiro-" + mode + "] Deserialized: " +
                        (obj == null ? "null" : obj.getClass().getName()));
                }
            } catch (Throwable t) {
                System.out.println("[shiro-" + mode + "] Processing error: " + t);
            }
        }

        private static byte[] decryptCBC(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
            Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return c.doFinal(ciphertext);
        }

        private static byte[] decryptGCM(byte[] ciphertext, byte[] key, byte[] iv) throws Exception {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
            return c.doFinal(ciphertext);
        }
    }

    static class CheckRceHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            java.io.File tmp = new java.io.File("/tmp");
            java.io.File[] files = tmp.listFiles();
            int count = 0;
            StringBuilder sb = new StringBuilder("[");
            if (files != null) {
                for (java.io.File f : files) {
                    if (f.getName().startsWith("oobx_")) {
                        if (count > 0) sb.append(",");
                        sb.append("\"").append(f.getName()).append("\"");
                        count++;
                    }
                }
            }
            sb.append("]");
            byte[] b = ("{\"rce_files\":" + sb + ",\"count\":" + count + "}").getBytes();
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.getResponseBody().close();
        }
    }

    static class HealthHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange ex) throws IOException {
            byte[] b = "{\"status\":\"ok\",\"endpoints\":[\"/login\",\"/login-gcm\",\"/check-rce\"]}".getBytes();
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.getResponseBody().close();
        }
    }

    static String extractCookie(String cookieHeader, String name) {
        if (cookieHeader == null) return null;
        for (String part : cookieHeader.split(";")) {
            String[] kv = part.trim().split("=", 2);
            if (kv.length == 2 && name.equals(kv[0].trim())) return kv[1].trim();
        }
        return null;
    }
}
