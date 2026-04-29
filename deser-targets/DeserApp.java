package com.vulnlab.deser;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

// Hessian imports (optional — only available in pom-spring3.xml + pom-cb2.xml builds)
// Using reflection to avoid compile errors in pom-cc3.xml (no Hessian dep)

public class DeserApp {

    public static void main(String[] args) throws Exception {
        int port = 8888;
        String portEnv = System.getenv("PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            port = Integer.parseInt(portEnv);
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/deser", new DeserHandler());
        server.createContext("/hessian",  new HessianHandler(false));
        server.createContext("/hessian2", new HessianHandler(true));
        server.createContext("/health", new HealthHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();
        System.out.println("[DeserApp] Java " + System.getProperty("java.version") + " listening on port " + port);
    }

    static class DeserHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            InputStream body = ex.getRequestBody();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = body.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            byte[] data = baos.toByteArray();

            try {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
                Object obj = ois.readObject();
                ois.close();
                System.out.println("[deser] OK: " + (obj == null ? "null" : obj.getClass().getName()));
            } catch (Throwable t) {
                System.out.println("[deser] Error: " + t);
            }

            byte[] resp = "OK".getBytes();
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }
    }

    /**
     * Hessian deserialization endpoint — supports both Hessian1 and Hessian2 protocols.
     * Required for jchains_hessian1/2_spring_exec against Spring 4.x target.
     * Uses reflection to avoid compile failure when Hessian jar is not on classpath.
     */
    static class HessianHandler implements HttpHandler {
        private final boolean hessian2;
        HessianHandler(boolean hessian2) { this.hessian2 = hessian2; }

        public void handle(HttpExchange ex) throws IOException {
            InputStream body = ex.getRequestBody();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096]; int n;
            while ((n = body.read(buf)) != -1) baos.write(buf, 0, n);
            byte[] data = baos.toByteArray();
            System.out.println("[hessian" + (hessian2?"2":"") + "] Received " + data.length + " bytes");
            Object result = null;
            try {
                result = deserializeHessian(data, hessian2);
                System.out.println("[hessian" + (hessian2?"2":"") + "] OK: " + result);
            } catch (java.lang.reflect.InvocationTargetException ite) {
                // InvocationTargetException wraps exception from Spring/Hessian chain.
                // The exec may have already been launched (async) — log cause and wait for it.
                Throwable cause = ite.getCause() != null ? ite.getCause() : ite;
                System.out.println("[hessian" + (hessian2?"2":"") + "] InvocationTargetException cause: " + cause);
                // Give async subprocess time to complete the OOB callback
                try { Thread.sleep(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
            } catch (Throwable t) {
                System.out.println("[hessian" + (hessian2?"2":"") + "] Error: " + t.getClass().getName() + ": " + t.getMessage());
            }
            // Call toString() on result if available — fires SpringExec/SignedObject chains
            if (result != null) {
                try { result.toString(); } catch (Throwable ignored) {}
            }
            byte[] resp = "OK".getBytes();
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }

        private Object deserializeHessian(byte[] data, boolean h2) throws Exception {
            // Try Hessian RPC frame (method call + args) first, then raw object.
            // Uses reflection to avoid compile failure when Hessian jar is not on classpath.
            Class<?> h2InputClass = Class.forName(h2
                ? "com.caucho.hessian.io.Hessian2Input"
                : "com.caucho.hessian.io.HessianInput");
            Class<?> abstractInputClass = Class.forName("com.caucho.hessian.io.AbstractHessianInput");
            try {
                Object rpcIn = h2InputClass.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(data));
                abstractInputClass.getMethod("readMethod").invoke(rpcIn);
                return abstractInputClass.getMethod("readObject").invoke(rpcIn);
            } catch (Throwable ignored) {}
            Object in = h2InputClass.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(data));
            return abstractInputClass.getMethod("readObject").invoke(in);
        }
    }

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String version = System.getProperty("java.version");
            byte[] resp = ("{\"status\":\"ok\",\"java\":\"" + version + "\",\"endpoints\":[\"/deser\",\"/hessian\",\"/hessian2\"]}").getBytes();
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }
    }
}
