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

public class DeserApp {

    public static void main(String[] args) throws Exception {
        int port = 8888;
        String portEnv = System.getenv("PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            port = Integer.parseInt(portEnv);
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/deser", new DeserHandler());
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

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String version = System.getProperty("java.version");
            byte[] resp = ("{\"status\":\"ok\",\"java\":\"" + version + "\",\"endpoints\":[\"/deser\"]}").getBytes();
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }
    }
}
