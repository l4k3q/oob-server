package com.vulnlab.blazeds;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * BlazeDS AMF3 deserialization target.
 *
 * Exposes two endpoints:
 *   POST /messagebroker/amf   — AMF3 deserialization via BlazeDS MessageBroker
 *   GET  /health              — JSON health check
 *
 * The jchains_blazeds_axis2 chain generates an AMF3 payload that encodes an
 * Axis2 MetaDataEntry object. When BlazeDS deserializes it, the gadget chain
 * triggers via CB1 → TemplatesImpl → bytecode execution.
 *
 * Gadgets required on classpath (all bundled via pom-blazeds.xml):
 *   - blazeds-common 4.7.3.1  (AMF3Deserializer, flex.messaging.io.amf.*)
 *   - commons-beanutils 1.9.4  (CB1)
 *   - commons-collections 3.2.1  (CC3)
 *   - commons-collections4 4.0   (CC4)
 *
 * java-chains produces the payload in binary AMF3 format.
 * This server reads the raw body and passes it to BlazeDS AMF3Deserializer.
 * Any deserialization exception is swallowed (RCE happens before the exception).
 */
public class BlazeDSApp {

    public static void main(String[] args) throws Exception {
        int port = 8080;
        String portEnv = System.getenv("PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            port = Integer.parseInt(portEnv);
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        server.createContext("/messagebroker/amf", new AmfHandler());
        server.createContext("/health", new HealthHandler());
        server.setExecutor(Executors.newCachedThreadPool());
        server.start();

        System.out.println("[BlazeDSApp] BlazeDS AMF3 target started");
        System.out.println("[BlazeDSApp] Java " + System.getProperty("java.version")
                + " listening on port " + port);
        System.out.println("[BlazeDSApp] Endpoint: POST /messagebroker/amf  (Content-Type: application/x-amf)");
        System.out.println("[BlazeDSApp] Gadgets: BlazeDS 4.7.3 + CC3 + CC4 + CB1");
    }

    // ── AMF3 deserialization handler ──────────────────────────────────────────

    static class AmfHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            // Read entire request body
            InputStream body = ex.getRequestBody();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = body.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            byte[] data = baos.toByteArray();

            System.out.println("[amf] Received " + data.length + " bytes from "
                    + ex.getRemoteAddress());

            if (data.length == 0) {
                byte[] resp = "ERROR: empty body".getBytes();
                ex.sendResponseHeaders(400, resp.length);
                ex.getResponseBody().write(resp);
                ex.getResponseBody().close();
                return;
            }

            // Attempt BlazeDS AMF3 deserialization
            // Uses reflection so the code compiles even if blazeds-common is absent
            // (though at runtime it must be present for the exploit to work)
            try {
                deserializeAmf3(data);
                System.out.println("[amf] Deserialization completed (or RCE triggered)");
            } catch (Throwable t) {
                // RCE side-effect already happened; exception is expected from gadget chains
                System.out.println("[amf] Deserialization threw (expected for gadget chains): "
                        + t.getClass().getName() + " - " + t.getMessage());
            }

            byte[] resp = "OK".getBytes();
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }

        /**
         * Deserialize raw AMF3 bytes using BlazeDS flex.messaging.io.amf.Amf3Input.
         *
         * BlazeDS AMF3 deserialization path (4.7.3):
         *   Amf3Input.readObject()
         *     → readObjectType()
         *       → if object-marker → readScriptObject()
         *         → instantiateClass() / assignValue()
         *
         * The Axis2MetaDataEntry gadget (java-chains BlazeDSAMF3AMPayload) encodes
         * a specially crafted AMF3 object that triggers CB1 during property assignment.
         *
         * We use reflection to avoid hard compile-time dependency on blazeds-common.
         * At runtime the shade jar includes blazeds-common 4.7.3.1.
         */
        private void deserializeAmf3(byte[] data) throws Exception {
            // flex.messaging.io.SerializationContext
            Class<?> ctxClass = Class.forName("flex.messaging.io.SerializationContext");
            Object ctx = ctxClass.getDeclaredConstructor().newInstance();

            // flex.messaging.io.amf.Amf3Input
            Class<?> amf3InputClass = Class.forName("flex.messaging.io.amf.Amf3Input");
            Object amf3Input = amf3InputClass
                    .getDeclaredConstructor(ctxClass)
                    .newInstance(ctx);

            // setInputStream(InputStream)
            amf3InputClass.getMethod("setInputStream", java.io.InputStream.class)
                    .invoke(amf3Input, new ByteArrayInputStream(data));

            // readObject() — triggers deserialization and any gadget chain
            amf3InputClass.getMethod("readObject").invoke(amf3Input);
        }
    }

    // ── Health handler ─────────────────────────────────────────────────────────

    static class HealthHandler implements HttpHandler {
        public void handle(HttpExchange ex) throws IOException {
            String javaVersion = System.getProperty("java.version");
            // Check if BlazeDS is actually on the classpath
            String blazedsStatus;
            try {
                Class.forName("flex.messaging.io.amf.Amf3Input");
                blazedsStatus = "ok";
            } catch (ClassNotFoundException e) {
                blazedsStatus = "missing";
            }
            String resp = String.format(
                    "{\"status\":\"ok\",\"java\":\"%s\",\"blazeds\":\"%s\","
                    + "\"endpoints\":[\"/messagebroker/amf\",\"/health\"],"
                    + "\"gadgets\":[\"CC3.2.1\",\"CC4.0\",\"CB1.9.4\",\"BlazeDS4.7.3\"]}",
                    javaVersion, blazedsStatus);
            byte[] respBytes = resp.getBytes();
            ex.sendResponseHeaders(200, respBytes.length);
            ex.getResponseBody().write(respBytes);
            ex.getResponseBody().close();
        }
    }
}
