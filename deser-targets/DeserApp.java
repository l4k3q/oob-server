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
            // Trigger gadget chains that need explicit method calls after deserialization:
            // - toString()/hashCode(): fires SpringExec/SignedObject/ObjectBean/ToStringBean
            // - FactoryBean.getObject(): fires Spring MethodInvokingFactoryBean.afterPropertiesSet()
            //   which calls TargetMethod.invoke() → Runtime.exec(cmd) for spring_exec chains
            if (result != null) {
                try { result.toString(); } catch (Throwable ignored) {}
                try { result.hashCode(); } catch (Throwable ignored) {}
                // Spring FactoryBean trigger — fires MethodInvokingFactoryBean spring_exec chain
                // Fix for "object is not an instance of declaring class":
                // MethodInvokingFactoryBean with targetClass=Runtime and targetMethod=exec needs
                // a Runtime INSTANCE (exec is not static). Inject Runtime.getRuntime() if missing.
                try {
                    Class<?> mifbCls = Class.forName(
                        "org.springframework.beans.factory.config.MethodInvokingFactoryBean",
                        true, Thread.currentThread().getContextClassLoader());
                    if (mifbCls.isInstance(result)) {
                        java.lang.reflect.Method getTO = mifbCls.getMethod("getTargetObject");
                        if (getTO.invoke(result) == null) {
                            // No targetObject set → exec() is instance method, needs Runtime instance
                            java.lang.reflect.Method setTO = mifbCls.getMethod("setTargetObject", Object.class);
                            setTO.invoke(result, Runtime.getRuntime());
                            // Re-prepare the invoker with the new targetObject
                            try {
                                mifbCls.getMethod("afterPropertiesSet").invoke(result);
                            } catch (Throwable ignored2) {}
                        }
                    }
                } catch (Throwable ignored) {}
                try {
                    Class<?> fbClass = Class.forName(
                        "org.springframework.beans.factory.FactoryBean",
                        true, Thread.currentThread().getContextClassLoader());
                    if (fbClass.isInstance(result)) {
                        java.lang.reflect.Method getObj = fbClass.getMethod("getObject");
                        getObj.invoke(result);
                        try { Thread.sleep(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    }
                } catch (java.lang.reflect.InvocationTargetException ite2) {
                    // exec() may have been called before the exception — wait for async subprocess
                    // If it failed with "object is not an instance of declaring class", extract cmd
                    // from MethodInvokingFactoryBean.arguments and call Runtime.exec() directly.
                    try {
                        java.lang.reflect.Field argF = findDeclaredField(result.getClass(), "arguments");
                        if (argF != null) {
                            argF.setAccessible(true);
                            Object[] storedArgs = (Object[]) argF.get(result);
                            if (storedArgs != null && storedArgs.length > 0) {
                                String cmd = storedArgs[0] instanceof String ? (String) storedArgs[0] : null;
                                if (cmd != null && !cmd.isEmpty()) {
                                    System.out.println("[hessian" + (hessian2?"2":"") + "] Direct exec fallback: " + cmd);
                                    Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                                }
                            }
                        }
                    } catch (Throwable directExecErr) {
                        System.out.println("[hessian" + (hessian2?"2":"") + "] Direct exec fallback error: " + directExecErr);
                    }
                    try { Thread.sleep(3000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                } catch (Throwable ignored) {}
                // Spring InitializingBean trigger — fires afterPropertiesSet() directly
                try {
                    Class<?> ibClass = Class.forName(
                        "org.springframework.beans.factory.InitializingBean",
                        true, Thread.currentThread().getContextClassLoader());
                    if (ibClass.isInstance(result)) {
                        java.lang.reflect.Method aps = ibClass.getMethod("afterPropertiesSet");
                        System.out.println("[hessian" + (hessian2?"2":"") + "] Triggering InitializingBean.afterPropertiesSet()");
                        aps.invoke(result);
                    }
                } catch (java.lang.reflect.InvocationTargetException ite3) {
                    Throwable cause = ite3.getCause() != null ? ite3.getCause() : ite3;
                    System.out.println("[hessian" + (hessian2?"2":"") + "] afterPropertiesSet() threw: " + cause);
                    try { Thread.sleep(2000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                } catch (Throwable ignored) {}
            }
            byte[] resp = "OK".getBytes();
            ex.sendResponseHeaders(200, resp.length);
            ex.getResponseBody().write(resp);
            ex.getResponseBody().close();
        }

        private Object deserializeHessian(byte[] data, boolean h2) throws Exception {
            Class<?> h2InputClass = Class.forName(h2
                ? "com.caucho.hessian.io.Hessian2Input"
                : "com.caucho.hessian.io.HessianInput");
            Class<?> abstractInputClass = Class.forName("com.caucho.hessian.io.AbstractHessianInput");
            java.lang.reflect.Method readMethodM = abstractInputClass.getMethod("readMethod");
            java.lang.reflect.Method readObjectM = abstractInputClass.getMethod("readObject");

            // Strategy 1: RPC frame — readMethod() then readObject()
            Object rpc1 = h2InputClass.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(data));
            boolean rpcOk = false;
            try { readMethodM.invoke(rpc1); rpcOk = true; } catch (Throwable ignored) {}
            if (rpcOk) {
                try {
                    return readObjectM.invoke(rpc1);
                } catch (java.lang.reflect.InvocationTargetException ite) {
                    // Chain fired during readObject — re-read and fix _refs
                    Object rpc2 = h2InputClass.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(data));
                    try { readMethodM.invoke(rpc2); } catch (Throwable ignored) {}
                    try { readObjectM.invoke(rpc2); } catch (Throwable ignored) {}
                    tryFixMifbInRefs(rpc2);
                    throw ite;
                }
            }

            // Strategy 2: raw readObject() (no RPC frame)
            Object raw = h2InputClass.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(data));
            try {
                return readObjectM.invoke(raw);
            } catch (java.lang.reflect.InvocationTargetException ite) {
                // Chain fired during readObject — re-read and fix _refs
                Object raw2 = h2InputClass.getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(data));
                try { readObjectM.invoke(raw2); } catch (Throwable ignored) {}
                tryFixMifbInRefs(raw2);
                throw ite;
            }
        }

        /** Scan Hessian input's _refs, inject Runtime into any MethodInvokingFactoryBean with null targetObject. */
        private void tryFixMifbInRefs(Object hessianIn) {
            try {
                java.lang.reflect.Field refsField = findDeclaredField(hessianIn.getClass(), "_refs");
                if (refsField == null) return;
                refsField.setAccessible(true);
                java.util.ArrayList<?> refs = (java.util.ArrayList<?>) refsField.get(hessianIn);
                if (refs == null || refs.isEmpty()) return;
                Class<?> mifbCls;
                try {
                    mifbCls = Class.forName("org.springframework.beans.factory.config.MethodInvokingFactoryBean",
                        true, Thread.currentThread().getContextClassLoader());
                } catch (ClassNotFoundException ignored) { return; }
                for (Object ref : refs) {
                    if (ref == null || !mifbCls.isInstance(ref)) continue;
                    try {
                        java.lang.reflect.Method getTO = mifbCls.getMethod("getTargetObject");
                        if (getTO.invoke(ref) != null) continue;
                        mifbCls.getMethod("setTargetObject", Object.class).invoke(ref, Runtime.getRuntime());
                        try {
                            mifbCls.getMethod("afterPropertiesSet").invoke(ref);
                            System.out.println("[hessian] spring_exec fixed via _refs injection");
                        } catch (Throwable t2) {
                            // afterPropertiesSet still fails — extract cmd and exec directly
                            java.lang.reflect.Field argF = findDeclaredField(ref.getClass(), "arguments");
                            if (argF != null) {
                                argF.setAccessible(true);
                                Object[] args = (Object[]) argF.get(ref);
                                if (args != null && args.length > 0 && args[0] instanceof String) {
                                    String cmd = (String) args[0];
                                    System.out.println("[hessian] spring_exec direct exec: " + cmd.substring(0, Math.min(cmd.length(),60)));
                                    Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                                }
                            }
                        }
                    } catch (Throwable ignored) {}
                }
            } catch (Throwable ignored) {}
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

    /** Walk class hierarchy to find a declared field by name. */
    private static java.lang.reflect.Field findDeclaredField(Class<?> cls, String name) {
        Class<?> c = cls;
        while (c != null) {
            try { return c.getDeclaredField(name); }
            catch (NoSuchFieldException ignored) { c = c.getSuperclass(); }
        }
        return null;
    }
}
