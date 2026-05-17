package com.oobx.controller;

import com.oobx.rebind.RebindStore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Generates JRMP referral response bytes for RMI rebind.
 * Called by the Python RMI listener when it needs a rebind payload.
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

        byte[] referralBytes = buildJrmpReferral(codebase, className);
        if (referralBytes.length == 0) {
            return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).build();
        }
        return ResponseEntity.ok()
                .header("Content-Type", "application/octet-stream")
                .body(referralBytes);
    }

    private byte[] buildJrmpReferral(String codebase, String className) {
        // RMI rebind needs a real JRMP referral frame. Returning HTTP 501 is
        // safer than a 200 with an empty body, which made clients fail later
        // with misleading transport errors.
        return new byte[0];
    }
}
