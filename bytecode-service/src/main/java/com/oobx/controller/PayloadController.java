package com.oobx.controller;

import com.oobx.chains.ChainHandler;
import com.oobx.chains.ChainRegistry;
import com.oobx.chains.PayloadResult;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
public class PayloadController {

    private final ChainRegistry registry;

    public PayloadController(ChainRegistry registry) {
        this.registry = registry;
    }

    @PostMapping("/generate")
    public ResponseEntity<Map<String, Object>> generate(@RequestBody Map<String, Object> body) {
        String chain = (String) body.get("chain");
        @SuppressWarnings("unchecked")
        Map<String, Object> params = (Map<String, Object>) body.getOrDefault("params", Map.of());

        ChainHandler handler = registry.get(chain);
        if (handler == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "unknown chain: " + chain,
                    "supported", registry.supported()));
        }
        try {
            PayloadResult result = handler.generate(chain, params);
            return ResponseEntity.ok(result.toApiResponse());
        } catch (Exception e) {
            // Unwrap InvocationTargetException to expose actual cause
            Throwable root = e;
            while (root.getCause() != null) root = root.getCause();
            String msg = root.getMessage() != null ? root.getMessage() : root.getClass().getName();
            return ResponseEntity.internalServerError().body(
                Map.of("error", msg, "type", root.getClass().getSimpleName()));
        }
    }

    @GetMapping("/chains")
    public ResponseEntity<Map<String, Object>> listChains() {
        return ResponseEntity.ok(Map.of(
            "chains", registry.supported(),
            "java_chains_available", registry.javaChainsAvailable(),
            "unavailable_jchains", registry.unavailableJavaChains()
        ));
    }
}
