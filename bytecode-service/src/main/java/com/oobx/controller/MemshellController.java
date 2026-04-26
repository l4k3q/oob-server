package com.oobx.controller;

import com.oobx.chains.PayloadResult;
import com.oobx.memshells.MemshellFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/memshell")
public class MemshellController {

    private final MemshellFactory factory;

    public MemshellController(MemshellFactory factory) {
        this.factory = factory;
    }

    @PostMapping("/generate")
    public ResponseEntity<Map<String, Object>> generate(@RequestBody Map<String, Object> body) {
        String framework = (String) body.getOrDefault("framework", "tomcat");
        String type = (String) body.getOrDefault("type", "filter");
        @SuppressWarnings("unchecked")
        Map<String, Object> params = (Map<String, Object>) body.getOrDefault("params", Map.of());

        try {
            PayloadResult result = factory.generate(framework, type, params);
            return ResponseEntity.ok(result.toApiResponse());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }
}
