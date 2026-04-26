package com.oobx.controller;

import com.oobx.rebind.RebindStore;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Base64;
import java.util.Map;

/**
 * Serves .class files for JNDI codebase delivery.
 * Called by Python http_collector when /callback/http/{token}/class/{class_name} is hit.
 */
@RestController
public class ClassController {

    private final RebindStore rebindStore;

    public ClassController(RebindStore rebindStore) {
        this.rebindStore = rebindStore;
    }

    @GetMapping("/class")
    public ResponseEntity<byte[]> getClass(
            @RequestParam String token,
            @RequestParam(required = false, defaultValue = "") String class_name) {
        RebindStore.Entry entry = rebindStore.get(token);
        if (entry == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.CONTENT_TYPE, "application/java-vm");
        headers.set("X-Class-Name", entry.className());
        return new ResponseEntity<>(entry.classBytes(), headers, HttpStatus.OK);
    }

    @PostMapping("/rebind/register")
    public ResponseEntity<Map<String, String>> registerRebind(@RequestBody Map<String, String> body) {
        String token = body.get("token");
        String className = body.get("class_name");
        String byteB64 = body.get("bytecode_b64");
        if (token == null || className == null || byteB64 == null) {
            return ResponseEntity.badRequest().body(Map.of("error", "token, class_name, bytecode_b64 required"));
        }
        byte[] bytes = Base64.getDecoder().decode(byteB64);
        rebindStore.register(token, className, bytes);
        return ResponseEntity.ok(Map.of("status", "registered", "token", token, "class_name", className));
    }

    @DeleteMapping("/rebind/{token}")
    public ResponseEntity<Map<String, String>> clearRebind(@PathVariable String token) {
        rebindStore.remove(token);
        return ResponseEntity.ok(Map.of("status", "cleared"));
    }
}
