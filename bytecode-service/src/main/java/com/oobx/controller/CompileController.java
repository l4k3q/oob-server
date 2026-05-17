package com.oobx.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.tools.*;
import java.io.ByteArrayOutputStream;
import java.nio.file.*;
import java.util.Base64;
import java.util.Comparator;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RestController
@RequestMapping("/compile")
public class CompileController {

    private static final Pattern CLASS_PATTERN =
        Pattern.compile("(?:^|\\s)public\\s+class\\s+(\\w+)", Pattern.MULTILINE);

    @PostMapping
    public ResponseEntity<Map<String, Object>> compile(@RequestBody Map<String, String> body) {
        String source = body.get("source");
        String className = body.get("class_name");

        if (source == null || source.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "source is required"));
        }

        // Auto-detect class name from source if not provided
        if (className == null || className.isBlank()) {
            Matcher m = CLASS_PATTERN.matcher(source);
            if (m.find()) {
                className = m.group(1);
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "class_name required (could not auto-detect from source)"));
            }
        }

        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            return ResponseEntity.internalServerError()
                .body(Map.of("error", "JavaCompiler not available — container needs JDK not JRE"));
        }

        Path tmpDir = null;
        try {
            tmpDir = Files.createTempDirectory("oobx_compile_");
            Path srcFile = tmpDir.resolve(className + ".java");
            Files.writeString(srcFile, source);

            ByteArrayOutputStream errStream = new ByteArrayOutputStream();
            // Compile targeting Java 8 bytecode for maximum compatibility
            int exitCode = compiler.run(null, null, errStream,
                "-source", "8", "-target", "8",
                "-proc:none",
                srcFile.toString()
            );

            if (exitCode != 0) {
                return ResponseEntity.unprocessableEntity()
                    .body(Map.of("error", errStream.toString("UTF-8").trim()));
            }

            // Find the compiled class file (may be nested if source had a package)
            final String finalClassName = className;
            Path classFile = Files.walk(tmpDir)
                .filter(p -> p.getFileName().toString().equals(finalClassName + ".class"))
                .findFirst()
                .orElse(null);

            if (classFile == null) {
                return ResponseEntity.unprocessableEntity()
                    .body(Map.of("error", "compiled but " + className + ".class not found"));
            }

            byte[] classBytes = Files.readAllBytes(classFile);
            String b64 = Base64.getEncoder().encodeToString(classBytes);

            return ResponseEntity.ok(Map.of("class_name", className, "bytecode_b64", b64));

        } catch (Exception e) {
            return ResponseEntity.internalServerError()
                .body(Map.of("error", e.getMessage() != null ? e.getMessage() : e.getClass().getName()));
        } finally {
            if (tmpDir != null) {
                try {
                    Files.walk(tmpDir).sorted(Comparator.reverseOrder())
                        .forEach(p -> { try { Files.delete(p); } catch (Exception ignored) {} });
                } catch (Exception ignored) {}
            }
        }
    }
}
