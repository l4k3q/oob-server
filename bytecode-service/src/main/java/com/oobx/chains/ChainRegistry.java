package com.oobx.chains;

import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Maps every catalog chain ID → ChainHandler.
 */
@Component
public class ChainRegistry {

    private final Map<String, ChainHandler> handlers = new HashMap<>();

    public ChainRegistry(
            YsoserialHandler ysoserial,
            CustomBytecodeHandler customBytecode,
            ShiroHandler shiro,
            ShiroChainHandler shiroCombined,
            HessianChainHandler hessian,
            C3P0ChainHandler c3p0,
            XStreamChainHandler xstream,
            FastjsonChainHandler fastjson) {

        // ── ysoserial catalog short IDs ──────────────────────────────────────
        Map<String, String> catalogIds = Map.ofEntries(
                Map.entry("ysoserial_cc1",         "CommonsCollections1"),
                Map.entry("ysoserial_cc2",         "CommonsCollections2"),
                Map.entry("ysoserial_cc3",         "CommonsCollections3"),
                Map.entry("ysoserial_cc4",         "CommonsCollections4"),
                Map.entry("ysoserial_cc5",         "CommonsCollections5"),
                Map.entry("ysoserial_cc6",         "CommonsCollections6"),
                Map.entry("ysoserial_cc7",         "CommonsCollections7"),
                Map.entry("ysoserial_cb1",         "CommonsBeanutils1"),
                Map.entry("cb_no_cc",              "CommonsBeanutils1"),
                Map.entry("ysoserial_spring1",     "Spring1"),
                Map.entry("ysoserial_spring2",     "Spring2"),
                Map.entry("ysoserial_hibernate1",  "Hibernate1"),
                Map.entry("ysoserial_rome",        "ROME"),
                Map.entry("ysoserial_groovy1",     "Groovy1"),
                Map.entry("ysoserial_jdk7u21",     "Jdk7u21"),
                Map.entry("ysoserial_urldns",      "URLDNS"),
                Map.entry("ysoserial_jrmp_client", "JRMPClient"),
                Map.entry("ysoserial_jrmplistener","JRMPListener")
        );
        catalogIds.forEach((id, _chain) -> handlers.put(id, ysoserial));

        // Also register by full lower-cased chain name
        for (String chain : YsoserialHandler.SUPPORTED_CHAINS) {
            handlers.put("ysoserial_" + chain.toLowerCase(), ysoserial);
            handlers.put(chain.toLowerCase(), ysoserial);
        }

        // ── Custom inline bytecode ───────────────────────────────────────────
        handlers.put("custom_bytecode",   customBytecode);
        handlers.put("memshell_bytecode", customBytecode);

        // ── Shiro cookie wrapper (raw JNDI → existing handler) ───────────────
        handlers.put("exfil_shiro", shiro);

        // ── JNDI-delivered deserialization ───────────────────────────────────
        handlers.put("jndi_ldap_deserialize", ysoserial);

        // ── Shiro one-shot (auto inner-payload + AES encrypt) ────────────────
        handlers.put("shiro_cbc", shiroCombined);
        handlers.put("shiro_gcm", shiroCombined);

        // ── Hessian1 / Hessian2 protocol chains ─────────────────────────────
        handlers.put("hessian1_cc6",    hessian);
        handlers.put("hessian1_spring", hessian);
        handlers.put("hessian1_rome",   hessian);
        handlers.put("hessian2_cc6",    hessian);
        handlers.put("hessian2_spring", hessian);
        handlers.put("hessian2_rome",   hessian);

        // ── C3P0 secondary deserialization ───────────────────────────────────
        handlers.put("c3p0_jndi",      c3p0);
        handlers.put("c3p0_wrapperds", c3p0);

        // ── XStream gadgets ──────────────────────────────────────────────────
        handlers.put("xstream_eventhandler", xstream);
        handlers.put("xstream_imageio",      xstream);

        // ── Fastjson gadgets ─────────────────────────────────────────────────
        handlers.put("fastjson_jdbcrowset",    fastjson);
        handlers.put("fastjson_jdbcrowset_v2", fastjson);
        handlers.put("fastjson_bcel",          fastjson);

        // ── jchains_* aliases → direct native implementations ────────────────
        // These mirror the java-chains chain IDs, implemented natively above
        handlers.put("jchains_hessian1_spring", hessian);
        handlers.put("jchains_hessian1_rome",   hessian);
        handlers.put("jchains_hessian2_spring", hessian);
        handlers.put("jchains_hessian2_rome",   hessian);
        handlers.put("jchains_shiro_cbc",       shiroCombined);
        handlers.put("jchains_shiro_gcm",       shiroCombined);
        handlers.put("jchains_native_cc6",      ysoserial);
        handlers.put("jchains_native_cb1",      ysoserial);
        handlers.put("jchains_xstream",         xstream);
        handlers.put("jchains_fastjson",        fastjson);
    }

    public ChainHandler get(String chainId) {
        return handlers.get(chainId.toLowerCase());
    }

    public Set<String> supported() {
        return handlers.keySet();
    }
}
