package com.oobx.chains;

import java.util.Map;

public interface ChainHandler {
    /**
     * Generate payload bytes.
     *
     * @param chainId the catalog chain ID (e.g. "ysoserial_cc6")
     * @param params  caller-provided parameters (cmd, url, class_name, etc.)
     * @return PayloadResult with bytes and metadata
     */
    PayloadResult generate(String chainId, Map<String, Object> params) throws Exception;
}
