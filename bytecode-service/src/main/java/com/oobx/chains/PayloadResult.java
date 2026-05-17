package com.oobx.chains;

import java.util.Base64;
import java.util.Map;

public record PayloadResult(
        String contentType,
        byte[] bytes,
        Map<String, Object> meta) {

    public Map<String, Object> toApiResponse() {
        return Map.of(
                "content_type", contentType,
                "value", Base64.getEncoder().encodeToString(bytes),
                "meta", meta
        );
    }
}
