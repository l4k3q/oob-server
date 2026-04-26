package com.oobx.rebind;

import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store mapping token -> (className, classBytes).
 * The LDAP listener in the Python broker calls /class?token=...&class_name=...
 * which hits ClassController and looks up here.
 */
@Component
public class RebindStore {

    private final Map<String, Entry> store = new ConcurrentHashMap<>();

    public void register(String token, String className, byte[] classBytes) {
        store.put(token, new Entry(className, classBytes));
    }

    public void remove(String token) {
        store.remove(token);
    }

    public Entry get(String token) {
        return store.get(token);
    }

    public record Entry(String className, byte[] classBytes) {}
}
