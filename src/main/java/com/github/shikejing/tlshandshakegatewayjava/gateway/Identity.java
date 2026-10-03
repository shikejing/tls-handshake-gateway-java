package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Local identity: a private key and its certificate chain (leaf first).
 */
public record Identity(PrivateKey key, List<X509Certificate> chain) {

    public Identity {
        chain = List.copyOf(chain);
    }

    public X509Certificate leaf() {
        return chain.get(0);
    }
}
