package com.github.shikejing.tlshandshakegatewayjava.gateway;

import javax.net.ssl.SSLSocket;
import java.security.cert.X509Certificate;

/**
 * Callback for successfully established and verified inbound connections.
 */
@FunctionalInterface
public interface ConnectionHandler {

    /**
     * @param socket   the established, verified TLS socket (owned by the caller;
     *                 closed after this method returns)
     * @param peerChain verified peer certificate chain, leaf first
     */
    void handle(SSLSocket socket, X509Certificate[] peerChain) throws Exception;
}
