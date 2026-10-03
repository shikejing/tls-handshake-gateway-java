package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.security.cert.X509Certificate;

/**
 * Local data source for certificate revocation status.
 */
public interface RevocationSource {

    /**
     * @param cert certificate to check
     * @return true if the certificate is revoked
     * @throws RevocationUnavailableException if the source cannot be consulted
     */
    boolean isRevoked(X509Certificate cert) throws RevocationUnavailableException;
}
