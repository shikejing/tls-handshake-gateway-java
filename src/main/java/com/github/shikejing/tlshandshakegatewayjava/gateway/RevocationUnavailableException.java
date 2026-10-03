package com.github.shikejing.tlshandshakegatewayjava.gateway;

/**
 * Signals that the revocation data source could not be consulted at all
 * (as opposed to returning a definitive status).
 */
public class RevocationUnavailableException extends Exception {

    public RevocationUnavailableException(String message) {
        super(message);
    }

    public RevocationUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
