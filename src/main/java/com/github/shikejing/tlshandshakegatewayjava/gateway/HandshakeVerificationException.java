package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.security.cert.CertificateException;

/**
 * Thrown when peer verification fails. Carries a {@link FailureReason} so callers
 * can distinguish the exact cause without parsing messages.
 */
public class HandshakeVerificationException extends CertificateException {

    private final FailureReason reason;

    public HandshakeVerificationException(FailureReason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public HandshakeVerificationException(FailureReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public FailureReason getReason() {
        return reason;
    }
}
