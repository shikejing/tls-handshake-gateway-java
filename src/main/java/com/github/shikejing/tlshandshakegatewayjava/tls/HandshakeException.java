package com.github.shikejing.tlshandshakegatewayjava.tls;

/**
 * 握手通道异常，携带失败原因码。
 */
public class HandshakeException extends Exception {

    private final FailureReason reason;

    public HandshakeException(FailureReason reason, String message) {
        super("[" + reason + "] " + message);
        this.reason = reason;
    }

    public HandshakeException(FailureReason reason, String message, Throwable cause) {
        super("[" + reason + "] " + message, cause);
        this.reason = reason;
    }

    public FailureReason getReason() {
        return reason;
    }
}
