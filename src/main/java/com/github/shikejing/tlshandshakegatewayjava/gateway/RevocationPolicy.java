package com.github.shikejing.tlshandshakegatewayjava.gateway;

/**
 * How to treat a handshake when the revocation data source is unavailable.
 */
public enum RevocationPolicy {
    /**
     * Reject the handshake when revocation status cannot be determined.
     * Safest option: an attacker cannot bypass revocation by breaking the source.
     */
    FAIL_CLOSED,
    /**
     * Allow the handshake when revocation status cannot be determined.
     * Favours availability; revoked certificates may be accepted while the
     * source is down. Use only when this trade-off is understood.
     */
    FAIL_OPEN
}
