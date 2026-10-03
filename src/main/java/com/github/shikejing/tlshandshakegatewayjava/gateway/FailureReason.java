package com.github.shikejing.tlshandshakegatewayjava.gateway;

/**
 * Machine-distinguishable reasons for a failed peer verification.
 */
public enum FailureReason {
    /** The presented chain is missing an intermediate certificate. */
    CHAIN_INCOMPLETE,
    /** A certificate signature in the chain could not be verified. */
    SIGNATURE_INVALID,
    /** The chain does not terminate at a configured trust anchor. */
    UNTRUSTED_ROOT,
    /** A certificate in the chain is expired. */
    CERT_EXPIRED,
    /** A certificate in the chain is not yet valid. */
    CERT_NOT_YET_VALID,
    /** keyUsage extension does not allow the required operation. */
    KEY_USAGE_MISMATCH,
    /** extendedKeyUsage does not match the peer role (clientAuth vs serverAuth). */
    EXTENDED_KEY_USAGE_MISMATCH,
    /** basicConstraints violated (e.g. a non-CA certificate issuing certificates). */
    BASIC_CONSTRAINTS_VIOLATION,
    /** No configured public-key fingerprint matched the peer certificate. */
    PIN_MISMATCH,
    /** A certificate in the chain is revoked. */
    CERT_REVOKED,
    /** The revocation data source was unavailable and policy is fail-closed. */
    REVOCATION_STATUS_UNAVAILABLE,
    /** The peer did not present any certificate. */
    NO_PEER_CERTIFICATE
}
