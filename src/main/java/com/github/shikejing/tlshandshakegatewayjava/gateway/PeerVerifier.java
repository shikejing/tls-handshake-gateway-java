package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.security.GeneralSecurityException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

/**
 * Verifies a peer certificate chain against a {@link SecurityPolicy} snapshot:
 * chain building to a trust anchor, validity, key usage / extended key usage
 * vs. the local role, basic constraints, public-key pins and revocation.
 *
 * <p>A verifier is bound to one immutable policy snapshot, so a single
 * handshake never observes a mix of old and new configuration.</p>
 */
public final class PeerVerifier {

    private static final Logger LOG = Logger.getLogger(PeerVerifier.class.getName());

    /** RFC 5280 extended key usage: id-kp-serverAuth. */
    private static final String EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    /** RFC 5280 extended key usage: id-kp-clientAuth. */
    private static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    private static final int KU_DIGITAL_SIGNATURE = 0;
    private static final int KU_KEY_CERT_SIGN = 5;

    private final SecurityPolicy policy;
    private final PeerRole localRole;

    public PeerVerifier(SecurityPolicy policy, PeerRole localRole) {
        this.policy = policy;
        this.localRole = localRole;
    }

    /**
     * Verify the peer chain.
     *
     * @param chain    chain as presented by the peer, leaf first
     * @param peerName logical peer name used to look up pins (may be null for none)
     * @throws HandshakeVerificationException with a specific {@link FailureReason}
     */
    public void verify(X509Certificate[] chain, String peerName) throws HandshakeVerificationException {
        if (chain == null || chain.length == 0) {
            throw new HandshakeVerificationException(
                    FailureReason.NO_PEER_CERTIFICATE, "peer did not present a certificate");
        }
        List<X509Certificate> path = buildPath(chain);
        checkValidity(path);
        checkBasicConstraints(path);
        checkKeyUsage(path);
        checkExtendedKeyUsage(path.get(0));
        checkPins(path.get(0), peerName);
        checkRevocation(path);
    }

    /**
     * Build a path from the leaf to a configured trust anchor, verifying each
     * signature. Presented intermediates and configured extra intermediates
     * are both considered.
     */
    private List<X509Certificate> buildPath(X509Certificate[] presented)
            throws HandshakeVerificationException {
        Set<X509Certificate> pool = new LinkedHashSet<>();
        pool.addAll(List.of(presented));
        pool.addAll(policy.getIntermediates());

        List<X509Certificate> path = new ArrayList<>();
        X509Certificate current = presented[0];
        path.add(current);

        while (true) {
            for (X509Certificate anchor : policy.getTrustAnchors()) {
                if (isIssuedBy(current, anchor)) {
                    // Chain terminates at a configured trust anchor.
                    return path;
                }
            }
            if (current.getSubjectX500Principal().equals(current.getIssuerX500Principal())) {
                throw new HandshakeVerificationException(FailureReason.UNTRUSTED_ROOT,
                        "certificate chain terminates at a self-signed certificate that is not"
                                + " a configured trust anchor (subject="
                                + current.getSubjectX500Principal() + ")");
            }
            X509Certificate issuer = null;
            boolean issuerFound = false;
            boolean signatureOk = false;
            for (X509Certificate candidate : pool) {
                if (candidate.equals(current) || path.contains(candidate)) {
                    continue;
                }
                if (!current.getIssuerX500Principal().equals(candidate.getSubjectX500Principal())) {
                    continue;
                }
                issuerFound = true;
                if (verifies(current, candidate)) {
                    signatureOk = true;
                    issuer = candidate;
                    break;
                }
            }
            if (!issuerFound) {
                throw new HandshakeVerificationException(FailureReason.CHAIN_INCOMPLETE,
                        "issuer not found for certificate (subject="
                                + current.getSubjectX500Principal() + ", issuer="
                                + current.getIssuerX500Principal()
                                + "); the peer likely omitted an intermediate certificate");
            }
            if (!signatureOk) {
                throw new HandshakeVerificationException(FailureReason.SIGNATURE_INVALID,
                        "signature verification failed for certificate (subject="
                                + current.getSubjectX500Principal() + ")");
            }
            path.add(issuer);
            current = issuer;
        }
    }

    private static boolean isIssuedBy(X509Certificate cert, X509Certificate issuer) {
        if (!cert.getIssuerX500Principal().equals(issuer.getSubjectX500Principal())) {
            return false;
        }
        return verifies(cert, issuer);
    }

    private static boolean verifies(X509Certificate cert, X509Certificate issuer) {
        try {
            cert.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static void checkValidity(List<X509Certificate> path)
            throws HandshakeVerificationException {
        for (X509Certificate cert : path) {
            try {
                cert.checkValidity();
            } catch (CertificateExpiredException e) {
                throw new HandshakeVerificationException(FailureReason.CERT_EXPIRED,
                        "certificate expired (subject=" + cert.getSubjectX500Principal()
                                + ", notAfter=" + cert.getNotAfter() + ")", e);
            } catch (CertificateNotYetValidException e) {
                throw new HandshakeVerificationException(FailureReason.CERT_NOT_YET_VALID,
                        "certificate not yet valid (subject=" + cert.getSubjectX500Principal()
                                + ", notBefore=" + cert.getNotBefore() + ")", e);
            }
        }
    }

    private static void checkBasicConstraints(List<X509Certificate> path)
            throws HandshakeVerificationException {
        // Every certificate above the leaf must be a CA.
        for (int i = 1; i < path.size(); i++) {
            X509Certificate ca = path.get(i);
            if (ca.getBasicConstraints() < 0) {
                throw new HandshakeVerificationException(FailureReason.BASIC_CONSTRAINTS_VIOLATION,
                        "issuer certificate is not a CA (subject="
                                + ca.getSubjectX500Principal() + ")");
            }
        }
    }

    private static void checkKeyUsage(List<X509Certificate> path)
            throws HandshakeVerificationException {
        X509Certificate leaf = path.get(0);
        boolean[] leafKu = leaf.getKeyUsage();
        if (leafKu != null && (leafKu.length <= KU_DIGITAL_SIGNATURE || !leafKu[KU_DIGITAL_SIGNATURE])) {
            throw new HandshakeVerificationException(FailureReason.KEY_USAGE_MISMATCH,
                    "end-entity certificate keyUsage does not allow digitalSignature"
                            + " (subject=" + leaf.getSubjectX500Principal() + ")");
        }
        for (int i = 1; i < path.size(); i++) {
            X509Certificate ca = path.get(i);
            boolean[] ku = ca.getKeyUsage();
            if (ku != null && (ku.length <= KU_KEY_CERT_SIGN || !ku[KU_KEY_CERT_SIGN])) {
                throw new HandshakeVerificationException(FailureReason.KEY_USAGE_MISMATCH,
                        "CA certificate keyUsage does not allow keyCertSign (subject="
                                + ca.getSubjectX500Principal() + ")");
            }
        }
    }

    private void checkExtendedKeyUsage(X509Certificate leaf)
            throws HandshakeVerificationException {
        List<String> eku;
        try {
            eku = leaf.getExtendedKeyUsage();
        } catch (Exception e) {
            throw new HandshakeVerificationException(FailureReason.EXTENDED_KEY_USAGE_MISMATCH,
                    "unparseable extendedKeyUsage extension (subject="
                            + leaf.getSubjectX500Principal() + ")", e);
        }
        if (eku == null) {
            // RFC 5280: absent EKU means no restriction.
            return;
        }
        String required = localRole == PeerRole.SERVER ? EKU_CLIENT_AUTH : EKU_SERVER_AUTH;
        String requiredName = localRole == PeerRole.SERVER ? "clientAuth" : "serverAuth";
        if (!eku.contains(required)) {
            throw new HandshakeVerificationException(FailureReason.EXTENDED_KEY_USAGE_MISMATCH,
                    "certificate extendedKeyUsage " + eku + " does not include " + requiredName
                            + " required for this role (subject="
                            + leaf.getSubjectX500Principal() + ")");
        }
    }

    private void checkPins(X509Certificate leaf, String peerName)
            throws HandshakeVerificationException {
        if (peerName == null) {
            return;
        }
        Set<String> pins = policy.pinsFor(peerName);
        if (pins.isEmpty()) {
            return;
        }
        String actual = Fingerprints.sha256OfPublicKey(leaf);
        if (!pins.contains(actual)) {
            // Deliberately do not include the certificate or its fingerprint in
            // the message: the failure must not leak peer certificate contents.
            throw new HandshakeVerificationException(FailureReason.PIN_MISMATCH,
                    "public key of peer '" + peerName + "' does not match any of the "
                            + pins.size() + " configured pin(s)");
        }
    }

    private void checkRevocation(List<X509Certificate> path)
            throws HandshakeVerificationException {
        RevocationSource source = policy.getRevocationSource();
        if (source == null) {
            return;
        }
        // Check leaf and intermediates; the trust anchor is trusted by configuration.
        for (X509Certificate cert : path) {
            if (policy.getTrustAnchors().contains(cert)) {
                continue;
            }
            boolean revoked;
            try {
                revoked = source.isRevoked(cert);
            } catch (RevocationUnavailableException e) {
                if (policy.getRevocationPolicy() == RevocationPolicy.FAIL_CLOSED) {
                    throw new HandshakeVerificationException(
                            FailureReason.REVOCATION_STATUS_UNAVAILABLE,
                            "revocation status unavailable and policy is FAIL_CLOSED"
                                    + " (subject=" + cert.getSubjectX500Principal() + ")", e);
                }
                LOG.warning("revocation status unavailable, allowing per FAIL_OPEN policy: "
                        + e.getMessage());
                return;
            }
            if (revoked) {
                throw new HandshakeVerificationException(FailureReason.CERT_REVOKED,
                        "certificate is revoked (subject=" + cert.getSubjectX500Principal()
                                + ", serial=" + cert.getSerialNumber().toString(16) + ")");
            }
        }
    }
}
