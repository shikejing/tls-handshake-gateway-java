package com.github.shikejing.tlshandshakegatewayjava.gateway;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PeerVerifierTest {

    private static TestPki.Ca root;
    private static TestPki.Ca intermediate;
    private static TestPki.Leaf serverLeaf;
    private static TestPki.Leaf clientLeaf;

    @BeforeAll
    static void pki() {
        root = TestPki.selfSignedCa("test-root");
        intermediate = TestPki.intermediateCa("test-intermediate", root);
        serverLeaf = TestPki.leaf("server", intermediate, KeyPurposeId.id_kp_serverAuth);
        clientLeaf = TestPki.leaf("client", intermediate, KeyPurposeId.id_kp_clientAuth);
    }

    private static SecurityPolicy.Builder basePolicy() {
        return SecurityPolicy.builder()
                .trustAnchors(Set.of(root.cert))
                .intermediates(Set.of(intermediate.cert));
    }

    private static X509Certificate[] chain(TestPki.Leaf leaf, boolean withIntermediate) {
        return withIntermediate
                ? new X509Certificate[]{leaf.cert, intermediate.cert}
                : new X509Certificate[]{leaf.cert};
    }

    private static HandshakeVerificationException expectFailure(FailureReason reason,
                                                                SecurityPolicy policy,
                                                                PeerRole role,
                                                                X509Certificate[] chain,
                                                                String peerName) {
        HandshakeVerificationException e = assertThrows(HandshakeVerificationException.class,
                () -> new PeerVerifier(policy, role).verify(chain, peerName));
        assertEquals(reason, e.getReason(), "unexpected failure reason: " + e.getMessage());
        return e;
    }

    @Test
    void validChainPassesBothRoles() {
        SecurityPolicy policy = basePolicy().build();
        assertDoesNotThrow(() -> new PeerVerifier(policy, PeerRole.CLIENT)
                .verify(chain(serverLeaf, true), null));
        assertDoesNotThrow(() -> new PeerVerifier(policy, PeerRole.SERVER)
                .verify(chain(clientLeaf, true), null));
    }

    @Test
    void missingIntermediateIsRejected() {
        // Peer presents only the leaf; no intermediates configured either.
        SecurityPolicy policy = SecurityPolicy.builder()
                .trustAnchors(Set.of(root.cert))
                .build();
        expectFailure(FailureReason.CHAIN_INCOMPLETE, policy, PeerRole.CLIENT,
                chain(serverLeaf, false), null);
    }

    @Test
    void badSignatureIsRejected() {
        TestPki.Ca impostor = TestPki.selfSignedCa("impostor");
        TestPki.Leaf forged = TestPki.leafWithBadSignature(
                "forged", intermediate, impostor.key, KeyPurposeId.id_kp_serverAuth);
        SecurityPolicy policy = basePolicy().build();
        expectFailure(FailureReason.SIGNATURE_INVALID, policy, PeerRole.CLIENT,
                chain(forged, true), null);
    }

    @Test
    void untrustedRootIsRejected() {
        TestPki.Ca otherRoot = TestPki.selfSignedCa("other-root");
        TestPki.Leaf foreign = TestPki.leaf("foreign", otherRoot, KeyPurposeId.id_kp_serverAuth);
        SecurityPolicy policy = basePolicy().build();
        // Peer presents its full chain; the chain ends at a root we do not trust.
        expectFailure(FailureReason.UNTRUSTED_ROOT, policy, PeerRole.CLIENT,
                new X509Certificate[]{foreign.cert, otherRoot.cert}, null);
    }

    @Test
    void expiredCertificateIsRejected() {
        TestPki.Leaf expired = TestPki.leaf("expired", intermediate, KeyPurposeId.id_kp_serverAuth,
                Instant.now().minus(10, ChronoUnit.DAYS), Instant.now().minus(1, ChronoUnit.DAYS),
                KeyUsage.digitalSignature, new java.math.BigInteger("111"));
        expectFailure(FailureReason.CERT_EXPIRED, basePolicy().build(), PeerRole.CLIENT,
                chain(expired, true), null);
    }

    @Test
    void notYetValidCertificateIsRejected() {
        TestPki.Leaf future = TestPki.leaf("future", intermediate, KeyPurposeId.id_kp_serverAuth,
                Instant.now().plus(1, ChronoUnit.DAYS), Instant.now().plus(10, ChronoUnit.DAYS),
                KeyUsage.digitalSignature, new java.math.BigInteger("112"));
        expectFailure(FailureReason.CERT_NOT_YET_VALID, basePolicy().build(), PeerRole.CLIENT,
                chain(future, true), null);
    }

    @Test
    void serverCertificateCannotAuthenticateAsClient() {
        // serverLeaf has only serverAuth; used where clientAuth is required.
        expectFailure(FailureReason.EXTENDED_KEY_USAGE_MISMATCH, basePolicy().build(),
                PeerRole.SERVER, chain(serverLeaf, true), null);
    }

    @Test
    void clientCertificateCannotAuthenticateAsServer() {
        expectFailure(FailureReason.EXTENDED_KEY_USAGE_MISMATCH, basePolicy().build(),
                PeerRole.CLIENT, chain(clientLeaf, true), null);
    }

    @Test
    void leafWithoutDigitalSignatureKeyUsageIsRejected() {
        TestPki.Leaf noSig = TestPki.leaf("nosig", intermediate, KeyPurposeId.id_kp_serverAuth,
                Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.DAYS),
                KeyUsage.keyEncipherment, new java.math.BigInteger("113"));
        expectFailure(FailureReason.KEY_USAGE_MISMATCH, basePolicy().build(), PeerRole.CLIENT,
                chain(noSig, true), null);
    }

    @Test
    void nonCaIssuerIsRejected() {
        // Issue a leaf from another leaf (which is not a CA).
        TestPki.Ca fakeCa = new TestPki.Ca(serverLeaf.cert,
                new java.security.KeyPair(serverLeaf.cert.getPublicKey(), serverLeaf.key));
        TestPki.Leaf subLeaf = TestPki.leaf("subleaf", fakeCa, KeyPurposeId.id_kp_serverAuth);
        SecurityPolicy policy = basePolicy().build();
        expectFailure(FailureReason.BASIC_CONSTRAINTS_VIOLATION, policy, PeerRole.CLIENT,
                new X509Certificate[]{subLeaf.cert, serverLeaf.cert, intermediate.cert}, null);
    }

    @Test
    void matchingPinPasses() {
        String pin = Fingerprints.sha256OfPublicKey(serverLeaf.cert);
        SecurityPolicy policy = basePolicy()
                .pinsByPeer(Map.of("server", Set.of(pin)))
                .build();
        assertDoesNotThrow(() -> new PeerVerifier(policy, PeerRole.CLIENT)
                .verify(chain(serverLeaf, true), "server"));
    }

    @Test
    void multiplePinsAllowRotation() {
        String pin = Fingerprints.sha256OfPublicKey(serverLeaf.cert);
        SecurityPolicy policy = basePolicy()
                .pinsByPeer(Map.of("server", Set.of("deadbeef", pin, "cafe")))
                .build();
        assertDoesNotThrow(() -> new PeerVerifier(policy, PeerRole.CLIENT)
                .verify(chain(serverLeaf, true), "server"));
    }

    @Test
    void mismatchedPinIsRejectedWithoutLeakingCertificate() {
        SecurityPolicy policy = basePolicy()
                .pinsByPeer(Map.of("server", Set.of("00".repeat(32))))
                .build();
        HandshakeVerificationException e = expectFailure(FailureReason.PIN_MISMATCH, policy,
                PeerRole.CLIENT, chain(serverLeaf, true), "server");
        String actualPin = Fingerprints.sha256OfPublicKey(serverLeaf.cert);
        assertTrue(!e.getMessage().contains(actualPin),
                "failure message must not leak the peer fingerprint");
        assertTrue(!e.getMessage().contains(serverLeaf.cert.getSubjectX500Principal().getName()),
                "failure message must not leak the peer certificate subject");
    }

    @Test
    void revokedCertificateIsRejected() {
        RevocationSource source = cert -> cert.getSerialNumber().equals(serverLeaf.cert.getSerialNumber());
        SecurityPolicy policy = basePolicy().revocationSource(source).build();
        expectFailure(FailureReason.CERT_REVOKED, policy, PeerRole.CLIENT,
                chain(serverLeaf, true), null);
    }

    @Test
    void unavailableRevocationSourceFailsClosedByDefault() {
        RevocationSource down = cert -> {
            throw new RevocationUnavailableException("source down");
        };
        SecurityPolicy policy = basePolicy().revocationSource(down).build();
        expectFailure(FailureReason.REVOCATION_STATUS_UNAVAILABLE, policy, PeerRole.CLIENT,
                chain(serverLeaf, true), null);
    }

    @Test
    void unavailableRevocationSourceFailsOpenWhenConfigured() {
        RevocationSource down = cert -> {
            throw new RevocationUnavailableException("source down");
        };
        SecurityPolicy policy = basePolicy()
                .revocationSource(down)
                .revocationPolicy(RevocationPolicy.FAIL_OPEN)
                .build();
        assertDoesNotThrow(() -> new PeerVerifier(policy, PeerRole.CLIENT)
                .verify(chain(serverLeaf, true), null));
    }

    @Test
    void emptyChainIsRejected() {
        expectFailure(FailureReason.NO_PEER_CERTIFICATE, basePolicy().build(),
                PeerRole.CLIENT, new X509Certificate[0], null);
    }
}
