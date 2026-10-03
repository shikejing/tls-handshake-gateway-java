package com.github.shikejing.tlshandshakegatewayjava.gateway;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HandshakeGatewayTest {

    private static TestPki.Ca root;
    private static TestPki.Ca intermediate;
    private static TestPki.Leaf serverLeaf;
    private static TestPki.Leaf clientLeaf;
    private static Identity serverIdentity;
    private static Identity clientIdentity;

    private HandshakeGateway gateway;

    @BeforeAll
    static void pki() {
        root = TestPki.selfSignedCa("gw-root");
        intermediate = TestPki.intermediateCa("gw-intermediate", root);
        serverLeaf = TestPki.leaf("gw-server", intermediate, KeyPurposeId.id_kp_serverAuth);
        clientLeaf = TestPki.leaf("gw-client", intermediate, KeyPurposeId.id_kp_clientAuth);
        serverIdentity = serverLeaf.identityWith(List.of(intermediate.cert));
        clientIdentity = clientLeaf.identityWith(List.of(intermediate.cert));
    }

    @AfterEach
    void tearDown() {
        if (gateway != null) {
            gateway.close();
        }
    }

    private static SecurityPolicy.Builder basePolicy() {
        return SecurityPolicy.builder()
                .trustAnchors(Set.of(root.cert))
                .intermediates(Set.of(intermediate.cert));
    }

    private HandshakeGateway newGateway(SecurityPolicy policy) {
        gateway = new HandshakeGateway(new PolicyManager(policy));
        return gateway;
    }

    private static ConnectionHandler countingHandler(AtomicInteger counter, CountDownLatch latch) {
        return (socket, chain) -> {
            counter.incrementAndGet();
            if (latch != null) {
                latch.countDown();
            }
        };
    }

    @Test
    void mutualHandshakeSucceedsOverLoopback() throws Exception {
        AtomicInteger accepted = new AtomicInteger();
        CountDownLatch latch = new CountDownLatch(1);
        newGateway(basePolicy().build());
        int port = gateway.listen(serverIdentity, null, countingHandler(accepted, latch));

        try (SSLSocket socket = gateway.connect(clientIdentity, null, port)) {
            assertTrue(socket.getSession().isValid());
        }
        assertTrue(latch.await(10, TimeUnit.SECONDS), "server handler not invoked");
        assertEquals(1, accepted.get());
    }

    /**
     * Assert that a connection attempt is rejected. In TLS 1.3 a server-side
     * rejection of the client certificate surfaces only after the client
     * handshake returns, so we also force I/O to observe the alert.
     */
    private void assertRejected(ConnectionAttempt attempt) {
        assertThrows(IOException.class, () -> {
            try (SSLSocket socket = attempt.connect()) {
                socket.setSoTimeout(10_000);
                socket.getOutputStream().write(0);
                socket.getOutputStream().flush();
                socket.getInputStream().read();
            }
        });
    }

    @FunctionalInterface
    private interface ConnectionAttempt {
        SSLSocket connect() throws IOException;
    }

    @Test
    void serverOnlyCertificateIsRejectedAsClient() throws Exception {
        // Client presents a serverAuth-only certificate: must fail client auth.
        newGateway(basePolicy().build());
        int port = gateway.listen(serverIdentity, null, (s, c) -> { });
        Identity badClient = serverLeaf.identityWith(List.of(intermediate.cert));
        assertRejected(() -> gateway.connect(badClient, null, port));
    }

    @Test
    void untrustedClientIsRejected() throws Exception {
        TestPki.Ca otherRoot = TestPki.selfSignedCa("other-root");
        TestPki.Leaf foreign = TestPki.leaf("foreign", otherRoot, KeyPurposeId.id_kp_clientAuth);
        newGateway(basePolicy().build());
        int port = gateway.listen(serverIdentity, null, (s, c) -> { });
        Identity foreignIdentity = foreign.identityWith(List.of(otherRoot.cert));
        assertRejected(() -> gateway.connect(foreignIdentity, null, port));
    }

    @Test
    void pinMismatchIsRejected() throws Exception {
        newGateway(basePolicy()
                .pinsByPeer(Map.of("server", Set.of("00".repeat(32))))
                .build());
        int port = gateway.listen(serverIdentity, null, (s, c) -> { });
        assertThrows(SSLHandshakeException.class,
                () -> gateway.connect(clientIdentity, "server", port));
    }

    @Test
    void matchingPinAmongRotationSetIsAccepted() throws Exception {
        String pin = Fingerprints.sha256OfPublicKey(serverLeaf.cert);
        newGateway(basePolicy()
                .pinsByPeer(Map.of("server", Set.of("11".repeat(32), pin)))
                .build());
        AtomicInteger accepted = new AtomicInteger();
        CountDownLatch latch = new CountDownLatch(1);
        int port = gateway.listen(serverIdentity, null, countingHandler(accepted, latch));
        try (SSLSocket socket = gateway.connect(clientIdentity, "server", port)) {
            assertTrue(socket.getSession().isValid());
        }
        assertTrue(latch.await(10, TimeUnit.SECONDS));
    }

    @Test
    void revokedClientCertificateIsRejected() throws Exception {
        Path revocationFile = Files.createTempFile("revoked", ".txt");
        Files.writeString(revocationFile,
                "# revoked serials\n" + clientLeaf.serial.toString(16) + "\n");
        newGateway(basePolicy()
                .revocationSource(new FileRevocationSource(revocationFile))
                .build());
        int port = gateway.listen(serverIdentity, null, (s, c) -> { });
        assertRejected(() -> gateway.connect(clientIdentity, null, port));
    }

    @Test
    void resumedSessionMustSatisfyUpdatedPins() throws Exception {
        String goodPin = Fingerprints.sha256OfPublicKey(serverLeaf.cert);
        PolicyManager manager = new PolicyManager(basePolicy()
                .pinsByPeer(Map.of("server", Set.of(goodPin)))
                .build());
        gateway = new HandshakeGateway(manager);
        int port = gateway.listen(serverIdentity, null, (s, c) -> { });

        // First connection establishes a session (and a resumable ticket).
        try (SSLSocket first = gateway.connect(clientIdentity, "server", port)) {
            assertTrue(first.getSession().isValid());
        }

        // Tighten the pins: the old session must not bypass the new policy.
        manager.update(basePolicy()
                .pinsByPeer(Map.of("server", Set.of("00".repeat(32))))
                .build());
        assertThrows(SSLHandshakeException.class,
                () -> gateway.connect(clientIdentity, "server", port));

        // Restore the original pins: connections work again.
        manager.update(basePolicy()
                .pinsByPeer(Map.of("server", Set.of(goodPin)))
                .build());
        try (SSLSocket third = gateway.connect(clientIdentity, "server", port)) {
            assertTrue(third.getSession().isValid());
        }
    }

    @Test
    void trustUpdateAppliesAtomicallyToNewConnections() throws Exception {
        PolicyManager manager = new PolicyManager(basePolicy().build());
        gateway = new HandshakeGateway(manager);
        AtomicInteger accepted = new AtomicInteger();
        int port = gateway.listen(serverIdentity, null, countingHandler(accepted, null));

        try (SSLSocket socket = gateway.connect(clientIdentity, null, port)) {
            assertTrue(socket.getSession().isValid());
        }

        // Rotate the trust anchor: the old chain must stop being accepted,
        // the new chain must be accepted, with no intermediate state.
        TestPki.Ca newRoot = TestPki.selfSignedCa("new-root");
        TestPki.Leaf newClient = TestPki.leaf("new-client", newRoot, KeyPurposeId.id_kp_clientAuth);
        TestPki.Leaf newServer = TestPki.leaf("new-server", newRoot, KeyPurposeId.id_kp_serverAuth);
        Identity newClientIdentity = newClient.identityWith(List.of());
        Identity newServerIdentity = newServer.identityWith(List.of());
        manager.update(SecurityPolicy.builder()
                .trustAnchors(Set.of(newRoot.cert))
                .build());

        // Server still presents the old chain -> client must reject it now.
        assertThrows(SSLHandshakeException.class,
                () -> gateway.connect(clientIdentity, null, port));

        // New listener under the new trust domain works.
        int newPort = gateway.listen(newServerIdentity, null, countingHandler(accepted, null));
        try (SSLSocket socket = gateway.connect(newClientIdentity, null, newPort)) {
            assertTrue(socket.getSession().isValid());
        }
    }

    @Test
    void concurrentHandshakesWithConcurrentPolicyUpdates() throws Exception {
        String pin = Fingerprints.sha256OfPublicKey(serverLeaf.cert);
        PolicyManager manager = new PolicyManager(basePolicy()
                .pinsByPeer(Map.of("server", Set.of(pin)))
                .build());
        gateway = new HandshakeGateway(manager);
        AtomicInteger accepted = new AtomicInteger();
        int port = gateway.listen(serverIdentity, null, countingHandler(accepted, null));

        int threads = 8;
        int iterations = 25;
        ExecutorService pool = Executors.newFixedThreadPool(threads + 1);
        ConcurrentLinkedQueue<Throwable> errors = new ConcurrentLinkedQueue<>();
        CountDownLatch start = new CountDownLatch(1);

        // One thread keeps flipping the policy between two equivalent variants.
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < iterations * 4; i++) {
                    Set<String> pins = i % 2 == 0
                            ? Set.of(pin)
                            : Set.of("11".repeat(32), pin);
                    manager.update(basePolicy().pinsByPeer(Map.of("server", pins)).build());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        });

        List<java.util.concurrent.Future<?>> futures = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < iterations; i++) {
                        try (SSLSocket socket = gateway.connect(clientIdentity, "server", port)) {
                            assertTrue(socket.getSession().isValid());
                        }
                    }
                } catch (Throwable e) {
                    errors.add(e);
                }
            }));
        }
        start.countDown();
        for (java.util.concurrent.Future<?> f : futures) {
            f.get(120, TimeUnit.SECONDS);
        }
        pool.shutdownNow();
        assertTrue(errors.isEmpty(), "concurrent errors: " + errors);
        // Give the server a moment to drain accepted connections.
        long deadline = System.currentTimeMillis() + 10_000;
        while (accepted.get() < threads * iterations && System.currentTimeMillis() < deadline) {
            Thread.sleep(50);
        }
        assertEquals(threads * iterations, accepted.get());
    }
}
