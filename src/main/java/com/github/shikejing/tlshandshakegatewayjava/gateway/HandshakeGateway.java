package com.github.shikejing.tlshandshakegatewayjava.gateway;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Loopback mutual-TLS gateway. Accepts inbound connections on 127.0.0.1 and
 * creates outbound connections, enforcing mutual certificate authentication.
 *
 * <p>After every handshake — including resumed sessions, where the trust
 * manager is not invoked — the peer chain is re-verified against the policy
 * snapshot effective at that moment, so resumed sessions can never bypass
 * updated pins, trust anchors or revocation settings.</p>
 *
 * <p>Thread-safe: the policy is read through {@link PolicyManager} snapshots,
 * client SSLContexts are cached in a concurrent map (preserving session
 * resumption), and each connection is handled on its own executor task.</p>
 */
public final class HandshakeGateway implements Closeable {

    private static final Logger LOG = Logger.getLogger(HandshakeGateway.class.getName());
    private static final String TLS_VERSION = "TLSv1.3";

    private final PolicyManager policyManager;
    private final Map<ClientKey, SSLContext> clientContexts = new ConcurrentHashMap<>();
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    private final ExecutorService connectionPool = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "handshake-gateway-conn");
        t.setDaemon(true);
        return t;
    });

    public HandshakeGateway(PolicyManager policyManager) {
        this.policyManager = Objects.requireNonNull(policyManager);
    }

    /**
     * Start a mutual-TLS listener on 127.0.0.1 with an ephemeral port.
     *
     * @param identity local server identity
     * @param peerName logical name used to look up pins for inbound clients
     *                 (may be null to disable pin checking for this listener)
     * @param handler  invoked for each verified connection
     * @return the bound port
     */
    public int listen(Identity identity, String peerName, ConnectionHandler handler)
            throws IOException {
        SSLContext context = newContext(identity, peerName);
        SSLServerSocket serverSocket;
        try {
            serverSocket = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(
                    0, 50, InetAddress.getLoopbackAddress());
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("cannot create server socket", e);
        }
        serverSocket.setNeedClientAuth(true);
        Listener listener = new Listener(serverSocket, peerName, handler);
        listeners.add(listener);
        Thread acceptThread = new Thread(listener, "handshake-gateway-accept-" + serverSocket.getLocalPort());
        acceptThread.setDaemon(true);
        listener.thread = acceptThread;
        acceptThread.start();
        return serverSocket.getLocalPort();
    }

    /**
     * Open a mutual-TLS connection to a local listener and verify the server
     * against the current policy (including pins for {@code peerName}).
     */
    public SSLSocket connect(Identity identity, String peerName, int port) throws IOException {
        SSLContext context = clientContexts.computeIfAbsent(
                new ClientKey(identity, peerName), k -> newContext(k.identity(), k.peerName()));
        SSLSocket socket;
        try {
            socket = (SSLSocket) context.getSocketFactory().createSocket();
            socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 10_000);
        } catch (IOException e) {
            throw e;
        }
        socket.startHandshake();
        // Re-verify after the handshake so resumed sessions are checked against
        // the policy in effect now, not the one from when the session was created.
        verifyPeer(socket, PeerRole.CLIENT, peerName);
        return socket;
    }

    private SSLContext newContext(Identity identity, String peerName) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(null, null);
            ks.setKeyEntry("identity", identity.key(), new char[0],
                    identity.chain().toArray(new X509Certificate[0]));
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, new char[0]);
            SSLContext context = SSLContext.getInstance(TLS_VERSION);
            context.init(kmf.getKeyManagers(),
                    new javax.net.ssl.TrustManager[]{new GatewayTrustManager(policyManager, peerName)},
                    null);
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("cannot build SSLContext", e);
        }
    }

    private void verifyPeer(SSLSocket socket, PeerRole localRole, String peerName)
            throws SSLHandshakeException {
        final X509Certificate[] chain;
        try {
            java.security.cert.Certificate[] raw = socket.getSession().getPeerCertificates();
            chain = new X509Certificate[raw.length];
            for (int i = 0; i < raw.length; i++) {
                chain[i] = (X509Certificate) raw[i];
            }
        } catch (Exception e) {
            throw fail(new HandshakeVerificationException(
                    FailureReason.NO_PEER_CERTIFICATE, "peer presented no certificates", e));
        }
        try {
            new PeerVerifier(policyManager.current(), localRole).verify(chain, peerName);
        } catch (HandshakeVerificationException e) {
            SSLHandshakeException ssl = fail(e);
            try {
                socket.close();
            } catch (IOException ignored) {
                // already failing
            }
            throw ssl;
        }
    }

    private static SSLHandshakeException fail(HandshakeVerificationException e) {
        SSLHandshakeException ssl = new SSLHandshakeException(
                "peer verification failed [" + e.getReason() + "]: " + e.getMessage());
        ssl.initCause(e);
        return ssl;
    }

    @Override
    public void close() {
        for (Listener listener : listeners) {
            listener.stop();
        }
        listeners.clear();
        connectionPool.shutdownNow();
    }

    private record ClientKey(Identity identity, String peerName) {
    }

    private final class Listener implements Runnable {
        private final SSLServerSocket serverSocket;
        private final String peerName;
        private final ConnectionHandler handler;
        private volatile boolean running = true;
        private Thread thread;

        private Listener(SSLServerSocket serverSocket, String peerName, ConnectionHandler handler) {
            this.serverSocket = serverSocket;
            this.peerName = peerName;
            this.handler = handler;
        }

        @Override
        public void run() {
            while (running) {
                final SSLSocket socket;
                try {
                    socket = (SSLSocket) serverSocket.accept();
                } catch (IOException e) {
                    if (running) {
                        LOG.log(Level.WARNING, "accept failed", e);
                    }
                    return;
                }
                connectionPool.submit(() -> serve(socket));
            }
        }

        private void serve(SSLSocket socket) {
            try (socket) {
                socket.startHandshake();
                // Covers resumed sessions: trust manager is skipped on
                // abbreviated handshakes, so re-verify against current policy.
                verifyPeer(socket, PeerRole.SERVER, peerName);
                handler.handle(socket, peerChain(socket));
            } catch (Exception e) {
                LOG.log(Level.FINE, "connection rejected: " + e.getMessage(), e);
            }
        }

        private X509Certificate[] peerChain(SSLSocket socket) throws Exception {
            java.security.cert.Certificate[] raw = socket.getSession().getPeerCertificates();
            X509Certificate[] chain = new X509Certificate[raw.length];
            for (int i = 0; i < raw.length; i++) {
                chain[i] = (X509Certificate) raw[i];
            }
            return chain;
        }

        private void stop() {
            running = false;
            try {
                serverSocket.close();
            } catch (IOException ignored) {
                // shutting down
            }
        }
    }
}
