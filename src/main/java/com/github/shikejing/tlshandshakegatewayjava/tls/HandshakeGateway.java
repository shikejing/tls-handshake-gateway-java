package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 基于本地回环的安全握手通道服务端：
 * 对每个入站连接执行双向证书校验（链信任、有效期、用途、公钥固定、吊销状态），
 * 校验通过后提供简单回显服务。
 *
 * <p>并发模型：每个连接一个工作线程；每次握手开始时取一次策略快照并绑定到
 * 该线程，整次握手（含复用会话的复核）使用同一快照，互不污染。
 */
public class HandshakeGateway {

    private static final Logger log = LoggerFactory.getLogger(HandshakeGateway.class);
    private static final char[] KEYSTORE_PASSWORD = "handshake-internal".toCharArray();

    private final PolicyManager policyManager;
    private final int requestedPort;
    private final ExecutorService workers;
    private final AtomicBoolean running = new AtomicBoolean();
    private final KeyManager[] keyManagers;

    private volatile SSLServerSocket serverSocket;
    private volatile SSLContext sslContext;
    private volatile PolicySnapshot contextSnapshot;
    private Thread acceptorThread;

    public HandshakeGateway(PolicyManager policyManager, int port) {
        this(policyManager, port, null);
    }

    public HandshakeGateway(PolicyManager policyManager, int port, KeyManager[] keyManagers) {
        this.policyManager = policyManager;
        this.requestedPort = port;
        this.keyManagers = keyManagers;
        this.workers = Executors.newCachedThreadPool(r -> {
            Thread t = new Thread(r, "hs-gateway-worker");
            t.setDaemon(true);
            return t;
        });
    }

    public void start() throws Exception {
        if (!running.compareAndSet(false, true)) {
            return;
        }
        contextSnapshot = policyManager.current();
        sslContext = buildContext(contextSnapshot, keyManagers);
        policyManager.addReloadListener(this::refreshContextIfIdentityChanged);

        SSLServerSocket socket = (SSLServerSocket) sslContext.getServerSocketFactory()
                .createServerSocket(requestedPort);
        socket.setNeedClientAuth(true);
        socket.setEnabledProtocols(new String[]{"TLSv1.2"});
        socket.setReuseAddress(true);
        this.serverSocket = socket;

        acceptorThread = new Thread(this::acceptLoop, "hs-gateway-acceptor");
        acceptorThread.setDaemon(true);
        acceptorThread.start();
        log.info("握手通道服务端已启动，监听 127.0.0.1:{}", getPort());
    }

    /** 仅在本端身份（密钥/证书）变化时重建 SSLContext，避免会话缓存被清空。 */
    private void refreshContextIfIdentityChanged() {
        PolicySnapshot now = policyManager.current();
        if (!identityEquals(now, contextSnapshot)) {
            contextSnapshot = now;
            sslContext = buildContext(now, keyManagers);
        }
    }

    private static boolean identityEquals(PolicySnapshot a, PolicySnapshot b) {
        if (a == null || b == null) {
            return a == b;
        }
        return java.util.Objects.equals(a.identityKey(), b.identityKey())
                && java.util.Objects.equals(a.identityChain(), b.identityChain());
    }

    private void acceptLoop() {
        while (running.get()) {
            try {
                SSLSocket socket = (SSLSocket) serverSocket.accept();
                workers.submit(() -> handleConnection(socket));
            } catch (SocketException e) {
                if (running.get()) {
                    log.warn("accept 异常: {}", e.toString());
                }
            } catch (IOException e) {
                if (running.get()) {
                    log.warn("accept 异常: {}", e.toString());
                }
            }
        }
    }

    private void handleConnection(SSLSocket socket) {
        PolicySnapshot snapshot = policyManager.current();
        ValidatingTrustManager.CURRENT.set(snapshot);
        try {
            socket.setSoTimeout(30_000);
            socket.startHandshake();

            // 1. 取 TrustManager 记录的校验失败
            CertificateValidationException failure = ValidatingTrustManager.takeRecordedFailure();
            // 2. 复用会话不会触发 TrustManager，这里按当前快照复核
            if (failure == null) {
                failure = postValidate(socket, snapshot);
            }
            if (failure != null) {
                log.info("连接被拒绝: {}", failure.getMessage());
                sendResult(socket, "REJECT:" + failure.getReason());
                return;
            }

            // 3. 校验通过，发送 OK 并等待对端结果
            sendResult(socket, "OK");
            String peerResult = readLine(socket);
            if (peerResult == null || peerResult.startsWith("REJECT")) {
                log.info("对端拒绝连接: {}", peerResult);
                return;
            }
            echoLoop(socket);
        } catch (IOException e) {
            log.debug("连接 IO 异常: {}", e.toString());
        } finally {
            ValidatingTrustManager.CURRENT.remove();
            ValidatingTrustManager.clearRecordedFailure();
            try {
                socket.close();
            } catch (IOException ignored) {
            }
        }
    }

    private void sendResult(SSLSocket socket, String result) throws IOException {
        java.io.OutputStream out = socket.getOutputStream();
        out.write((result + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8));
        out.flush();
    }

    private String readLine(SSLSocket socket) throws IOException {
        java.io.BufferedReader in = new java.io.BufferedReader(
                new java.io.InputStreamReader(socket.getInputStream(), java.nio.charset.StandardCharsets.UTF_8));
        return in.readLine();
    }

    private CertificateValidationException postValidate(SSLSocket socket, PolicySnapshot snapshot) {
        try {
            X509Certificate[] peer = (X509Certificate[]) socket.getSession().getPeerCertificates();
            new CertificateValidator().validate(peer, snapshot.role(), snapshot);
            return null;
        } catch (CertificateValidationException e) {
            return e;
        } catch (Exception e) {
            return new CertificateValidationException(FailureReason.VALIDATION_ERROR,
                    "读取对端会话证书失败: " + e, e);
        }
    }

    private void echoLoop(SSLSocket socket) throws IOException {
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        PrintWriter out = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
        String line;
        while ((line = in.readLine()) != null) {
            out.println("echo:" + line);
        }
    }

    static SSLContext buildContext(PolicySnapshot snapshot, KeyManager[] customKeyManagers) {
        try {
            SSLContext context = SSLContext.getInstance("TLS");
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            PrivateKey key = snapshot.identityKey();
            List<X509Certificate> chain = snapshot.identityChain();
            if (key != null && !chain.isEmpty()) {
                keyStore.setKeyEntry("identity", key, KEYSTORE_PASSWORD,
                        chain.toArray(new X509Certificate[0]));
            }
            KeyManager[] keyManagers = customKeyManagers;
            if (keyManagers == null) {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, KEYSTORE_PASSWORD);
                keyManagers = kmf.getKeyManagers();
            }
            TrustManager[] trustManagers = new TrustManager[]{new ValidatingTrustManager()};
            context.init(keyManagers, trustManagers, null);
            if (!snapshot.sessionResumptionEnabled()) {
                context.getClientSessionContext().setSessionCacheSize(0);
                context.getServerSessionContext().setSessionCacheSize(0);
            }
            return context;
        } catch (Exception e) {
            throw new IllegalStateException("构建 SSLContext 失败", e);
        }
    }

    public void stop() {
        if (!running.compareAndSet(true, false)) {
            return;
        }
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException ignored) {
        }
        workers.shutdownNow();
        log.info("握手通道服务端已停止");
    }

    public int getPort() {
        SSLSocket s = null;
        if (serverSocket == null) {
            return -1;
        }
        return serverSocket.getLocalPort();
    }
}
