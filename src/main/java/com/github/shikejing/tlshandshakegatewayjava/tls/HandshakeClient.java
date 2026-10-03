package com.github.shikejing.tlshandshakegatewayjava.tls;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * 握手通道客户端：连接本地回环服务端，执行双向证书校验，
 * 并在握手后对会话（含复用会话）按当前策略快照复核。
 *
 * <p>握手完成后通过应用级结果协议确认服务端接受本次连接；
 * 若被拒绝，失败信息中包含可区分的原因码。
 */
public class HandshakeClient implements AutoCloseable {

    private final PolicyManager policyManager;
    private final KeyManager[] keyManagers;
    private volatile SSLContext sslContext;
    private volatile PolicySnapshot contextSnapshot;
    private SSLSocket socket;
    private byte[] firstSessionId;
    private byte[] lastSessionId;

    public HandshakeClient(PolicyManager policyManager) {
        this(policyManager, null);
    }

    public HandshakeClient(PolicyManager policyManager, KeyManager[] keyManagers) {
        this.policyManager = policyManager;
        this.keyManagers = keyManagers;
        this.contextSnapshot = policyManager.current();
        this.sslContext = HandshakeGateway.buildContext(contextSnapshot, keyManagers);
        policyManager.addReloadListener(this::refreshContextIfIdentityChanged);
    }

    /** 仅在本端身份变化时重建 SSLContext，保留会话缓存。 */
    private void refreshContextIfIdentityChanged() {
        PolicySnapshot now = policyManager.current();
        if (!identityEquals(now, contextSnapshot)) {
            contextSnapshot = now;
            sslContext = HandshakeGateway.buildContext(now, keyManagers);
        }
    }

    private static boolean identityEquals(PolicySnapshot a, PolicySnapshot b) {
        if (a == null || b == null) {
            return a == b;
        }
        return java.util.Objects.equals(a.identityKey(), b.identityKey())
                && java.util.Objects.equals(a.identityChain(), b.identityChain());
    }

    /**
     * 连接并完成握手。握手开始时取一次策略快照，整次握手复用同一快照。
     * 握手后通过应用级结果协议确认对端接受本次连接。
     */
    public void connect(String host, int port) throws IOException, HandshakeException {
        PolicySnapshot snapshot = policyManager.current();
        SSLSocket newSocket = (SSLSocket) sslContext.getSocketFactory().createSocket(host, port);
        ValidatingTrustManager.CURRENT.set(snapshot);
        try {
            newSocket.setEnabledProtocols(new String[]{"TLSv1.2"});
            newSocket.setSoTimeout(30_000);
            newSocket.startHandshake();

            // 1. 读取服务端的握手结果
            String result = readLine(newSocket);
            if (result == null) {
                throw new HandshakeException(FailureReason.VALIDATION_ERROR, "服务端关闭了连接");
            }
            if (result.startsWith("REJECT")) {
                FailureReason reason = parseReason(result);
                throw new HandshakeException(reason, "服务端拒绝连接: " + result);
            }

            // 2. 复核服务端证书（含复用会话，复用会话不触发 TrustManager）
            CertificateValidationException failure = ValidatingTrustManager.takeRecordedFailure();
            if (failure == null) {
                failure = postValidate(newSocket, snapshot);
            }
            if (failure != null) {
                sendResult(newSocket, "REJECT:" + failure.getReason());
                throw new HandshakeException(failure.getReason(), failure.getMessage(), failure);
            }

            // 3. 发送本端确认
            sendResult(newSocket, "OK");
            trackSession(newSocket);
            this.socket = newSocket;
        } finally {
            ValidatingTrustManager.CURRENT.remove();
            ValidatingTrustManager.clearRecordedFailure();
        }
    }

    private static FailureReason parseReason(String result) {
        String code = result.substring("REJECT:".length());
        try {
            return FailureReason.valueOf(code);
        } catch (IllegalArgumentException e) {
            return FailureReason.VALIDATION_ERROR;
        }
    }

    private void sendResult(SSLSocket socket, String result) throws IOException {
        OutputStream out = socket.getOutputStream();
        out.write((result + "\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    private String readLine(SSLSocket socket) throws IOException {
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
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

    private void trackSession(SSLSocket socket) {
        SSLSession session = socket.getSession();
        byte[] id = session.getId();
        if (firstSessionId == null) {
            firstSessionId = id;
        }
        lastSessionId = id;
    }

    /** 发送一行文本并读取回显。 */
    public String echo(String message) throws IOException {
        if (socket == null || socket.isClosed()) {
            throw new IOException("尚未连接");
        }
        PrintWriter out = new PrintWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8), true);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        out.println(message);
        return in.readLine();
    }

    /** 当前连接是否复用了首次握手的会话。 */
    public boolean isResumed() {
        return firstSessionId != null && lastSessionId != null
                && Arrays.equals(firstSessionId, lastSessionId);
    }

    public byte[] getSessionId() {
        return lastSessionId == null ? null : lastSessionId.clone();
    }

    @Override
    public void close() throws IOException {
        if (socket != null) {
            socket.close();
        }
    }
}
