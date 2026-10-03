package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManager;
import java.io.IOException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 基于本地回环的握手通道集成测试：
 * 覆盖双向证书认证、各类拒绝场景、会话复用复核、配置热更新原子生效与高并发正确性。
 */
class HandshakeGatewayIT {

    static TestCertificates certs;

    HandshakeGateway gateway;
    PolicyManager serverPm;
    int port;

    @BeforeAll
    static void initCerts() throws Exception {
        certs = new TestCertificates();
    }

    @AfterEach
    void tearDown() {
        if (gateway != null) {
            gateway.stop();
        }
    }

    // ---------- 配置构造 ----------

    private PolicyConfig.Builder serverBase() {
        return PolicyConfig.builder()
                .role(HandshakeRole.SERVER)
                .identity(certs.server.keyPair.getPrivate(), List.of(certs.server.chain))
                .trustAnchors(Set.of(certs.rootCa))
                .pinningEnabled(true)
                .revocationEnabled(true)
                .revocationDataAvailable(true)
                .revokedSerials(Set.of(certs.clientRevoked.cert.getSerialNumber()))
                .revocationUnavailable(RevocationPolicy.FAIL_CLOSED)
                .sessionResumptionEnabled(true);
    }

    private PolicyConfig.Builder clientBase() {
        return PolicyConfig.builder()
                .role(HandshakeRole.CLIENT)
                .identity(certs.client.keyPair.getPrivate(), List.of(certs.client.chain))
                .trustAnchors(Set.of(certs.rootCa))
                .pinningEnabled(true)
                .revocationEnabled(true)
                .revocationDataAvailable(true)
                .revocationUnavailable(RevocationPolicy.FAIL_CLOSED)
                .sessionResumptionEnabled(true);
    }

    private void startServer(PolicyConfig cfg) throws Exception {
        serverPm = new PolicyManager(cfg);
        gateway = new HandshakeGateway(serverPm, 0);
        gateway.start();
        port = gateway.getPort();
    }

    private HandshakeClient newClient(PolicyConfig cfg) {
        KeyManager[] kms = new KeyManager[]{
                new FixedKeyManager("client", cfg.identityKey(),
                        cfg.identityChain().toArray(new X509Certificate[0]))};
        return new HandshakeClient(new PolicyManager(cfg), kms);
    }

    private Map<String, Set<String>> clientPins() {
        return Map.of("internal-client",
                Set.of(TestCertificates.fingerprint(certs.client.cert),
                        TestCertificates.fingerprint(certs.clientRotated.cert)));
    }

    private Map<String, Set<String>> serverPins() {
        return Map.of("localhost", Set.of(TestCertificates.fingerprint(certs.server.cert)));
    }

    // ---------- 断言工具 ----------

    /** 断言连接失败，且失败信息中包含指定原因码（解包整个异常链）。 */
    private void expectConnectFailure(FailureReason expected, HandshakeClient client) {
        Exception e = assertThrows(Exception.class, () -> client.connect("127.0.0.1", port));
        boolean found = false;
        Throwable cur = e;
        while (cur != null) {
            if (cur.getMessage() != null && cur.getMessage().contains("[" + expected + "]")) {
                found = true;
                break;
            }
            cur = cur.getCause();
        }
        assertTrue(found, "失败原因应为 [" + expected + "]，实际: " + e);
    }

    private void expectConnectFailure(FailureReason expected, PolicyConfig clientCfg) {
        HandshakeClient client = newClient(clientCfg);
        try {
            expectConnectFailure(expected, client);
        } finally {
            try {
                client.close();
            } catch (IOException ignored) {
            }
        }
    }

    // ---------- 正常双向认证 ----------

    @Test
    void mutualHandshake_shouldSucceed_andEcho() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        HandshakeClient client = newClient(clientBase().pins(serverPins()).build());
        client.connect("127.0.0.1", port);
        assertEquals("echo:hello", client.echo("hello"));
        client.close();
    }

    @Test
    void rotatedClientKey_shouldSucceed() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        PolicyConfig clientCfg = clientBase()
                .identity(certs.clientRotated.keyPair.getPrivate(), List.of(certs.clientRotated.chain))
                .pins(serverPins()).build();
        HandshakeClient client = newClient(clientCfg);
        client.connect("127.0.0.1", port);
        assertEquals("echo:ok", client.echo("ok"));
        client.close();
    }

    // ---------- 信任链失败 ----------

    @Test
    void missingIntermediate_shouldBeRejected() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        PolicyConfig clientCfg = clientBase()
                .identity(certs.client.keyPair.getPrivate(), List.of(certs.client.cert))
                .pins(serverPins()).build();
        expectConnectFailure(FailureReason.CHAIN_MISSING_INTERMEDIATE, clientCfg);
    }

    @Test
    void untrustedRoot_shouldBeRejected() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        PolicyConfig clientCfg = clientBase()
                .identity(certs.clientSelfSigned.keyPair.getPrivate(), List.of(certs.clientSelfSigned.chain))
                .pins(serverPins()).build();
        expectConnectFailure(FailureReason.CHAIN_UNTRUSTED_ROOT, clientCfg);
    }

    @Test
    void invalidSignature_shouldBeRejected() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        PolicyConfig clientCfg = clientBase()
                .identity(certs.clientSignedByIntermediate2.keyPair.getPrivate(),
                        List.of(certs.clientSignedByIntermediate2.chain))
                .pins(serverPins()).build();
        expectConnectFailure(FailureReason.SIGNATURE_INVALID, clientCfg);
    }

    // ---------- 有效期与用途 ----------

    @Test
    void expiredClientCert_shouldBeRejected() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        PolicyConfig clientCfg = clientBase()
                .identity(certs.clientExpired.keyPair.getPrivate(), List.of(certs.clientExpired.chain))
                .pins(serverPins()).build();
        expectConnectFailure(FailureReason.CERT_EXPIRED, clientCfg);
    }

    @Test
    void wrongRoleEku_shouldBeRejected() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        PolicyConfig clientCfg = clientBase()
                .identity(certs.clientServerAuthOnly.keyPair.getPrivate(),
                        List.of(certs.clientServerAuthOnly.chain))
                .pins(serverPins()).build();
        expectConnectFailure(FailureReason.ROLE_MISMATCH, clientCfg);
    }

    // ---------- 公钥固定 ----------

    @Test
    void pinMismatch_shouldBeRejected() throws Exception {
        startServer(serverBase()
                .pins(Map.of("internal-client",
                        Set.of(TestCertificates.fingerprint(certs.server.cert))))
                .build());
        expectConnectFailure(FailureReason.PIN_MISMATCH,
                clientBase().pins(serverPins()).build());
    }

    // ---------- 吊销 ----------

    @Test
    void revokedCert_shouldBeRejected() throws Exception {
        // 固定凭据需包含被吊销证书的指纹，使校验进行到吊销检查
        Map<String, Set<String>> pins = Map.of("internal-client",
                Set.of(TestCertificates.fingerprint(certs.clientRevoked.cert)));
        startServer(serverBase().pins(pins).build());
        PolicyConfig clientCfg = clientBase()
                .identity(certs.clientRevoked.keyPair.getPrivate(), List.of(certs.clientRevoked.chain))
                .pins(serverPins()).build();
        expectConnectFailure(FailureReason.CERT_REVOKED, clientCfg);
    }

    @Test
    void revocationUnavailable_failClosed_shouldReject() throws Exception {
        startServer(serverBase().pins(clientPins())
                .revocationDataAvailable(false).revocationUnavailable(RevocationPolicy.FAIL_CLOSED)
                .build());
        expectConnectFailure(FailureReason.REVOCATION_DATA_UNAVAILABLE,
                clientBase().pins(serverPins()).build());
    }

    @Test
    void revocationUnavailable_failOpen_shouldAllow() throws Exception {
        startServer(serverBase().pins(clientPins())
                .revocationDataAvailable(false).revocationUnavailable(RevocationPolicy.FAIL_OPEN)
                .build());
        HandshakeClient client = newClient(clientBase().pins(serverPins()).build());
        client.connect("127.0.0.1", port);
        assertEquals("echo:x", client.echo("x"));
        client.close();
    }

    // ---------- 会话复用 ----------

    @Test
    void sessionResumption_shouldReuseSession() throws Exception {
        startServer(serverBase().pins(clientPins()).build());
        HandshakeClient client = newClient(clientBase().pins(serverPins()).build());
        client.connect("127.0.0.1", port);
        byte[] firstId = client.getSessionId();

        // 复用同一客户端实例（同一 SSLContext 会话缓存）
        client.connect("127.0.0.1", port);
        byte[] secondId = client.getSessionId();
        assertTrue(client.isResumed(), "第二次握手应复用会话");
        assertArrayEquals(firstId, secondId, "复用会话的 ID 应与首次一致");
        assertEquals("echo:again", client.echo("again"));
        client.close();
    }

    @Test
    void resumedSession_afterPinChange_shouldBeRejected() throws Exception {
        PolicyConfig serverCfg = serverBase().pins(clientPins()).build();
        PolicyConfig clientCfg = clientBase().pins(serverPins()).build();
        startServer(serverCfg);
        serverPm = new PolicyManager(serverCfg);
        // 让网关与客户端共用各自的 PolicyManager，便于热更新
        gateway.stop();
        gateway = new HandshakeGateway(serverPm, 0);
        gateway.start();
        port = gateway.getPort();

        PolicyManager clientPm = new PolicyManager(clientCfg);
        HandshakeClient client = new HandshakeClient(clientPm);
        client.connect("127.0.0.1", port);
        client.close();

        // 热更新：服务端固定凭据更换（客户端指纹不再匹配），客户端对服务端的固定也更换
        serverPm.reload(serverCfg.toBuilder()
                .pins(Map.of("internal-client",
                        Set.of(TestCertificates.fingerprint(certs.server.cert))))
                .build());
        clientPm.reload(clientCfg.toBuilder()
                .pins(Map.of("localhost",
                        Set.of(TestCertificates.fingerprint(certs.client.cert))))
                .build());

        // 复用同一客户端实例（同一 SSLContext 会话缓存）；复用的会话也必须满足新策略
        Exception e = assertThrows(Exception.class, () -> client.connect("127.0.0.1", port));
        boolean pinFailure = false;
        Throwable cur = e;
        while (cur != null) {
            if (cur.getMessage() != null && cur.getMessage().contains("[" + FailureReason.PIN_MISMATCH + "]")) {
                pinFailure = true;
                break;
            }
            cur = cur.getCause();
        }
        assertTrue(pinFailure, "复用会话在固定凭据变化后应被拒绝，实际: " + e);
        client.close();
    }

    // ---------- 热更新原子性 ----------

    @Test
    void hotReload_newConnectionsUseNewPolicy_establishedConnectionUnaffected() throws Exception {
        PolicyConfig serverCfg = serverBase().pins(clientPins()).build();
        startServer(serverCfg);

        // 已建立的长连接
        HandshakeClient established = newClient(clientBase().pins(serverPins()).build());
        established.connect("127.0.0.1", port);
        assertEquals("echo:1", established.echo("1"));

        // 热更新：清空信任锚（新连接无法构建链）
        serverPm.reload(serverCfg.toBuilder().trustAnchors(Set.of()).build());

        // 新连接被拒绝
        expectConnectFailure(FailureReason.CHAIN_MISSING_INTERMEDIATE,
                clientBase().pins(serverPins()).build());

        // 已建立的连接不受影响
        assertEquals("echo:2", established.echo("2"));
        established.close();

        // 恢复策略后新连接恢复正常
        serverPm.reload(serverCfg);
        HandshakeClient afterRestore = newClient(clientBase().pins(serverPins()).build());
        afterRestore.connect("127.0.0.1", port);
        assertEquals("echo:3", afterRestore.echo("3"));
        afterRestore.close();
    }

    // ---------- 高并发 ----------

    @Test
    void concurrentHandshakes_shouldAllSucceedOrFailConsistently() throws Exception {
        PolicyConfig serverCfg = serverBase().pins(clientPins()).build();
        startServer(serverCfg);
        PolicyConfig clientCfg = clientBase().pins(serverPins()).build();

        int threads = 24;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        List<Callable<Boolean>> tasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            tasks.add(() -> {
                HandshakeClient c = newClient(clientCfg);
                try {
                    c.connect("127.0.0.1", port);
                    return "echo:hi".equals(c.echo("hi"));
                } finally {
                    c.close();
                }
            });
        }
        List<Future<Boolean>> results = pool.invokeAll(tasks);
        for (Future<Boolean> f : results) {
            assertTrue(f.get(30, TimeUnit.SECONDS), "所有并发握手都应成功");
        }

        // 热更新固定凭据后，新连接应一致失败，且不污染其他连接
        serverPm.reload(serverCfg.toBuilder()
                .pins(Map.of("internal-client",
                        Set.of(TestCertificates.fingerprint(certs.server.cert))))
                .build());
        List<Callable<Boolean>> failTasks = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
            failTasks.add(() -> {
                HandshakeClient c = newClient(clientCfg);
                try {
                    c.connect("127.0.0.1", port);
                    return false;
                } catch (Exception e) {
                    boolean pinFailure = false;
                    Throwable cur = e;
                    while (cur != null) {
                        if (cur.getMessage() != null
                                && cur.getMessage().contains("[" + FailureReason.PIN_MISMATCH + "]")) {
                            pinFailure = true;
                            break;
                        }
                        cur = cur.getCause();
                    }
                    return pinFailure;
                } finally {
                    c.close();
                }
            });
        }
        for (Future<Boolean> f : pool.invokeAll(failTasks)) {
            assertTrue(f.get(30, TimeUnit.SECONDS), "策略更新后所有新连接应一致地被拒绝");
        }
        pool.shutdownNow();
    }
}
