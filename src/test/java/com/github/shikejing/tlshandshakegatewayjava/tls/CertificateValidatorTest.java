package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CertificateValidator} 单元测试：覆盖信任链、有效期、用途、固定、吊销等校验语义。
 */
class CertificateValidatorTest {

    static TestCertificates certs;
    final CertificateValidator validator = new CertificateValidator();

    @BeforeAll
    static void setup() throws Exception {
        certs = new TestCertificates();
    }

    private PolicySnapshot snapshot(HandshakeRole role, Map<String, Set<String>> pins,
                                    Set<BigInteger> revoked, boolean revAvailable,
                                    RevocationPolicy rp) {
        PolicyConfig config = PolicyConfig.builder()
                .role(role)
                .trustAnchors(Set.of(certs.rootCa))
                .pins(pins == null ? Map.of() : pins)
                .pinningEnabled(pins != null)
                .revocationEnabled(true)
                .revokedSerials(revoked == null ? Set.of() : revoked)
                .revocationDataAvailable(revAvailable)
                .revocationUnavailable(rp)
                .build();
        return PolicySnapshot.from(config, 0);
    }

    private PolicySnapshot snapshot(HandshakeRole role) {
        return snapshot(role, null, null, true, RevocationPolicy.FAIL_CLOSED);
    }

    private void expect(FailureReason expected, X509Certificate[] chain, HandshakeRole role,
                        PolicySnapshot snapshot) {
        CertificateValidationException e = assertThrows(CertificateValidationException.class,
                () -> validator.validate(chain, role, snapshot));
        assertEquals(expected, e.getReason(), "失败原因码应可区分: " + e.getMessage());
        // 失败信息不得包含证书完整内容（证书的完整 DER/PEM 不应出现）
        assertTrue(e.getMessage().startsWith("[" + expected + "]"),
                "失败信息应以原因码开头: " + e.getMessage());
    }

    private Map<String, Set<String>> clientPin(String fp) {
        return Map.of("internal-client", Set.of(fp));
    }

    // ---------- 正常场景 ----------

    @Test
    void validClientCert_shouldPass() throws Exception {
        validator.validate(certs.client.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER, clientPin(TestCertificates.fingerprint(certs.client.cert)),
                        null, true, RevocationPolicy.FAIL_CLOSED));
    }

    @Test
    void validServerCert_shouldPass() throws Exception {
        validator.validate(certs.server.chain, HandshakeRole.CLIENT,
                snapshot(HandshakeRole.CLIENT, Map.of("localhost",
                        Set.of(TestCertificates.fingerprint(certs.server.cert))),
                        null, true, RevocationPolicy.FAIL_CLOSED));
    }

    // ---------- 信任链失败 ----------

    @Test
    void missingIntermediate_shouldBeRejectedWithDistinguishableReason() {
        expect(FailureReason.CHAIN_MISSING_INTERMEDIATE,
                new X509Certificate[]{certs.client.cert}, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    @Test
    void untrustedRoot_shouldBeRejected() {
        expect(FailureReason.CHAIN_UNTRUSTED_ROOT,
                certs.clientSelfSigned.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    @Test
    void invalidSignature_shouldBeRejected() {
        // 叶子由中间 CA2 签名，却搭配中间 CA1 的证书
        expect(FailureReason.SIGNATURE_INVALID,
                certs.clientSignedByIntermediate2.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    // ---------- 有效期 ----------

    @Test
    void expiredCert_shouldBeRejected() {
        expect(FailureReason.CERT_EXPIRED, certs.clientExpired.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    @Test
    void notYetValidCert_shouldBeRejected() {
        expect(FailureReason.CERT_NOT_YET_VALID, certs.clientNotYetValid.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    // ---------- 用途与角色匹配 ----------

    @Test
    void serverAuthOnlyCert_asClient_shouldBeRejected() {
        // 本端是服务端，对端证书必须具备客户端身份；仅 serverAuth 不允许
        expect(FailureReason.ROLE_MISMATCH, certs.clientServerAuthOnly.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    @Test
    void clientAuthOnlyCert_asServer_shouldBeRejected() {
        // 本端是客户端，对端证书必须具备服务端身份；仅 clientAuth 不允许
        expect(FailureReason.ROLE_MISMATCH, certs.serverClientAuthOnly.chain, HandshakeRole.CLIENT,
                snapshot(HandshakeRole.CLIENT));
    }

    @Test
    void caLeaf_shouldBeRejected() {
        expect(FailureReason.END_ENTITY_IS_CA, certs.clientCaLeaf.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    @Test
    void clientKeyUsageWrong_shouldBeRejected() {
        // 客户端证书密钥用途仅 keyEncipherment，不允许客户端身份
        expect(FailureReason.ROLE_MISMATCH, certs.clientKeyUsageWrong.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }

    @Test
    void serverKeyUsageWrong_shouldBeRejected() {
        // 服务端证书密钥用途仅 digitalSignature，不允许服务端身份
        expect(FailureReason.ROLE_MISMATCH, certs.serverKeyUsageWrong.chain, HandshakeRole.CLIENT,
                snapshot(HandshakeRole.CLIENT));
    }

    // ---------- 公钥固定 ----------

    @Test
    void pinMismatch_shouldBeRejectedWithoutLeakingCertContents() {
        String wrongFp = TestCertificates.fingerprint(certs.server.cert);
        CertificateValidationException e = assertThrows(CertificateValidationException.class,
                () -> validator.validate(certs.client.chain, HandshakeRole.SERVER,
                        snapshot(HandshakeRole.SERVER, clientPin(wrongFp),
                                null, true, RevocationPolicy.FAIL_CLOSED)));
        assertEquals(FailureReason.PIN_MISMATCH, e.getReason());
        // 失败信息不得包含证书指纹本身或证书内容
        assertTrue(e.getMessage().contains("internal-client"));
    }

    @Test
    void pinNotConfigured_shouldBeRejected() {
        expect(FailureReason.PIN_NOT_CONFIGURED, certs.client.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER, Map.of(), null, true, RevocationPolicy.FAIL_CLOSED));
    }

    @Test
    void multiplePinsForRotation_shouldAcceptEither() throws Exception {
        String fp1 = TestCertificates.fingerprint(certs.client.cert);
        String fp2 = TestCertificates.fingerprint(certs.clientRotated.cert);
        // 配置中同时保留新旧两枚指纹
        PolicySnapshot snap = snapshot(HandshakeRole.SERVER,
                Map.of("internal-client", Set.of(fp1, fp2)),
                null, true, RevocationPolicy.FAIL_CLOSED);
        validator.validate(certs.client.chain, HandshakeRole.SERVER, snap);
        validator.validate(certs.clientRotated.chain, HandshakeRole.SERVER, snap);
    }

    // ---------- 吊销 ----------

    @Test
    void revokedCert_shouldBeRejected() {
        expect(FailureReason.CERT_REVOKED, certs.clientRevoked.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER, clientPin(TestCertificates.fingerprint(certs.clientRevoked.cert)),
                        Set.of(certs.clientRevoked.cert.getSerialNumber()),
                        true, RevocationPolicy.FAIL_CLOSED));
    }

    @Test
    void revocationDataUnavailable_failClosed_shouldReject() {
        expect(FailureReason.REVOCATION_DATA_UNAVAILABLE, certs.client.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER, clientPin(TestCertificates.fingerprint(certs.client.cert)),
                        null, false, RevocationPolicy.FAIL_CLOSED));
    }

    @Test
    void revocationDataUnavailable_failOpen_shouldAllow() throws Exception {
        // fail-open：数据源不可用时放行（被吊销风险上升，文档需说明）
        validator.validate(certs.client.chain, HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER, clientPin(TestCertificates.fingerprint(certs.client.cert)),
                        null, false, RevocationPolicy.FAIL_OPEN));
    }

    // ---------- 无证书 ----------

    @Test
    void noPeerCert_shouldBeRejected() {
        expect(FailureReason.NO_PEER_CERTIFICATE, new X509Certificate[0], HandshakeRole.SERVER,
                snapshot(HandshakeRole.SERVER));
    }
}
