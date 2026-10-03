package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link PolicyFileLoader} 与 {@link FileRevocationDataSource} 测试：
 * 覆盖策略文件解析、吊销数据源读取与不可用策略。
 */
class PolicyFileLoaderTest {

    static TestCertificates certs;

    @TempDir
    Path tempDir;

    @BeforeAll
    static void initCerts() throws Exception {
        certs = new TestCertificates();
    }

    private void writePem(Path path, X509Certificate... certs) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (X509Certificate c : certs) {
            sb.append("-----BEGIN CERTIFICATE-----\n");
            sb.append(java.util.Base64.getEncoder().encodeToString(c.getEncoded()));
            sb.append("\n-----END CERTIFICATE-----\n");
        }
        Files.writeString(path, sb.toString());
    }

    @Test
    void loadPolicyFile_shouldParseAnchorsPinsAndRevocation() throws Exception {
        Path caFile = tempDir.resolve("ca.pem");
        writePem(caFile, certs.rootCa);

        Path revFile = tempDir.resolve("revoked.txt");
        BigInteger revokedSerial = certs.clientRevoked.cert.getSerialNumber();
        Files.writeString(revFile, "# 注释\n" + revokedSerial.toString(16) + "\n");

        Path policyFile = tempDir.resolve("policy.properties");
        String fp = TestCertificates.fingerprint(certs.client.cert);
        Files.writeString(policyFile, """
                role=server
                trustAnchors=%s
                pin.client.internal-client=%s
                revocation.enabled=true
                revocation.file=%s
                revocation.unavailablePolicy=fail-closed
                pinning.enabled=true
                """.formatted(caFile, fp, revFile));

        PolicyConfig config = new PolicyFileLoader(policyFile).load();

        assertEquals(HandshakeRole.SERVER, config.role());
        assertEquals(1, config.trustAnchors().size());
        assertTrue(config.trustAnchors().contains(certs.rootCa));
        assertNotNull(config.pins().get("internal-client"));
        assertTrue(config.pins().get("internal-client").contains(fp));
        assertTrue(config.revokedSerials().contains(revokedSerial));
        assertTrue(config.revocationDataAvailable());
        assertEquals(RevocationPolicy.FAIL_CLOSED, config.revocationUnavailable());
    }

    @Test
    void missingRevocationFile_shouldMarkUnavailable() throws Exception {
        Path caFile = tempDir.resolve("ca.pem");
        writePem(caFile, certs.rootCa);

        Path policyFile = tempDir.resolve("policy.properties");
        Files.writeString(policyFile, """
                role=server
                trustAnchors=%s
                revocation.enabled=true
                revocation.file=%s
                revocation.unavailablePolicy=fail-open
                """.formatted(caFile, tempDir.resolve("missing.txt")));

        PolicyConfig config = new PolicyFileLoader(policyFile).load();
        assertFalse(config.revocationDataAvailable());
        assertEquals(RevocationPolicy.FAIL_OPEN, config.revocationUnavailable());
    }

    @Test
    void revocationDataSource_shouldRefreshOnFileChange() throws Exception {
        Path revFile = tempDir.resolve("revoked.txt");
        Files.writeString(revFile, "");
        FileRevocationDataSource ds = new FileRevocationDataSource(revFile);
        assertTrue(ds.isAvailable());
        assertTrue(ds.revokedSerials().isEmpty());

        BigInteger serial = certs.clientRevoked.cert.getSerialNumber();
        Files.writeString(revFile, serial.toString(16) + "\n");
        // 触发刷新
        assertTrue(ds.revokedSerials().contains(serial));
    }

    @Test
    void policyManagerReload_shouldAtomicallySwapSnapshot() throws Exception {
        PolicyConfig cfg1 = PolicyConfig.builder()
                .role(HandshakeRole.SERVER)
                .trustAnchors(Set.of(certs.rootCa))
                .pins(java.util.Map.of("internal-client",
                        Set.of(TestCertificates.fingerprint(certs.client.cert))))
                .build();
        PolicyManager manager = new PolicyManager(cfg1);
        assertEquals(1, manager.current().trustAnchors().size());

        PolicyConfig cfg2 = cfg1.toBuilder().trustAnchors(Set.of()).build();
        manager.reload(cfg2);
        assertEquals(0, manager.current().trustAnchors().size());
        assertTrue(manager.epoch() > 0);
    }
}
