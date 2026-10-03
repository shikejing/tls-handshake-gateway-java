package com.github.shikejing.tlshandshakegatewayjava.tls;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Properties;

/**
 * 从本地属性文件加载策略配置，支持运行中重新加载。
 *
 * <pre>
 * role=server|client
 * identity.key=path/to/key.pem            # PKCS#8 PEM 私钥
 * identity.cert=path/to/cert.pem          # 本端证书（PEM，可含多张）
 * trustAnchors=ca1.pem,ca2.pem            # 信任锚（PEM）
 * pin.client.<CN>=sha256:aa:bb,sha256:cc:dd
 * pin.server.<CN>=sha256:..
 * pinning.enabled=true|false
 * revocation.enabled=true|false
 * revocation.file=revoked.txt
 * revocation.unavailablePolicy=fail-open|fail-closed
 * sessionResumption.enabled=true|false
 * </pre>
 */
public class PolicyFileLoader {

    private final Path file;

    public PolicyFileLoader(Path file) {
        this.file = file;
    }

    public Path getFile() {
        return file;
    }

    /** 读取并解析为策略配置。 */
    public PolicyConfig load() {
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(file)) {
            props.load(in);
        } catch (IOException e) {
            throw new IllegalStateException("无法读取策略文件: " + file, e);
        }
        try {
            HandshakeRole role = HandshakeRole.valueOf(
                    props.getProperty("role", "server").trim().toUpperCase());

            PrivateKey identityKey = null;
            List<X509Certificate> identityChain = List.of();
            String keyPath = props.getProperty("identity.key");
            String certPath = props.getProperty("identity.cert");
            if (keyPath != null && certPath != null) {
                identityKey = loadPrivateKey(Path.of(keyPath.trim()));
                identityChain = loadCertificates(Path.of(certPath.trim()));
            }

            List<X509Certificate> anchors = new ArrayList<>();
            String anchorProp = props.getProperty("trustAnchors");
            if (anchorProp != null && !anchorProp.isBlank()) {
                for (String p : anchorProp.split(",")) {
                    anchors.addAll(loadCertificates(Path.of(p.trim())));
                }
            }

            Map<String, Set<String>> pins = new LinkedHashMap<>();
            for (String name : props.stringPropertyNames()) {
                if (name.startsWith("pin.")) {
                    String rest = name.substring("pin.".length());
                    String[] parts = rest.split("\\.", 2);
                    String peer = parts.length == 2 ? parts[1] : parts[0];
                    Set<String> fps = new java.util.LinkedHashSet<>();
                    for (String fp : props.getProperty(name).split(",")) {
                        String normalized = normalizeFingerprint(fp);
                        if (!normalized.isEmpty()) {
                            fps.add(normalized);
                        }
                    }
                    pins.merge(peer, fps, (a, b) -> {
                        a.addAll(b);
                        return a;
                    });
                }
            }

            boolean revocationEnabled = Boolean.parseBoolean(
                    props.getProperty("revocation.enabled", "true").trim());
            boolean revocationAvailable = true;
            java.util.Set<java.math.BigInteger> revokedSerials = java.util.Set.of();
            String revPath = props.getProperty("revocation.file");
            if (revPath != null && !revPath.isBlank()) {
                FileRevocationDataSource ds = new FileRevocationDataSource(Path.of(revPath.trim()));
                revocationAvailable = ds.isAvailable();
                if (revocationAvailable) {
                    revokedSerials = ds.revokedSerials();
                }
            }
            RevocationPolicy revPolicy = "fail-open".equalsIgnoreCase(
                    props.getProperty("revocation.unavailablePolicy", "fail-closed").trim())
                    ? RevocationPolicy.FAIL_OPEN : RevocationPolicy.FAIL_CLOSED;

            return PolicyConfig.builder()
                    .role(role)
                    .identity(identityKey, identityChain)
                    .trustAnchors(java.util.Set.copyOf(anchors))
                    .pins(pins)
                    .pinningEnabled(Boolean.parseBoolean(
                            props.getProperty("pinning.enabled", "true").trim()))
                    .revocationEnabled(revocationEnabled)
                    .revokedSerials(revokedSerials)
                    .revocationDataAvailable(revocationAvailable)
                    .revocationUnavailable(revPolicy)
                    .sessionResumptionEnabled(Boolean.parseBoolean(
                            props.getProperty("sessionResumption.enabled", "true").trim()))
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("解析策略文件失败: " + file, e);
        }
    }

    static List<X509Certificate> loadCertificates(Path path) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream in = Files.newInputStream(path)) {
            List<X509Certificate> list = new ArrayList<>();
            for (Certificate c : cf.generateCertificates(in)) {
                list.add((X509Certificate) c);
            }
            return list;
        }
    }

    static PrivateKey loadPrivateKey(Path path) throws Exception {
        String pem = Files.readString(path, StandardCharsets.UTF_8);
        String base64 = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception ignore) {
            return KeyFactory.getInstance("EC").generatePrivate(spec);
        }
    }

    private static String normalizeFingerprint(String fp) {
        String v = fp.trim().toLowerCase();
        if (v.startsWith("sha256:")) {
            v = v.substring("sha256:".length());
        }
        v = v.replace(":", "");
        return v.isEmpty() ? "" : "sha256:" + v;
    }
}
