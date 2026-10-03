package com.github.shikejing.tlshandshakegatewayjava.tls;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;

/**
 * 证书校验器：链信任、有效期、密钥用途、基本约束、公钥固定、吊销状态。
 * 校验全程使用同一个 {@link PolicySnapshot}，保证一次握手策略一致，
 * 不会出现“半新半旧”的校验结果。
 */
public class CertificateValidator {

    /** 服务端身份证书扩展密钥用途 OID。 */
    private static final String EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    /** 客户端身份证书扩展密钥用途 OID。 */
    private static final String EKU_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

    /**
     * 对端证书链执行完整校验。
     *
     * @param chain    对端证书链（叶子在前）
     * @param role     本端角色（决定对端证书应具备的用途）
     * @param snapshot 本次握手使用的策略快照
     */
    public void validate(X509Certificate[] chain, HandshakeRole role, PolicySnapshot snapshot)
            throws CertificateValidationException {
        if (chain == null || chain.length == 0 || chain[0] == null) {
            throw new CertificateValidationException(FailureReason.NO_PEER_CERTIFICATE,
                    "对端未提供证书");
        }

        // 1. 证书链结构与签名：缺中间证书、签名无法验证、根不受信
        validateChainStructure(chain, snapshot.trustAnchors());

        // 2. 有效期
        validateValidity(chain);

        // 3. 基本约束 + 密钥用途（与角色匹配）
        validateUsage(chain, role);

        // 4. 公开密钥固定
        if (snapshot.pinningEnabled()) {
            validatePinning(chain[0], snapshot);
        }

        // 5. 吊销状态
        if (snapshot.revocationEnabled()) {
            validateRevocation(chain, snapshot);
        }
    }

    /**
     * 逐张验证链上签名关系，并判定链顶是否能锚定到信任锚。
     * 失败原因区分：缺中间证书 / 签名无效 / 根不受信。
     */
    private void validateChainStructure(X509Certificate[] chain, Set<X509Certificate> anchors)
            throws CertificateValidationException {
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            X509PrincipalWrapper issuer = findIssuer(cert, chain, i, anchors);
            if (issuer == null) {
                // 无法找到颁发者：链顶为自签名但不在信任锚中，或缺少中间证书
                if (i == chain.length - 1
                        && cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                    throw new CertificateValidationException(FailureReason.CHAIN_UNTRUSTED_ROOT,
                            "证书链终结于不受信的根证书: "
                                    + CertificateValidationException.redactedSummary(cert));
                }
                throw new CertificateValidationException(FailureReason.CHAIN_MISSING_INTERMEDIATE,
                        "证书链缺少中间证书，无法构建到信任锚的路径: "
                                + CertificateValidationException.redactedSummary(cert));
            }
            try {
                cert.verify(issuer.publicKey);
            } catch (Exception e) {
                throw new CertificateValidationException(FailureReason.SIGNATURE_INVALID,
                        "证书签名无法用颁发者公钥验证: "
                                + CertificateValidationException.redactedSummary(cert), e);
            }
        }
    }

    private X509PrincipalWrapper findIssuer(X509Certificate cert, X509Certificate[] chain, int index,
                                            Set<X509Certificate> anchors) {
        X500Principal issuerName = cert.getIssuerX500Principal();
        // 优先在链内查找颁发者
        if (index < chain.length - 1) {
            X509Certificate candidate = chain[index + 1];
            if (candidate.getSubjectX500Principal().equals(issuerName)) {
                return new X509PrincipalWrapper(candidate.getPublicKey());
            }
            return null;
        }
        // 链顶：在信任锚中查找颁发者
        for (X509Certificate anchor : anchors) {
            if (anchor.getSubjectX500Principal().equals(issuerName)) {
                return new X509PrincipalWrapper(anchor.getPublicKey());
            }
        }
        return null;
    }

    private record X509PrincipalWrapper(PublicKey publicKey) {
    }

    private void validateValidity(X509Certificate[] chain) throws CertificateValidationException {
        for (X509Certificate cert : chain) {
            try {
                cert.checkValidity();
            } catch (java.security.cert.CertificateExpiredException e) {
                throw new CertificateValidationException(FailureReason.CERT_EXPIRED,
                        "证书已过有效期: " + CertificateValidationException.redactedSummary(cert), e);
            } catch (java.security.cert.CertificateNotYetValidException e) {
                throw new CertificateValidationException(FailureReason.CERT_NOT_YET_VALID,
                        "证书尚未生效: " + CertificateValidationException.redactedSummary(cert), e);
            }
        }
    }

    private void validateUsage(X509Certificate[] chain, HandshakeRole role)
            throws CertificateValidationException {
        X509Certificate leaf = chain[0];
        // 终端证书不得是 CA
        if (leaf.getBasicConstraints() >= 0) {
            throw new CertificateValidationException(FailureReason.END_ENTITY_IS_CA,
                    "终端证书带有 CA 基本约束，不能用于身份认证: "
                            + CertificateValidationException.redactedSummary(leaf));
        }
        // 中间证书必须是 CA
        for (int i = 1; i < chain.length; i++) {
            if (chain[i].getBasicConstraints() < 0) {
                throw new CertificateValidationException(FailureReason.CHAIN_BASIC_CONSTRAINTS_INVALID,
                        "中间证书不具备 CA 基本约束: "
                                + CertificateValidationException.redactedSummary(chain[i]));
            }
        }
        // 扩展密钥用途必须与角色匹配
        String requiredEku = role == HandshakeRole.SERVER ? EKU_CLIENT_AUTH : EKU_SERVER_AUTH;
        try {
            List<String> ekus = leaf.getExtendedKeyUsage();
            if (ekus != null && !ekus.contains(requiredEku)) {
                throw new CertificateValidationException(FailureReason.ROLE_MISMATCH,
                        "证书扩展密钥用途与当前角色不匹配，缺少 " + requiredEku + ": "
                                + CertificateValidationException.redactedSummary(leaf));
            }
        } catch (java.security.cert.CertificateParsingException e) {
            throw new CertificateValidationException(FailureReason.VALIDATION_ERROR,
                    "解析证书扩展密钥用途失败", e);
        }
        // 密钥用途必须与角色匹配
        boolean[] keyUsage = leaf.getKeyUsage();
        if (keyUsage != null) {
            if (role == HandshakeRole.SERVER) {
                // 对端是客户端：需要 digitalSignature
                if (!keyUsage[0]) {
                    throw new CertificateValidationException(FailureReason.ROLE_MISMATCH,
                            "证书密钥用途不允许客户端身份(digitalSignature): "
                                    + CertificateValidationException.redactedSummary(leaf));
                }
            } else {
                // 对端是服务端：需要 digitalSignature 或 keyEncipherment
                if (!keyUsage[0] && !keyUsage[2]) {
                    throw new CertificateValidationException(FailureReason.ROLE_MISMATCH,
                            "证书密钥用途不允许服务端身份: "
                                    + CertificateValidationException.redactedSummary(leaf));
                }
            }
        }
    }

    private void validatePinning(X509Certificate leaf, PolicySnapshot snapshot)
            throws CertificateValidationException {
        String peer = commonName(leaf);
        Set<String> allowed = snapshot.pins().get(peer);
        if (allowed == null || allowed.isEmpty()) {
            throw new CertificateValidationException(FailureReason.PIN_NOT_CONFIGURED,
                    "未配置对端身份[" + peer + "]的公钥固定凭据");
        }
        String actual = HexFormat.of().formatHex(sha256(leaf.getPublicKey().getEncoded()));
        boolean matched = allowed.stream()
                .map(CertificateValidator::normalizeFingerprint)
                .anyMatch(actual::equalsIgnoreCase);
        if (!matched) {
            // 不泄露证书全部内容，只给出对端标识与原因
            throw new CertificateValidationException(FailureReason.PIN_MISMATCH,
                    "对端身份[" + peer + "]的公钥指纹与配置的固定凭据均不匹配");
        }
    }

    private void validateRevocation(X509Certificate[] chain, PolicySnapshot snapshot)
            throws CertificateValidationException {
        if (!snapshot.revocationDataAvailable()) {
            if (snapshot.revocationUnavailable() == RevocationPolicy.FAIL_CLOSED) {
                throw new CertificateValidationException(FailureReason.REVOCATION_DATA_UNAVAILABLE,
                        "吊销状态数据源不可用，策略为 fail-closed，拒绝握手");
            }
            // fail-open：数据源不可用时跳过吊销检查（放行）
            return;
        }
        Set<BigInteger> revoked = snapshot.revokedSerials();
        for (X509Certificate cert : chain) {
            if (revoked.contains(cert.getSerialNumber())) {
                throw new CertificateValidationException(FailureReason.CERT_REVOKED,
                        "证书已被吊销: " + CertificateValidationException.redactedSummary(cert));
            }
        }
    }

    private static byte[] sha256(byte[] data) throws CertificateValidationException {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new CertificateValidationException(FailureReason.VALIDATION_ERROR,
                    "计算公钥指纹失败", e);
        }
    }

    private static String normalizeFingerprint(String fp) {
        String v = fp.trim().toLowerCase();
        if (v.startsWith("sha256:")) {
            v = v.substring("sha256:".length());
        }
        return v;
    }

    /** 从证书主体的 CN 属性提取对端标识。 */
    static String commonName(X509Certificate cert) {
        String dn = cert.getSubjectX500Principal().getName(X500Principal.RFC2253);
        for (String part : splitRfc2253(dn)) {
            int idx = part.indexOf('=');
            if (idx > 0 && part.substring(0, idx).trim().equalsIgnoreCase("CN")) {
                return part.substring(idx + 1).trim();
            }
        }
        return dn;
    }

    /** 简单拆分 RFC2253 DN，处理转义逗号。 */
    private static List<String> splitRfc2253(String dn) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean escaped = false;
        for (int i = 0; i < dn.length(); i++) {
            char c = dn.charAt(i);
            if (escaped) {
                cur.append(c);
                escaped = false;
            } else if (c == '\\') {
                escaped = true;
                cur.append(c);
            } else if (c == ',') {
                parts.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        parts.add(cur.toString());
        return parts;
    }
}
