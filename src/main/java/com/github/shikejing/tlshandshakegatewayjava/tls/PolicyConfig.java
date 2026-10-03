package com.github.shikejing.tlshandshakegatewayjava.tls;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 握手策略配置（不可变）。一次配置对应一个原子生效的策略快照。
 *
 * @param role                    本端角色
 * @param trustAnchors            信任锚（根证书）集合
 * @param pins                    公钥固定：对端标识(CN) -> 允许的 SPKI 指纹集合(sha256:hex)
 * @param pinningEnabled          是否启用公钥固定
 * @param revocationEnabled       是否启用吊销检查
 * @param revokedSerials          已吊销证书序列号（本地数据源）
 * @param revocationUnavailable  数据源不可用时的策略
 * @param revocationDataAvailable 吊销数据源是否可用
 * @param sessionResumptionEnabled 是否允许会话复用
 * @param identityKey              本端身份私钥
 * @param identityChain            本端身份证书链
 */
public record PolicyConfig(
        HandshakeRole role,
        PrivateKey identityKey,
        List<X509Certificate> identityChain,
        Set<X509Certificate> trustAnchors,
        Map<String, Set<String>> pins,
        boolean pinningEnabled,
        boolean revocationEnabled,
        Set<java.math.BigInteger> revokedSerials,
        RevocationPolicy revocationUnavailable,
        boolean revocationDataAvailable,
        boolean sessionResumptionEnabled) {

    public static Builder builder() {
        return new Builder();
    }

    public Builder toBuilder() {
        Builder b = new Builder();
        b.role = role;
        b.identityKey = identityKey;
        b.identityChain = identityChain;
        b.trustAnchors = trustAnchors;
        b.pins = pins;
        b.pinningEnabled = pinningEnabled;
        b.revocationEnabled = revocationEnabled;
        b.revokedSerials = revokedSerials;
        b.revocationUnavailable = revocationUnavailable;
        b.revocationDataAvailable = revocationDataAvailable;
        b.sessionResumptionEnabled = sessionResumptionEnabled;
        return b;
    }

    public static final class Builder {
        private HandshakeRole role = HandshakeRole.SERVER;
        private PrivateKey identityKey;
        private List<X509Certificate> identityChain = List.of();
        private Set<X509Certificate> trustAnchors = Set.of();
        private Map<String, Set<String>> pins = Map.of();
        private boolean pinningEnabled = true;
        private boolean revocationEnabled = true;
        private Set<java.math.BigInteger> revokedSerials = Set.of();
        private RevocationPolicy revocationUnavailable = RevocationPolicy.FAIL_CLOSED;
        private boolean revocationDataAvailable = true;
        private boolean sessionResumptionEnabled = true;

        public Builder role(HandshakeRole role) { this.role = role; return this; }
        public Builder identity(PrivateKey key, List<X509Certificate> chain) {
            this.identityKey = key;
            this.identityChain = chain;
            return this;
        }
        public Builder trustAnchors(Set<X509Certificate> v) { this.trustAnchors = v; return this; }
        public Builder pins(Map<String, Set<String>> v) { this.pins = v; return this; }
        public Builder pinningEnabled(boolean v) { this.pinningEnabled = v; return this; }
        public Builder revocationEnabled(boolean v) { this.revocationEnabled = v; return this; }
        public Builder revokedSerials(Set<java.math.BigInteger> v) { this.revokedSerials = v; return this; }
        public Builder revocationUnavailable(RevocationPolicy v) { this.revocationUnavailable = v; return this; }
        public Builder revocationDataAvailable(boolean v) { this.revocationDataAvailable = v; return this; }
        public Builder sessionResumptionEnabled(boolean v) { this.sessionResumptionEnabled = v; return this; }

        public PolicyConfig build() {
            return new PolicyConfig(role, identityKey, List.copyOf(identityChain), Set.copyOf(trustAnchors), Map.copyOf(pins),
                    pinningEnabled, revocationEnabled, Set.copyOf(revokedSerials),
                    revocationUnavailable, revocationDataAvailable, sessionResumptionEnabled);
        }
    }
}
