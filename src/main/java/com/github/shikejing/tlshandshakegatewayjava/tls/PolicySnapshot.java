package com.github.shikejing.tlshandshakegatewayjava.tls;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 不可变策略快照。一次握手从开始到结束始终使用同一个快照，
 * 因此进行中的握手不会处于“半新半旧”的策略之下。
 */
public record PolicySnapshot(
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
        boolean sessionResumptionEnabled,
        long epoch) {

    public static PolicySnapshot from(PolicyConfig config, long epoch) {
        return new PolicySnapshot(
                config.role(),
                config.identityKey(),
                config.identityChain(),
                config.trustAnchors(),
                config.pins(),
                config.pinningEnabled(),
                config.revocationEnabled(),
                config.revokedSerials(),
                config.revocationUnavailable(),
                config.revocationDataAvailable(),
                config.sessionResumptionEnabled(),
                epoch);
    }
}
