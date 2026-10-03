package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Immutable snapshot of everything needed to verify a peer:
 * trust anchors, extra intermediates, public-key pins and revocation settings.
 * Instances are replaced wholesale by {@link PolicyManager} so an update is
 * atomic for new handshakes.
 */
public final class SecurityPolicy {

    private final Set<X509Certificate> trustAnchors;
    private final Set<X509Certificate> intermediates;
    private final Map<String, Set<String>> pinsByPeer;
    private final RevocationSource revocationSource;
    private final RevocationPolicy revocationPolicy;

    private SecurityPolicy(Builder builder) {
        this.trustAnchors = Set.copyOf(builder.trustAnchors);
        this.intermediates = Set.copyOf(builder.intermediates);
        this.pinsByPeer = Map.copyOf(builder.pinsByPeer);
        this.revocationSource = builder.revocationSource;
        this.revocationPolicy = builder.revocationPolicy;
    }

    public Set<X509Certificate> getTrustAnchors() {
        return trustAnchors;
    }

    public Set<X509Certificate> getIntermediates() {
        return intermediates;
    }

    /** @return acceptable SHA-256 fingerprints (hex, lowercase) for the named peer, or empty. */
    public Set<String> pinsFor(String peerName) {
        return pinsByPeer.getOrDefault(peerName, Set.of());
    }

    public RevocationSource getRevocationSource() {
        return revocationSource;
    }

    public RevocationPolicy getRevocationPolicy() {
        return revocationPolicy;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private Set<X509Certificate> trustAnchors = Set.of();
        private Set<X509Certificate> intermediates = Set.of();
        private Map<String, Set<String>> pinsByPeer = Map.of();
        private RevocationSource revocationSource;
        private RevocationPolicy revocationPolicy = RevocationPolicy.FAIL_CLOSED;

        public Builder trustAnchors(Set<X509Certificate> anchors) {
            this.trustAnchors = anchors;
            return this;
        }

        public Builder intermediates(Set<X509Certificate> intermediates) {
            this.intermediates = intermediates;
            return this;
        }

        public Builder pinsByPeer(Map<String, Set<String>> pinsByPeer) {
            this.pinsByPeer = pinsByPeer;
            return this;
        }

        public Builder revocationSource(RevocationSource source) {
            this.revocationSource = source;
            return this;
        }

        public Builder revocationPolicy(RevocationPolicy policy) {
            this.revocationPolicy = policy;
            return this;
        }

        public SecurityPolicy build() {
            return new SecurityPolicy(this);
        }
    }
}
