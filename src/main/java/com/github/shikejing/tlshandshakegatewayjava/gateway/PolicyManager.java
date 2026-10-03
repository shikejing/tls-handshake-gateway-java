package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds the currently effective {@link SecurityPolicy}. Updates are atomic:
 * a handshake captures one snapshot and uses it consistently, so it never
 * observes a half-old/half-new policy.
 */
public final class PolicyManager {

    private final AtomicReference<SecurityPolicy> current;

    public PolicyManager(SecurityPolicy initial) {
        this.current = new AtomicReference<>(Objects.requireNonNull(initial));
    }

    /** Snapshot of the policy effective right now. */
    public SecurityPolicy current() {
        return current.get();
    }

    /** Atomically replace the effective policy; applies to new handshakes only. */
    public void update(SecurityPolicy newPolicy) {
        current.set(Objects.requireNonNull(newPolicy));
    }
}
