package com.github.shikejing.tlshandshakegatewayjava.tls;

import java.math.BigInteger;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 策略管理器。以原子引用保存当前策略快照，
 * 配置更新（信任锚、固定凭据、吊销列表）对新建连接原子生效。
 * 已建立的连接与进行中的握手继续使用旧快照，不受更新影响。
 */
public class PolicyManager {

    private final AtomicReference<PolicySnapshot> current = new AtomicReference<>();
    private final List<Runnable> reloadListeners = new CopyOnWriteArrayList<>();
    private volatile long epoch = 0L;

    public PolicyManager(PolicyConfig initial) {
        this.current.set(PolicySnapshot.from(initial, epoch));
    }

    /** 返回当前生效的策略快照；握手开始时取一次，全程复用。 */
    public PolicySnapshot current() {
        return current.get();
    }

    /** 原子替换策略，对之后新建的连接生效。 */
    public void reload(PolicyConfig config) {
        long next = epoch + 1;
        current.set(PolicySnapshot.from(config, next));
        epoch = next;
        for (Runnable listener : reloadListeners) {
            try {
                listener.run();
            } catch (RuntimeException e) {
                // 单个监听器失败不影响策略替换
            }
        }
    }

    /** 注册策略更新监听器（用于重建 SSLContext 等）。 */
    public void addReloadListener(Runnable listener) {
        reloadListeners.add(listener);
    }

    /**
     * 仅原子更新吊销状态（吊销数据源文件变化时），其余策略不变。
     */
    public void updateRevocation(Set<BigInteger> serials, boolean available) {
        PolicySnapshot cur = current.get();
        long nextEpoch = epoch + 1;
        PolicySnapshot next = new PolicySnapshot(
                cur.role(), cur.identityKey(), cur.identityChain(),
                cur.trustAnchors(), cur.pins(), cur.pinningEnabled(),
                cur.revocationEnabled(), serials, cur.revocationUnavailable(),
                available, cur.sessionResumptionEnabled(), nextEpoch);
        current.set(next);
        epoch = nextEpoch;
    }

    public long epoch() {
        return epoch;
    }
}
