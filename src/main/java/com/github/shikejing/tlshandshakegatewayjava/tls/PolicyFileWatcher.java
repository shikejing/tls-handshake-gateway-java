package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 策略文件热更新轮询器：
 * <ul>
 *   <li>策略文件变化 → 重新加载完整策略并原子替换；</li>
 *   <li>仅吊销数据文件变化 → 原子更新吊销序列号集合，其余策略不变。</li>
 * </ul>
 * 更新对之后新建的连接生效，进行中的握手与已建立连接不受影响。
 */
public class PolicyFileWatcher {

    private static final Logger log = LoggerFactory.getLogger(PolicyFileWatcher.class);

    private final PolicyManager manager;
    private final PolicyFileLoader loader;
    private final Path revocationFile;
    private final Duration interval;

    private ScheduledExecutorService executor;
    private volatile long policyMtime = -1L;
    private volatile long revocationMtime = -1L;

    public PolicyFileWatcher(PolicyManager manager, PolicyFileLoader loader,
                             Path revocationFile, Duration interval) {
        this.manager = manager;
        this.loader = loader;
        this.revocationFile = revocationFile;
        this.interval = interval;
    }

    public void start() {
        policyMtime = mtime(loader.getFile());
        revocationMtime = revocationFile == null ? -1L : mtime(revocationFile);
        executor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "tls-policy-watcher");
            t.setDaemon(true);
            return t;
        });
        executor.scheduleWithFixedDelay(this::tick, interval.toMillis(), interval.toMillis(),
                TimeUnit.MILLISECONDS);
    }

    public void stop() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    private void tick() {
        try {
            long newPolicyMtime = mtime(loader.getFile());
            if (newPolicyMtime != policyMtime) {
                log.info("检测到策略文件变化，重新加载: {}", loader.getFile());
                manager.reload(loader.load());
                policyMtime = newPolicyMtime;
                if (revocationFile != null) {
                    revocationMtime = mtime(revocationFile);
                }
                log.info("策略热更新完成，当前 epoch={}", manager.epoch());
                return;
            }
            if (revocationFile != null) {
                long newRevMtime = mtime(revocationFile);
                if (newRevMtime != revocationMtime) {
                    log.info("检测到吊销数据文件变化，重新加载吊销状态");
                    FileRevocationDataSource ds = new FileRevocationDataSource(revocationFile);
                    manager.updateRevocation(ds.revokedSerials(), ds.isAvailable());
                    revocationMtime = newRevMtime;
                }
            }
        } catch (RuntimeException e) {
            log.warn("策略热更新失败，沿用旧策略: {}", e.toString());
        }
    }

    private static long mtime(Path path) {
        try {
            return Files.getLastModifiedTime(path).toMillis();
        } catch (Exception e) {
            return -1L;
        }
    }
}
