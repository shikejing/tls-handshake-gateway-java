package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 基于本地文件的吊销数据源。文件每行一个被吊销证书的序列号（十六进制，可带 0x 前缀），
 * 以 # 开头的行为注释。文件不可读时 {@link #isAvailable()} 返回 false，
 * 由策略决定 fail-open 或 fail-closed。
 */
public class FileRevocationDataSource implements RevocationDataSource {

    private static final Logger log = LoggerFactory.getLogger(FileRevocationDataSource.class);

    private final Path file;
    private volatile long lastLoadedMtime = -1L;
    private volatile Set<BigInteger> cached = Set.of();
    private volatile boolean available;

    public FileRevocationDataSource(Path file) {
        this.file = file;
    }

    @Override
    public Set<BigInteger> revokedSerials() {
        refreshIfNeeded();
        return cached;
    }

    @Override
    public boolean isAvailable() {
        refreshIfNeeded();
        return available;
    }

    /** 文件最后修改时间，供热更新轮询使用。 */
    public long lastModified() {
        try {
            return Files.getLastModifiedTime(file).toMillis();
        } catch (IOException e) {
            return -1L;
        }
    }

    private void refreshIfNeeded() {
        long mtime = lastModified();
        if (mtime == lastLoadedMtime && available) {
            return;
        }
        synchronized (this) {
            if (mtime == lastLoadedMtime && available) {
                return;
            }
            try {
                List<String> lines = Files.readAllLines(file);
                Set<BigInteger> serials = new HashSet<>();
                for (String line : lines) {
                    String trimmed = line.trim();
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                        continue;
                    }
                    String hex = trimmed.startsWith("0x") || trimmed.startsWith("0X")
                            ? trimmed.substring(2) : trimmed;
                    serials.add(new BigInteger(hex, 16));
                }
                cached = Set.copyOf(serials);
                available = true;
                lastLoadedMtime = mtime;
                log.debug("吊销数据源加载完成: {} 个序列号", serials.size());
            } catch (IOException | RuntimeException e) {
                available = false;
                log.warn("吊销数据源不可用: {} ({})", file, e.toString());
            }
        }
    }
}
