package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Revocation source backed by a local file containing revoked certificate
 * serial numbers (hex, one per line, '#' comments allowed). The file is
 * re-read when its modification time changes; a missing or unreadable file
 * raises {@link RevocationUnavailableException} so the configured
 * {@link RevocationPolicy} decides the outcome.
 *
 * <p>Thread-safe: the cached snapshot is held in a volatile reference and
 * reloads are serialized; concurrent checks never observe a partial file.</p>
 */
public final class FileRevocationSource implements RevocationSource {

    private final Path file;
    private volatile Snapshot snapshot = new Snapshot(null, Set.of());

    public FileRevocationSource(Path file) {
        this.file = file.toAbsolutePath();
    }

    @Override
    public boolean isRevoked(X509Certificate cert) throws RevocationUnavailableException {
        return load().serials.contains(normalize(cert.getSerialNumber()));
    }

    private Snapshot load() throws RevocationUnavailableException {
        FileTime mtime;
        try {
            mtime = Files.getLastModifiedTime(file);
        } catch (IOException e) {
            throw new RevocationUnavailableException("revocation file not readable: " + file, e);
        }
        Snapshot current = snapshot;
        if (current.mtime != null && current.mtime.equals(mtime)) {
            return current;
        }
        synchronized (this) {
            current = snapshot;
            if (current.mtime != null && current.mtime.equals(mtime)) {
                return current;
            }
            Snapshot fresh = new Snapshot(mtime, readSerials());
            snapshot = fresh;
            return fresh;
        }
    }

    private Set<String> readSerials() throws RevocationUnavailableException {
        try {
            Set<String> serials = new HashSet<>();
            for (String line : Files.readAllLines(file)) {
                String trimmed = line.strip();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                serials.add(normalize(new BigInteger(trimmed, 16)));
            }
            return Set.copyOf(serials);
        } catch (IOException | NumberFormatException e) {
            throw new RevocationUnavailableException("revocation file unreadable: " + file, e);
        }
    }

    private static String normalize(BigInteger serial) {
        return serial.toString(16).toLowerCase(Locale.ROOT);
    }

    private record Snapshot(FileTime mtime, Set<String> serials) {
    }
}
