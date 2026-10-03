package com.github.shikejing.tlshandshakegatewayjava.gateway;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileRevocationSourceTest {

    @TempDir
    Path dir;

    private static TestPki.Leaf leafWithSerial(BigInteger serial) {
        TestPki.Ca root = TestPki.selfSignedCa("rev-root");
        return TestPki.leaf("leaf", root, KeyPurposeId.id_kp_serverAuth,
                Instant.now().minus(1, ChronoUnit.HOURS), Instant.now().plus(1, ChronoUnit.DAYS),
                KeyUsage.digitalSignature, serial);
    }

    @Test
    void missingFileIsUnavailable() {
        FileRevocationSource source = new FileRevocationSource(dir.resolve("nope.txt"));
        assertThrows(RevocationUnavailableException.class,
                () -> source.isRevoked(leafWithSerial(new BigInteger("1")).cert));
    }

    @Test
    void revokedSerialIsDetected() throws Exception {
        Path file = dir.resolve("revoked.txt");
        TestPki.Leaf revoked = leafWithSerial(new BigInteger("abcd", 16));
        TestPki.Leaf fine = leafWithSerial(new BigInteger("1234", 16));
        Files.writeString(file, "# comment\n\nABCD\n");
        FileRevocationSource source = new FileRevocationSource(file);
        assertTrue(source.isRevoked(revoked.cert));
        assertFalse(source.isRevoked(fine.cert));
    }

    @Test
    void fileChangesArePickedUp() throws Exception {
        Path file = dir.resolve("revoked.txt");
        TestPki.Leaf leaf = leafWithSerial(new BigInteger("42", 16));
        Files.writeString(file, "# empty\n");
        FileRevocationSource source = new FileRevocationSource(file);
        assertFalse(source.isRevoked(leaf.cert));

        // mtime resolution can be coarse; ensure a visible change.
        Files.writeString(file, "42\n");
        Files.setLastModifiedTime(file,
                java.nio.file.attribute.FileTime.from(Instant.now().plusSeconds(5)));
        assertTrue(source.isRevoked(leaf.cert));
    }
}
