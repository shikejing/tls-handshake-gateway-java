package com.github.shikejing.tlshandshakegatewayjava.gateway;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.Locale;

/**
 * Public-key pin fingerprints: SHA-256 over the certificate's
 * SubjectPublicKeyInfo, hex-encoded lowercase.
 */
public final class Fingerprints {

    private Fingerprints() {
    }

    public static String sha256OfPublicKey(X509Certificate cert) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(cert.getPublicKey().getEncoded());
            StringBuilder sb = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                sb.append(Character.forDigit((b >> 4) & 0xF, 16));
                sb.append(Character.forDigit(b & 0xF, 16));
            }
            return sb.toString().toLowerCase(Locale.ROOT);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }
}
