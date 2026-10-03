package com.github.shikejing.tlshandshakegatewayjava.gateway;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

/**
 * Generates an in-memory PKI for tests: root CA, intermediate CA and
 * end-entity certificates with configurable usage/validity.
 */
final class TestPki {

    static final class Ca {
        final X509Certificate cert;
        final PrivateKey key;
        final KeyPair keyPair;

        Ca(X509Certificate cert, KeyPair keyPair) {
            this.cert = cert;
            this.key = keyPair.getPrivate();
            this.keyPair = keyPair;
        }
    }

    static final class Leaf {
        final X509Certificate cert;
        final PrivateKey key;
        final BigInteger serial;

        Leaf(X509Certificate cert, PrivateKey key, BigInteger serial) {
            this.cert = cert;
            this.key = key;
            this.serial = serial;
        }

        Identity identityWith(List<X509Certificate> chainTail) {
            java.util.List<X509Certificate> chain = new java.util.ArrayList<>();
            chain.add(cert);
            chain.addAll(chainTail);
            return new Identity(key, chain);
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    static KeyPair generateKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static Ca selfSignedCa(String cn) {
        return selfSignedCa(cn, Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(365, ChronoUnit.DAYS));
    }

    static Ca selfSignedCa(String cn, Instant notBefore, Instant notAfter) {
        KeyPair kp = generateKeyPair();
        X509Certificate cert = build(cn, "CN=" + cn, kp.getPublic(), kp.getPrivate(),
                true, null, null, notBefore, notAfter, nextSerial());
        return new Ca(cert, kp);
    }

    static Ca intermediateCa(String cn, Ca issuer) {
        KeyPair kp = generateKeyPair();
        X509Certificate cert = build(cn, issuer.cert.getSubjectX500Principal().getName(),
                kp.getPublic(), issuer.key, true, null, null,
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(365, ChronoUnit.DAYS), nextSerial());
        return new Ca(cert, kp);
    }

    static Leaf leaf(String cn, Ca issuer, KeyPurposeId eku) {
        return leaf(cn, issuer, eku, Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(365, ChronoUnit.DAYS),
                KeyUsage.digitalSignature, nextSerial());
    }

    static Leaf leaf(String cn, Ca issuer, KeyPurposeId eku, Instant notBefore, Instant notAfter,
                     int keyUsageBits, BigInteger serial) {
        KeyPair kp = generateKeyPair();
        X509Certificate cert = build(cn, issuer.cert.getSubjectX500Principal().getName(),
                kp.getPublic(), issuer.key, false, eku, keyUsageBits,
                notBefore, notAfter, serial);
        return new Leaf(cert, kp.getPrivate(), serial);
    }

    /**
     * Leaf whose issuer field names {@code claimedIssuer} but which is actually
     * signed with {@code actualSignerKey}: produces a signature that cannot verify.
     */
    static Leaf leafWithBadSignature(String cn, Ca claimedIssuer, PrivateKey actualSignerKey,
                                     KeyPurposeId eku) {
        KeyPair kp = generateKeyPair();
        X509Certificate cert = build(cn, claimedIssuer.cert.getSubjectX500Principal().getName(),
                kp.getPublic(), actualSignerKey, false, eku, KeyUsage.digitalSignature,
                Instant.now().minus(1, ChronoUnit.HOURS),
                Instant.now().plus(365, ChronoUnit.DAYS), nextSerial());
        return new Leaf(cert, kp.getPrivate(), nextSerial());
    }

    private static BigInteger nextSerial() {
        return new BigInteger(64, RANDOM).abs();
    }

    private static X509Certificate build(String subjectCn, String issuerDn,
                                         java.security.PublicKey subjectKey,
                                         PrivateKey signerKey, boolean ca,
                                         KeyPurposeId eku, Integer keyUsageBits,
                                         Instant notBefore, Instant notAfter, BigInteger serial) {
        try {
            X500Name subject = new X500Name("CN=" + subjectCn);
            X500Name issuerName = new X500Name(issuerDn);
            X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                    issuerName, serial, Date.from(notBefore), Date.from(notAfter),
                    subject, subjectKey);
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
            int ku = keyUsageBits != null ? keyUsageBits
                    : (ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature);
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(ku));
            if (eku != null) {
                builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
            }
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signerKey);
            return new JcaX509CertificateConverter()
                    .getCertificate(builder.build(signer));
        } catch (Exception e) {
            throw new IllegalStateException("cannot build certificate", e);
        }
    }
}
