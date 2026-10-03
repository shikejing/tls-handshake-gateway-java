package com.github.shikejing.tlshandshakegatewayjava.tls;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.HexFormat;

/**
 * 测试用证书工厂：生成根 CA、中间 CA 以及各种异常场景的终端证书。
 */
public final class TestCertificates {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /** 终端证书套件：密钥对 + 证书 + 链（叶子在前）。 */
    public static final class Bundle {
        public final KeyPair keyPair;
        public final X509Certificate cert;
        public final X509Certificate[] chain;

        Bundle(KeyPair keyPair, X509Certificate cert, X509Certificate[] chain) {
            this.keyPair = keyPair;
            this.cert = cert;
            this.chain = chain;
        }
    }

    public final X509Certificate rootCa;
    public final KeyPair rootKey;
    public final X509Certificate intermediateCa;
    public final KeyPair intermediateKey;
    /** 另一把中间 CA 密钥，用于构造签名无法验证的链。 */
    public final X509Certificate intermediate2Ca;
    public final KeyPair intermediate2Key;

    public final Bundle server;
    public final Bundle client;
    /** 同一 CN 的轮换密钥对。 */
    public final Bundle clientRotated;
    public final Bundle clientExpired;
    public final Bundle clientNotYetValid;
    /** EKU 仅含 serverAuth 的客户端证书。 */
    public final Bundle clientServerAuthOnly;
    /** EKU 仅含 clientAuth 的服务端证书。 */
    public final Bundle serverClientAuthOnly;
    /** 终端证书带 CA 基本约束。 */
    public final Bundle clientCaLeaf;
    /** 密钥用途仅 keyEncipherment 的客户端证书。 */
    public final Bundle clientKeyUsageWrong;
    /** 密钥用途仅 digitalSignature 的服务端证书。 */
    public final Bundle serverKeyUsageWrong;
    public final Bundle clientRevoked;
    /** 自签名、不受信的客户端证书。 */
    public final Bundle clientSelfSigned;
    /** 用中间 CA2 签名、却搭配中间 CA1 证书的客户端链（签名无效）。 */
    public final Bundle clientSignedByIntermediate2;

    private long serialSeq = 1000;

    public TestCertificates() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
        kpg.initialize(2048);

        rootKey = kpg.generateKeyPair();
        intermediateKey = kpg.generateKeyPair();
        intermediate2Key = kpg.generateKeyPair();

        rootCa = buildCa(rootKey, rootKey, "CN=Test Root CA,O=Test", null,
                Duration.ofDays(3650), BigInteger.valueOf(1));
        intermediateCa = buildCa(intermediateKey, rootKey, "CN=Test Intermediate CA,O=Test",
                rootCa, Duration.ofDays(3650), BigInteger.valueOf(2));
        intermediate2Ca = buildCa(intermediate2Key, rootKey, "CN=Test Intermediate CA2,O=Test",
                rootCa, Duration.ofDays(3650), BigInteger.valueOf(3));

        server = leaf("CN=localhost,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_serverAuth, KeyUsage.digitalSignature | KeyUsage.keyEncipherment,
                Duration.ofDays(365), false);
        client = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), false);
        clientRotated = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), false);
        clientExpired = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), false, Instant.now().minus(Duration.ofDays(400)),
                Instant.now().minus(Duration.ofDays(10)));
        clientNotYetValid = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), false, Instant.now().plus(Duration.ofDays(10)),
                Instant.now().plus(Duration.ofDays(400)));
        clientServerAuthOnly = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_serverAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), false);
        serverClientAuthOnly = leaf("CN=localhost,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature | KeyUsage.keyEncipherment,
                Duration.ofDays(365), false);
        clientCaLeaf = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), true);
        clientKeyUsageWrong = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.keyEncipherment,
                Duration.ofDays(365), false);
        serverKeyUsageWrong = leaf("CN=localhost,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_serverAuth, KeyUsage.keyCertSign,
                Duration.ofDays(365), false);
        clientRevoked = leaf("CN=internal-client,O=Test", intermediateKey, intermediateCa,
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), false);
        clientSelfSigned = selfSignedLeaf("CN=internal-client,O=Test",
                KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature, Duration.ofDays(365));
        clientSignedByIntermediate2 = leaf("CN=internal-client,O=Test", intermediate2Key,
                intermediateCa, KeyPurposeId.id_kp_clientAuth, KeyUsage.digitalSignature,
                Duration.ofDays(365), false);
    }

    private X509Certificate buildCa(KeyPair subject, KeyPair issuer, String subjectDn,
                                     X509Certificate issuerCert, Duration validity, BigInteger serial)
            throws Exception {
        Instant now = Instant.now();
        X500Principal subjectName = new X500Principal(subjectDn);
        X500Principal issuerName = issuerCert == null ? subjectName
                : issuerCert.getSubjectX500Principal();
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(subject.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, serial,
                Date.from(now.minus(Duration.ofDays(1))),
                Date.from(now.plus(validity)),
                subjectName, subject.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(0));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(pubInfo.getPublicKeyData().getBytes()));
        if (issuerCert != null) {
            builder.addExtension(Extension.authorityKeyIdentifier, false,
                    new AuthorityKeyIdentifier(
                            SubjectPublicKeyInfo.getInstance(issuer.getPublic().getEncoded())));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                .build(issuer.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    private Bundle leaf(String dn, KeyPair issuerKey, X509Certificate issuerCert,
                        KeyPurposeId eku, int keyUsage, Duration validity, boolean ca)
            throws Exception {
        return leaf(dn, issuerKey, issuerCert, eku, keyUsage, validity, ca,
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(validity));
    }

    private Bundle leaf(String dn, KeyPair issuerKey, X509Certificate issuerCert,
                        KeyPurposeId eku, int keyUsage, Duration validity, boolean ca,
                        Instant notBefore, Instant notAfter) throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X500Principal subjectName = new X500Principal(dn);
        X500Principal issuerName = issuerCert.getSubjectX500Principal();
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuerName, BigInteger.valueOf(serialSeq++),
                Date.from(notBefore), Date.from(notAfter),
                subjectName, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(pubInfo.getPublicKeyData().getBytes()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                new AuthorityKeyIdentifier(
                        SubjectPublicKeyInfo.getInstance(issuerKey.getPublic().getEncoded())));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                .build(issuerKey.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(holder);
        return new Bundle(pair, cert, new X509Certificate[]{cert, issuerCert});
    }

    private Bundle selfSignedLeaf(String dn, KeyPurposeId eku, int keyUsage, Duration validity)
            throws Exception {
        KeyPair pair = KeyPairGenerator.getInstance("RSA", "BC").generateKeyPair();
        X500Principal subjectName = new X500Principal(dn);
        SubjectPublicKeyInfo pubInfo = SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded());
        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subjectName, BigInteger.valueOf(serialSeq++),
                Date.from(Instant.now().minus(Duration.ofDays(1))),
                Date.from(Instant.now().plus(validity)),
                subjectName, pair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        builder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(eku));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                new SubjectKeyIdentifier(pubInfo.getPublicKeyData().getBytes()));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC")
                .build(pair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(holder);
        return new Bundle(pair, cert, new X509Certificate[]{cert});
    }

    /** 计算证书公钥的 SPKI SHA-256 指纹。 */
    public static String fingerprint(X509Certificate cert) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(cert.getPublicKey().getEncoded());
            return "sha256:" + HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
