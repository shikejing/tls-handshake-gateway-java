package com.github.shikejing.tlshandshakegatewayjava.tls;

import java.security.cert.X509Certificate;

/**
 * 证书校验异常，携带失败原因码。
 * 注意：异常消息不包含证书完整内容，仅包含原因码与通用描述。
 */
public class CertificateValidationException extends Exception {

    private final FailureReason reason;

    public CertificateValidationException(FailureReason reason, String message) {
        super("[" + reason + "] " + message);
        this.reason = reason;
    }

    public CertificateValidationException(FailureReason reason, String message, Throwable cause) {
        super("[" + reason + "] " + message, cause);
        this.reason = reason;
    }

    public FailureReason getReason() {
        return reason;
    }

    /** 生成不泄露证书内容的摘要描述，用于日志与失败信息。 */
    public static String redactedSummary(X509Certificate cert) {
        if (cert == null) {
            return "<no-certificate>";
        }
        String cn = cert.getSubjectX500Principal() == null ? null : cert.getSubjectX500Principal().getName();
        return "subject=" + (cn == null ? "<unknown>" : cn)
                + ", serial=" + (cert.getSerialNumber() == null ? "<unknown>" : cert.getSerialNumber().toString(16))
                + ", notAfter=" + (cert.getNotAfter() == null ? "<unknown>" : cert.getNotAfter().toInstant());
    }
}
