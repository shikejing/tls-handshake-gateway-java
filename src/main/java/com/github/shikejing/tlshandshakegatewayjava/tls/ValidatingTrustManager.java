package com.github.shikejing.tlshandshakegatewayjava.tls;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * 自定义 TrustManager：在握手阶段调用 {@link CertificateValidator} 完成校验。
 * 每次握手通过 {@link ThreadLocal} 绑定本次使用的策略快照，
 * 从而支持高并发下不同连接使用不同快照、互不污染。
 *
 * <p>校验失败时不直接抛出 TLS 异常（TLS alert 无法携带具体原因码），
 * 而是将失败记录在 {@link ThreadLocal} 中，由握手后的应用级结果协议
 * 将可区分的失败原因发送给对端，再关闭连接。
 */
public class ValidatingTrustManager implements X509TrustManager {

    /** 本次握手使用的策略快照，由握手发起线程在 startHandshake 前绑定。 */
    static final ThreadLocal<PolicySnapshot> CURRENT = new ThreadLocal<>();

    /** 本次握手记录的校验失败（TM 不抛出，交由应用级结果协议处理）。 */
    private static final ThreadLocal<CertificateValidationException> RECORDED_FAILURE =
            new ThreadLocal<>();

    private final CertificateValidator validator = new CertificateValidator();

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        check(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        check(chain);
    }

    private void check(X509Certificate[] chain) {
        PolicySnapshot snapshot = CURRENT.get();
        if (snapshot == null) {
            RECORDED_FAILURE.set(new CertificateValidationException(
                    FailureReason.VALIDATION_ERROR, "未绑定本次握手的策略快照"));
            return;
        }
        try {
            validator.validate(chain, snapshot.role(), snapshot);
        } catch (CertificateValidationException e) {
            RECORDED_FAILURE.set(e);
        }
    }

    /** 取走本次握手记录的失败，无失败返回 null。 */
    static CertificateValidationException takeRecordedFailure() {
        CertificateValidationException e = RECORDED_FAILURE.get();
        RECORDED_FAILURE.remove();
        return e;
    }

    static void clearRecordedFailure() {
        RECORDED_FAILURE.remove();
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        PolicySnapshot snapshot = CURRENT.get();
        if (snapshot == null) {
            return new X509Certificate[0];
        }
        return snapshot.trustAnchors().toArray(new X509Certificate[0]);
    }
}
