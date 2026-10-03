package com.github.shikejing.tlshandshakegatewayjava.tls;

/**
 * 吊销状态数据源不可用时的处理策略。
 */
public enum RevocationPolicy {
    /** 数据源不可用时拒绝所有握手（更安全，可用性下降）。 */
    FAIL_CLOSED,
    /** 数据源不可用时放行（可用性优先，被吊销证书可能蒙混过关）。 */
    FAIL_OPEN
}
