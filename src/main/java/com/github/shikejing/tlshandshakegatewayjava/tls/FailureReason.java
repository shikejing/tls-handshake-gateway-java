package com.github.shikejing.tlshandshakegatewayjava.tls;

/**
 * 证书校验失败原因码。每个原因码对应一种可区分的拒绝理由，
 * 失败信息中只包含原因码与面向运维的描述，不泄露证书全部内容。
 */
public enum FailureReason {
    /** 证书链缺少中间证书，无法构建到信任锚的路径。 */
    CHAIN_MISSING_INTERMEDIATE,
    /** 证书链终结于不受信的根证书。 */
    CHAIN_UNTRUSTED_ROOT,
    /** 链中某张证书的签名无法用其颁发者公钥验证。 */
    SIGNATURE_INVALID,
    /** 证书已过有效期。 */
    CERT_EXPIRED,
    /** 证书尚未生效。 */
    CERT_NOT_YET_VALID,
    /** 证书用途（EKU/KeyUsage/BasicConstraints）与当前角色不匹配。 */
    ROLE_MISMATCH,
    /** 终端证书错误地带有 CA 身份。 */
    END_ENTITY_IS_CA,
    /** 链中非终端证书不具备 CA 身份，违反基本约束。 */
    CHAIN_BASIC_CONSTRAINTS_INVALID,
    /** 公钥固定校验失败：对端公钥指纹不在允许集合内。 */
    PIN_MISMATCH,
    /** 未配置任何固定凭据，而固定校验处于启用状态。 */
    PIN_NOT_CONFIGURED,
    /** 证书已被吊销。 */
    CERT_REVOKED,
    /** 吊销状态数据源不可用，且策略为拒绝。 */
    REVOCATION_DATA_UNAVAILABLE,
    /** 对端未提供证书。 */
    NO_PEER_CERTIFICATE,
    /** 其他校验异常。 */
    VALIDATION_ERROR
}
