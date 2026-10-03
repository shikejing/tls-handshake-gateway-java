package com.github.shikejing.tlshandshakegatewayjava.tls;

import java.math.BigInteger;
import java.util.Set;

/**
 * 吊销状态本地数据源。
 */
public interface RevocationDataSource {

    /** 返回当前已吊销证书的序列号集合。 */
    Set<BigInteger> revokedSerials();

    /** 数据源是否可用（文件可读、解析正常）。 */
    boolean isAvailable();
}
