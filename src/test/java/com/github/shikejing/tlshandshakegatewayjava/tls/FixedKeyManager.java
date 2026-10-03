package com.github.shikejing.tlshandshakegatewayjava.tls;

import javax.net.ssl.X509KeyManager;
import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * 测试用 KeyManager：忽略服务端的可接受 CA 列表，始终出示配置的证书链，
 * 用于模拟发送残缺链/异常链的对端，以验证服务端的证书链校验逻辑。
 */
final class FixedKeyManager implements X509KeyManager {

    private final String alias;
    private final PrivateKey privateKey;
    private final X509Certificate[] chain;

    FixedKeyManager(String alias, PrivateKey privateKey, X509Certificate[] chain) {
        this.alias = alias;
        this.privateKey = privateKey;
        this.chain = chain == null ? new X509Certificate[0] : chain.clone();
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[]{alias};
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[]{alias};
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        return alias;
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        return chain.clone();
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
        return privateKey;
    }
}
