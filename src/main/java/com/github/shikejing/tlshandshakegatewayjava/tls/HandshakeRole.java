package com.github.shikejing.tlshandshakegatewayjava.tls;

/**
 * 握手通道中的角色。
 */
public enum HandshakeRole {
    /** 服务端：校验对端是否具备合法的客户端身份。 */
    SERVER,
    /** 客户端：校验对端是否具备合法的服务端身份。 */
    CLIENT
}
