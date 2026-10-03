package com.github.shikejing.tlshandshakegatewayjava.gateway;

/**
 * Role of the local peer during a handshake. Determines which end-entity
 * certificate usage is required from the remote peer.
 */
public enum PeerRole {
    /** We act as the TLS server; the remote peer must present a client certificate. */
    SERVER,
    /** We act as the TLS client; the remote peer must present a server certificate. */
    CLIENT
}
