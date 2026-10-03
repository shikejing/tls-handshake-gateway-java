package com.github.shikejing.tlshandshakegatewayjava.gateway;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Trust manager that delegates to {@link PeerVerifier} using the policy
 * snapshot effective at the moment of the check. The peer name used for pin
 * lookup is bound per connection via {@link #forPeer(String)}.
 *
 * <p>Stateless apart from the final configuration fields, hence thread-safe.</p>
 */
public final class GatewayTrustManager extends X509ExtendedTrustManager {

    private final PolicyManager policyManager;
    private final String peerName;

    public GatewayTrustManager(PolicyManager policyManager, String peerName) {
        this.policyManager = policyManager;
        this.peerName = peerName;
    }

    /** Return a trust manager identical to this one but pinning against another peer name. */
    public GatewayTrustManager forPeer(String newPeerName) {
        return new GatewayTrustManager(policyManager, newPeerName);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        verifyAsServer(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        verifyAsServer(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        verifyAsServer(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        verifyAsClient(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        verifyAsClient(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        verifyAsClient(chain);
    }

    /** We are the server: the remote peer must authenticate as a client. */
    private void verifyAsServer(X509Certificate[] chain) throws CertificateException {
        new PeerVerifier(policyManager.current(), PeerRole.SERVER).verify(chain, peerName);
    }

    /** We are the client: the remote peer must authenticate as a server. */
    private void verifyAsClient(X509Certificate[] chain) throws CertificateException {
        new PeerVerifier(policyManager.current(), PeerRole.CLIENT).verify(chain, peerName);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return policyManager.current().getTrustAnchors().toArray(new X509Certificate[0]);
    }
}
