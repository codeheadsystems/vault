package com.codeheadsystems.vault.net

import com.codeheadsystems.vault.core.VaultCore
import java.net.InetAddress
import java.net.Socket
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.SSLSession
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/**
 * Accepts exactly the leaf certificate whose DER SHA-256 is `fp`, through `vault-core`'s pin check.
 * The chain, the name, and the validity dates are ignored (spec, Setup text).
 */
class PinnedTrustManager(private val core: VaultCore, private val fp: String) : X509TrustManager {
    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        val leaf = chain?.firstOrNull() ?: throw CertificateException("no certificate")
        if (!core.pinMatches(fp, leaf.encoded)) throw CertificateException("certificate does not match the pin")
    }

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) =
        throw CertificateException("no client certificates")

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

/** Checks the pin again on the session's peer certificate, instead of returning `true`. */
class PinnedHostnameVerifier(private val core: VaultCore, private val fp: String) : HostnameVerifier {
    override fun verify(hostname: String?, session: SSLSession?): Boolean {
        val leaf = try {
            session?.peerCertificates?.firstOrNull() as? X509Certificate
        } catch (_: Exception) {
            null
        } ?: return false
        return core.pinMatches(fp, leaf.encoded)
    }
}

/** Enables TLS 1.3 and 1.2 only on every socket it creates. */
class ModernTlsSocketFactory(private val delegate: SSLSocketFactory) : SSLSocketFactory() {
    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean) = restrict(delegate.createSocket(s, host, port, autoClose))
    override fun createSocket(host: String?, port: Int) = restrict(delegate.createSocket(host, port))
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int) =
        restrict(delegate.createSocket(host, port, localHost, localPort))
    override fun createSocket(host: InetAddress?, port: Int) = restrict(delegate.createSocket(host, port))
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int) =
        restrict(delegate.createSocket(address, port, localAddress, localPort))

    private fun restrict(socket: Socket): Socket {
        if (socket is SSLSocket) {
            val enabled = allowedProtocols(socket.supportedProtocols)
            if (enabled.isEmpty()) throw javax.net.ssl.SSLHandshakeException("no TLS 1.2 or later")
            socket.enabledProtocols = enabled
        }
        return socket
    }

    companion object {
        private val ALLOWED = listOf("TLSv1.3", "TLSv1.2")

        /** The protocols to enable: TLS 1.3 and 1.2, of those the socket supports. */
        fun allowedProtocols(supported: Array<String>): Array<String> = ALLOWED.filter { it in supported }.toTypedArray()
    }
}
