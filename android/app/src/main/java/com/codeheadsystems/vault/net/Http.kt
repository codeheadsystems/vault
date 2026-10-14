package com.codeheadsystems.vault.net

import com.codeheadsystems.vault.core.VaultCore
import java.net.HttpURLConnection
import java.security.KeyStore
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.TrustManagerFactory

/** A response: the status, the server's `Date` in ms (0 when absent), and the body. */
class HttpResponse(val code: Int, val dateMs: Long, val etag: String?, val body: ByteArray)

/**
 * `HttpsURLConnection` transport (docs/android.md, Transport): redirects off, caches off, TLS 1.2
 * or later, and with `fp` the pinned trust manager and hostname verifier; without `fp`, the system
 * authorities that the network security configuration allows. [debug] is `BuildConfig.DEBUG`.
 */
class Http(private val core: VaultCore, private val debug: Boolean) {

    fun request(
        method: String,
        url: String,
        token: String,
        fp: String?,
        headers: Map<String, String> = emptyMap(),
        body: ByteArray? = null,
    ): HttpResponse {
        val target = TransportRules.target(url, debug)
        val conn = target.toURL().openConnection() as HttpURLConnection
        conn.instanceFollowRedirects = false
        conn.useCaches = false
        conn.connectTimeout = TIMEOUT_MS
        conn.readTimeout = TIMEOUT_MS
        conn.requestMethod = method
        if (conn is HttpsURLConnection) {
            val trust: Array<TrustManager> = if (fp != null) {
                arrayOf(PinnedTrustManager(core, fp))
            } else {
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
                    .apply { init(null as KeyStore?) }.trustManagers
            }
            val ctx = SSLContext.getInstance("TLS").apply { init(null, trust, null) }
            conn.sslSocketFactory = ModernTlsSocketFactory(ctx.socketFactory)
            if (fp != null) conn.hostnameVerifier = PinnedHostnameVerifier(core, fp)
        }
        conn.setRequestProperty("Authorization", "Bearer $token")
        conn.setRequestProperty("Cache-Control", "no-store")
        headers.forEach { (k, v) -> conn.setRequestProperty(k, v) }
        try {
            if (body != null) {
                conn.doOutput = true
                conn.setFixedLengthStreamingMode(body.size)
                conn.outputStream.use { it.write(body) }
            }
            val code = conn.responseCode
            val stream = if (code < 400) conn.inputStream else conn.errorStream
            val bytes = stream?.use { it.readBytes() } ?: ByteArray(0)
            return HttpResponse(code, conn.getHeaderFieldDate("Date", 0L), conn.getHeaderField("ETag"), bytes)
        } finally {
            conn.disconnect()
        }
    }

    private companion object {
        const val TIMEOUT_MS = 30_000
    }
}
