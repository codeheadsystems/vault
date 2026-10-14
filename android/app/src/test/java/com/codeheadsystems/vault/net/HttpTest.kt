package com.codeheadsystems.vault.net

import com.codeheadsystems.vault.FakeCore
import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.io.IOException
import java.net.InetSocketAddress
import java.security.KeyStore
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/** [Http.request] against a local TLS server with a self-signed certificate for another name. */
class HttpTest {
    private lateinit var server: HttpsServer
    private lateinit var fp: String
    private var base = ""
    private val seen = mutableListOf<String>()

    @Before
    fun start() {
        val ks = KeyStore.getInstance("PKCS12")
        javaClass.getResourceAsStream("/tls/server.p12")!!.use { ks.load(it, "testpass".toCharArray()) }
        val cert = ks.getCertificate("server") as X509Certificate
        fp = MessageDigest.getInstance("SHA-256").digest(cert.encoded).joinToString("") { "%02x".format(it) }
        val kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(ks, "testpass".toCharArray()) }
        val ctx = SSLContext.getInstance("TLS").apply { init(kmf.keyManagers, null, null) }
        server = HttpsServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.httpsConfigurator = HttpsConfigurator(ctx)
        server.createContext("/v1/vault") { ex ->
            seen += "${ex.requestMethod} ${ex.requestURI} ${ex.requestHeaders.getFirst("Authorization")} ${ex.requestHeaders.getFirst("If-Match")}"
            val body = "vault".toByteArray()
            ex.responseHeaders.add("ETag", "\"abc\"")
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        server.createContext("/redirect") { ex ->
            seen += "redirect"
            ex.responseHeaders.add("Location", "$base/v1/vault")
            ex.sendResponseHeaders(302, -1)
            ex.close()
        }
        server.start()
        base = "https://127.0.0.1:${server.address.port}"
    }

    @After
    fun stop() = server.stop(0)

    private val http = Http(FakeCore(), debug = false)

    @Test
    fun thePinnedCertificateIsAcceptedWhateverItsName() {
        val r = http.request("PUT", "$base/v1/vault", "TOKEN", fp, mapOf("If-Match" to "\"x\""), "body".toByteArray())
        assertEquals(200, r.code)
        assertEquals("vault", String(r.body))
        assertEquals("\"abc\"", r.etag)
        // The server's Date header, parsed: the JDK server sets it to the current time.
        assertTrue("${r.dateMs}", kotlin.math.abs(System.currentTimeMillis() - r.dateMs) < 60_000)
        assertEquals(listOf("PUT /v1/vault Bearer TOKEN \"x\""), seen)
    }

    @Test
    fun anotherPinNeverConnects() {
        assertThrows(IOException::class.java) { http.request("GET", "$base/v1/vault", "TOKEN", "00".repeat(32)) }
        assertTrue("the server saw no request", seen.isEmpty())
    }

    @Test
    fun withoutAPinTheSelfSignedCertificateIsRefused() {
        assertThrows(IOException::class.java) { http.request("GET", "$base/v1/vault", "TOKEN", null) }
    }

    @Test
    fun aRedirectIsNotFollowed() {
        val r = http.request("GET", "$base/redirect", "TOKEN", fp)
        assertEquals(302, r.code)
        assertEquals(listOf("redirect"), seen)
    }

    @Test
    fun plainHttpIsRefusedBeforeAnyConnection() {
        assertThrows(TransportRefused::class.java) { http.request("GET", "http://127.0.0.1:${server.address.port}/v1/vault", "TOKEN", null) }
        assertTrue(seen.isEmpty())
    }
}
