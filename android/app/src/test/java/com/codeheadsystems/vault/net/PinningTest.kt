package com.codeheadsystems.vault.net

import com.codeheadsystems.vault.FakeCore
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PinningTest {
    // An ECDSA P-256 certificate for nas.lan that expired on 2020-01-02.
    private val der = Base64.getDecoder().decode(
        "MIIBjTCCATOgAwIBAgIUU5j3bYBihop9v2o3b6SDQAcN1UswCgYIKoZIzj0EAwIwEjEQMA4GA1UEAwwHbmFzLmxhbjAeFw0yMDAxMDEwMDAwMDBaFw0y" +
            "MDAxMDIwMDAwMDBaMBIxEDAOBgNVBAMMB25hcy5sYW4wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARJ7APcQd9NRTVxZUGynRKPS1axla7j81nAxvGe" +
            "qFJHyOaupq4hE5zMOTbjl8g7/3KlZFmSjbdWg+sA472YFabdo2cwZTAdBgNVHQ4EFgQUtId4qNSr+FZNXOFISM/IEfXs7dwwHwYDVR0jBBgwFoAUtId4" +
            "qNSr+FZNXOFISM/IEfXs7dwwDwYDVR0TAQH/BAUwAwEB/zASBgNVHREECzAJggduYXMubGFuMAoGCCqGSM49BAMCA0gAMEUCIQD0EVFnGlDkPVXl1XWr" +
            "sNLubfcPA5Y79if9xd+k/USVBAIgHi0u9qLMj62gUOrQONUB+ieHP2AHCD/zzusbTkmmKIU=",
    )
    private val fp = "104e365375d23b9cc062bef7aee8a4ca802f39ead7bbb5b964f3458608f74cf5"
    private val cert = CertificateFactory.getInstance("X.509").generateCertificate(der.inputStream()) as X509Certificate
    private val core = FakeCore()

    @Test
    fun thePinnedLeafIsAcceptedDespiteItsNameAndDates() {
        assertArrayEquals(der, cert.encoded)
        PinnedTrustManager(core, fp).checkServerTrusted(arrayOf(cert), "ECDHE_ECDSA")
    }

    @Test
    fun anotherPinIsRefused() {
        assertThrows(CertificateException::class.java) {
            PinnedTrustManager(core, "00".repeat(32)).checkServerTrusted(arrayOf(cert), "ECDHE_ECDSA")
        }
    }

    @Test
    fun anEmptyChainIsRefused() {
        assertThrows(CertificateException::class.java) { PinnedTrustManager(core, fp).checkServerTrusted(arrayOf(), "RSA") }
        assertThrows(CertificateException::class.java) { PinnedTrustManager(core, fp).checkServerTrusted(null, "RSA") }
    }

    @Test
    fun clientCertificatesAreNeverTrusted() {
        assertThrows(CertificateException::class.java) { PinnedTrustManager(core, fp).checkClientTrusted(arrayOf(cert), "RSA") }
        assertEquals(0, PinnedTrustManager(core, fp).acceptedIssuers.size)
    }

    @Test
    fun theHostnameVerifierChecksThePinWithoutASession() {
        assertEquals(false, PinnedHostnameVerifier(core, fp).verify("nas.lan", null))
    }

    @Test
    fun onlyTls12AndLaterAreEnabled() {
        val supported = arrayOf("SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
        assertArrayEquals(arrayOf("TLSv1.3", "TLSv1.2"), ModernTlsSocketFactory.allowedProtocols(supported))
        assertArrayEquals(arrayOf("TLSv1.2"), ModernTlsSocketFactory.allowedProtocols(arrayOf("TLSv1.1", "TLSv1.2")))
        assertEquals(0, ModernTlsSocketFactory.allowedProtocols(arrayOf("TLSv1", "TLSv1.1")).size)
    }
}
