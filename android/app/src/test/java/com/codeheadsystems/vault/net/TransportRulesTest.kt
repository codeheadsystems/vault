package com.codeheadsystems.vault.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class TransportRulesTest {
    private fun target(url: String, debug: Boolean = false) = TransportRules.target(url, debug).toString()

    @Test
    fun httpsIsAllowedAnywhere() {
        assertEquals("https://nas.lan:8443/v1/vault", target("https://nas.lan:8443/v1/vault"))
        assertEquals("https://10.0.2.2:18443/v1/vault", target("https://10.0.2.2:18443/v1/vault"))
        assertEquals("https://[fd00::1]:8443/v1/vault?x=1", target("https://[fd00::1]:8443/v1/vault?x=1"))
    }

    @Test
    fun releaseRefusesHttpLoopbackIncluded() {
        for (url in listOf("http://127.0.0.1:8080/v1/vault", "http://[::1]:8080/", "http://localhost:8080/", "http://nas.lan/")) {
            assertThrows(url, TransportRefused::class.java) { target(url, debug = false) }
        }
    }

    @Test
    fun debugAllowsHttpToLoopbackAddressesOnly() {
        assertEquals("http://127.0.0.1:8080/v1/vault", target("http://127.0.0.1:8080/v1/vault", debug = true))
        assertEquals("http://[::1]:8080/v1/vault", target("http://[::1]:8080/v1/vault", debug = true))
        for (url in listOf("http://10.0.2.2:18081/", "http://nas.lan/", "http://127.0.0.2/", "http://0x7f.1/")) {
            assertThrows(url, TransportRefused::class.java) { target(url, debug = true) }
        }
    }

    @Test
    fun localhostIsNeverResolved() {
        assertEquals("http://127.0.0.1:8080/v1/vault", target("http://localhost:8080/v1/vault", debug = true))
        assertEquals("https://127.0.0.1:8443/v1/vault", target("https://LOCALHOST:8443/v1/vault"))
    }

    @Test
    fun otherSchemesUserInformationAndFragmentsAreRefused() {
        for (url in listOf("ftp://nas.lan/", "vault://setup?url=x", "https://user@nas.lan/", "https://nas.lan/#f", "not a url", "https:///path")) {
            assertThrows(url, TransportRefused::class.java) { target(url) }
        }
    }
}
