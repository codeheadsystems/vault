package com.codeheadsystems.vault.autofill

import uniffi.vault_android.AppPage
import uniffi.vault_android.Page
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FillTargetsTest {
    private val firefox = "a78b62a5165b4494b2fead9e76a280d22d937fee6251aece599446b2ea319b04"
    private val chrome = "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83"
    private val chromeOther = "1975b2f17177bc89a5dff31f9e64a6cae281a53dc1d1d59b1d147fe1c82afa00"
    private val other = "00".repeat(32)

    private fun one(digest: String, pkg: String = "org.mozilla.firefox") = AppPage(pkg, listOf(digest), listOf(digest), false)

    private fun crossOrigin(focusInFrame: Boolean) = Structure.parse(listOf(N(webDomain = "", children = listOf(
        firefoxForm("127.0.0.1", firefoxInput("inuser", "127.0.0.1", "text", focused = focusInFrame), firefoxInput("inpass", "127.0.0.1", "password")),
        firefoxForm("10.0.2.2", firefoxInput("topuser", "10.0.2.2", "text", focused = !focusInFrame), firefoxInput("toppass", "10.0.2.2", "password")),
    ))))!!

    @Test
    fun allowlistHoldsTheThreeDigests() {
        assertTrue(BrowserAllowlist.allows(one(firefox)))
        assertTrue(BrowserAllowlist.allows(one(chrome, "com.android.chrome")))
        assertTrue(BrowserAllowlist.allows(one(chromeOther, "com.android.chrome")))
        assertEquals(3, BrowserAllowlist.BROWSERS.values.sumOf { it.size })
    }

    @Test
    fun allowlistRefusesOtherCertificatesAndPackages() {
        assertFalse(BrowserAllowlist.allows(one(chrome)))
        assertFalse(BrowserAllowlist.allows(one(other)))
        assertFalse(BrowserAllowlist.allows(one(firefox, "org.example.browser")))
        // A failed package lookup gives no signers.
        assertFalse(BrowserAllowlist.allows(AppPage("org.mozilla.firefox", emptyList(), emptyList(), false)))
    }

    @Test
    fun allowlistUsesTheCurrentCertificateOnly() {
        // A listed certificate only in the history (rotated away from) does not count.
        assertFalse(BrowserAllowlist.allows(AppPage("org.mozilla.firefox", listOf(other), listOf(firefox, other), false)))
        // An app with several signers is never a browser.
        assertFalse(BrowserAllowlist.allows(AppPage("org.mozilla.firefox", listOf(firefox, other), emptyList(), true)))
    }

    @Test
    fun firefoxFillIsConfinedToTheFocusedFrame() {
        val inFrame = FillTargets.of(one(firefox), crossOrigin(focusInFrame = true))
        assertEquals(Page.AndroidWeb("http", "127.0.0.1"), inFrame.page)
        assertEquals(listOf("inuser", "inpass"), inFrame.fields.map { it.id })
        val inTop = FillTargets.of(one(firefox), crossOrigin(focusInFrame = false))
        assertEquals(Page.AndroidWeb("http", "10.0.2.2"), inTop.page)
        assertEquals(listOf("topuser", "toppass"), inTop.fields.map { it.id })
    }

    @Test
    fun aWebDomainFromAnOrdinaryAppIsIgnored() {
        val webview = one(other, "com.example.webview")
        val t = FillTargets.of(webview, crossOrigin(focusInFrame = true))
        assertEquals(Page.App(webview), t.page)
        assertEquals(4, t.fields.size)
    }

    @Test
    fun aBrowserWithTheWrongCertificateIsAnApp() {
        val t = FillTargets.of(one(other), crossOrigin(focusInFrame = true))
        assertTrue(t.page is Page.App)
    }

    @Test
    fun aBrowserWithoutAWebSchemeIsAnApp() {
        val w = Structure.parse(listOf(N(webDomain = "example.com", webScheme = null, children = listOf(
            N(autofillId = "p", autofillHints = listOf("password"), isFocused = true),
        ))))!!
        assertTrue(FillTargets.of(one(chrome, "com.android.chrome"), w).page is Page.App)
    }

    @Test
    fun fieldsWithoutADomainAreLeftOutOfAWebFill() {
        val w = Structure.parse(listOf(N(children = listOf(
            N(webDomain = "example.com", webScheme = "https", children = listOf(
                N(autofillId = "p", autofillHints = listOf("password"), isFocused = true),
            )),
            N(autofillId = "native", autofillHints = listOf("username")),
        ))))!!
        val t = FillTargets.of(one(chrome, "com.android.chrome"), w)
        assertEquals(Page.AndroidWeb("https", "example.com"), t.page)
        assertEquals(listOf("p"), t.fields.map { it.id })
    }
}
