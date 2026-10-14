package com.codeheadsystems.vault.autofill

import uniffi.vault_android.AppPage
import uniffi.vault_android.Page
import uniffi.vault_android.androidWebPage

/** The page a fill request is for, and the fields a fill may reach. */
data class FillTarget<I>(val page: Page, val fields: List<Field<I>>)

/** The browser allowlist (docs/android.md, Web matching). */
object BrowserAllowlist {
    /** Package to the SHA-256 digests of its accepted signing certificates, lowercase hex. */
    val BROWSERS: Map<String, Set<String>> = mapOf(
        "com.android.chrome" to setOf(
            "f0fd6c5b410f25cb25c3b53346c8972fae30f8ee7411df910480ad6b2d60db83",
            "1975b2f17177bc89a5dff31f9e64a6cae281a53dc1d1d59b1d147fe1c82afa00",
        ),
        "org.mozilla.firefox" to setOf(
            "a78b62a5165b4494b2fead9e76a280d22d937fee6251aece599446b2ea319b04",
        ),
    )

    /** Whether the app is an allowlisted browser: one signer whose current certificate is listed. */
    fun allows(app: AppPage): Boolean {
        val digests = BROWSERS[app.packageName] ?: return false
        if (app.multipleSigners || app.signers.size != 1) return false
        return app.signers.single().lowercase() in digests
    }
}

/**
 * The fill target of a parsed window (docs/android.md, Web matching and App matching).
 *
 * From an allowlisted browser that reports a `webScheme` for the focused field, and whose page
 * `androidWebPage` accepts, the page is the focused field's frame, and a fill reaches only the
 * fields whose own `webDomain` and `webScheme` equal the focused field's; fields with no domain are
 * ignored. From any other app, `webDomain` is ignored and the page is the app, with every field of
 * the window.
 */
object FillTargets {
    fun <I> of(app: AppPage, window: ParsedWindow<I>): FillTarget<I> {
        val focus = window.focused
        val host = focus.webDomain
        val scheme = focus.webScheme
        if (BrowserAllowlist.allows(app) && !host.isNullOrEmpty() && !scheme.isNullOrEmpty()) {
            val web = androidWebPage(scheme, host)
            if (web != null) {
                val same = window.fields.filter { it.webDomain == host && it.webScheme == scheme }
                return FillTarget(Page.AndroidWeb(web.scheme, web.host), same)
            }
        }
        return FillTarget(Page.App(app), window.fields)
    }
}
