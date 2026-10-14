package com.codeheadsystems.vault.net

import java.net.URI
import java.net.URISyntaxException

/** A request refused before any connection is made. */
class TransportRefused(message: String) : Exception(message)

/**
 * The Kotlin-side transport rules (docs/android.md, Transport), checked before any request; the
 * network security configuration enforces the cleartext part again.
 *
 * - `https` is allowed to any host.
 * - `http` is refused in release builds, loopback included, because every app on a phone shares
 *   the loopback interface. Debug builds allow it to `127.0.0.1` and `[::1]` only.
 * - `localhost` is never resolved: it connects to `127.0.0.1`.
 * - User information and fragments are refused.
 */
object TransportRules {

    /** The URL to connect to, or [TransportRefused]. [debug] is `BuildConfig.DEBUG`. */
    fun target(url: String, debug: Boolean): URI {
        val u = try {
            URI(url)
        } catch (e: URISyntaxException) {
            throw TransportRefused("not a URL")
        }
        val host = u.host ?: throw TransportRefused("no host")
        if (u.rawUserInfo != null) throw TransportRefused("user information in the URL")
        if (u.rawFragment != null) throw TransportRefused("fragment in the URL")
        val connectHost = if (host.equals("localhost", ignoreCase = true)) "127.0.0.1" else host
        when (u.scheme?.lowercase()) {
            "https" -> Unit
            "http" -> {
                if (!debug) throw TransportRefused("plain http is refused")
                if (connectHost != "127.0.0.1" && connectHost != "[::1]") {
                    throw TransportRefused("plain http is allowed only to 127.0.0.1 and [::1] in debug builds")
                }
            }
            else -> throw TransportRefused("scheme must be https")
        }
        return URI(u.scheme.lowercase(), null, connectHost, u.port, u.rawPath, u.rawQuery, null)
    }
}
