package com.codeheadsystems.vault.autofill

/**
 * Requesting packages the autofill service never serves: no fill, no `SaveInfo`, and every save
 * request dropped. The app's own package, and the system's own screens, whose password fields
 * hold the device PIN or password (Settings' "confirm your PIN"), which must not reach a synced
 * vault.
 */
object Refused {
    val SYSTEM_PACKAGES = setOf("com.android.settings", "com.android.systemui")

    fun refuses(requester: String, ownPackage: String) = requester == ownPackage || requester in SYSTEM_PACKAGES
}

/** The service's first decisions, before any structure is parsed. */
object ServiceGate {
    /** Whether a fill request gets an answer: not in compatibility mode, and not from a refused package. */
    fun servesFill(flags: Int, requester: String, ownPackage: String) =
        flags and android.service.autofill.FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST == 0 && !Refused.refuses(requester, ownPackage)

    /** Whether a save request is kept: only while unlocked, and not from a refused package. */
    fun keepsSave(unlocked: Boolean, requester: String, ownPackage: String) = unlocked && !Refused.refuses(requester, ownPackage)
}
