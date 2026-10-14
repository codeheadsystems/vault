package com.codeheadsystems.vault.autofill

import uniffi.vault_android.AppMatch
import uniffi.vault_android.Outcome

/**
 * What the picker asks before a fill (docs/android.md, App matching): nothing for a `fill`
 * outcome; otherwise a question that names the item and the destination, and says why for an app
 * whose signature changed, a binding about to be made or moved, or a signature that could not be
 * checked.
 */
object Confirmations {
    /** The question for a candidate, or null to fill without asking. */
    fun forCandidate(outcome: Outcome, appMatch: AppMatch?, name: String, destination: String): String? {
        if (outcome == Outcome.FILL) return null
        val fill = "Fill '$name' into $destination?"
        return when (appMatch) {
            AppMatch.SIGNATURE_CHANGED -> "The app's signature changed since '$name' was bound to it. $fill It stays bound to the old signature."
            AppMatch.REBIND -> "The app now signs with a newer certificate of the same lineage. $fill It is bound to the new one."
            AppMatch.BIND -> "$fill This binds '$name' to the app's signing certificate."
            AppMatch.UNVERIFIED -> "The app's signature could not be checked. $fill"
            AppMatch.FILL, null -> fill
        }
    }

    /** The question for an item chosen through "Choose another item". */
    fun forExplicitChoice(name: String, destination: String) = "'$name' is not saved for $destination. Fill it anyway?"
}
