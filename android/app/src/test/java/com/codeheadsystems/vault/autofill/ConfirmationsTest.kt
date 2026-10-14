package com.codeheadsystems.vault.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.vault_android.AppMatch
import uniffi.vault_android.AppPage
import uniffi.vault_android.Outcome
import uniffi.vault_android.Page
import uniffi.vault_android.explicitChoiceAllowed

class ConfirmationsTest {
    private val dest = "'GitHub' (com.github.android)"

    @Test
    fun aFillOutcomeAsksNothing() {
        assertNull(Confirmations.forCandidate(Outcome.FILL, AppMatch.FILL, "GitHub", dest))
        assertNull(Confirmations.forCandidate(Outcome.FILL, null, "GitHub", "https://github.com"))
    }

    @Test
    fun everyQuestionNamesTheItemAndTheDestination() {
        for (m in listOf(null, AppMatch.FILL, AppMatch.REBIND, AppMatch.SIGNATURE_CHANGED, AppMatch.BIND, AppMatch.UNVERIFIED)) {
            val q = Confirmations.forCandidate(Outcome.CONFIRM, m, "GitHub", dest)!!
            assertTrue(q, q.contains("'GitHub'") && q.contains(dest))
        }
        val e = Confirmations.forExplicitChoice("GitHub", dest)
        assertTrue(e, e.contains("'GitHub'") && e.contains(dest))
    }

    @Test
    fun aChangedSignatureIsAWarningThatDoesNotRebind() {
        val q = Confirmations.forCandidate(Outcome.CONFIRM, AppMatch.SIGNATURE_CHANGED, "GitHub", dest)!!
        assertTrue(q, q.startsWith("The app's signature changed"))
        assertTrue(q, q.contains("stays bound to the old signature"))
    }

    @Test
    fun anotherItemIsRefusedForAnHttpPageThatIsNotALocalHost() {
        assertFalse(explicitChoiceAllowed(Page.AndroidWeb("http", "example.com")))
        assertTrue(explicitChoiceAllowed(Page.AndroidWeb("http", "10.0.2.2")))
        assertTrue(explicitChoiceAllowed(Page.AndroidWeb("http", "nas.lan")))
        assertTrue(explicitChoiceAllowed(Page.AndroidWeb("https", "example.com")))
        assertTrue(explicitChoiceAllowed(Page.App(AppPage("com.example", emptyList(), emptyList(), false))))
    }
}
