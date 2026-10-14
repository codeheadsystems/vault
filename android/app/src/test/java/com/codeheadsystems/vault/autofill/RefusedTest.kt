package com.codeheadsystems.vault.autofill

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RefusedTest {
    private val own = "com.codeheadsystems.vault"

    @Test
    fun theAppItselfAndTheSystemScreensAreRefused() {
        assertTrue(Refused.refuses(own, own))
        assertTrue(Refused.refuses("com.android.settings", own))
        assertTrue(Refused.refuses("com.android.systemui", own))
    }

    @Test
    fun otherAppsAndBrowsersAreServed() {
        for (pkg in listOf("org.mozilla.firefox", "com.android.chrome", "com.codeheadsystems.vault.e2etarget", "com.android.settings.extra")) {
            assertFalse(pkg, Refused.refuses(pkg, own))
        }
    }
}

class ServiceGateTest {
    private val own = "com.codeheadsystems.vault"
    private val compat = android.service.autofill.FillRequest.FLAG_COMPATIBILITY_MODE_REQUEST

    @Test
    fun compatibilityModeAndRefusedPackagesGetNoFill() {
        assertTrue(ServiceGate.servesFill(0, "org.mozilla.firefox", own))
        assertFalse(ServiceGate.servesFill(compat, "org.mozilla.firefox", own))
        assertFalse(ServiceGate.servesFill(0, "com.android.settings", own))
        assertFalse(ServiceGate.servesFill(0, own, own))
    }

    @Test
    fun aSaveIsDroppedWhileLockedOrFromARefusedPackage() {
        assertTrue(ServiceGate.keepsSave(true, "org.mozilla.firefox", own))
        assertFalse(ServiceGate.keepsSave(false, "org.mozilla.firefox", own))
        assertFalse(ServiceGate.keepsSave(true, "com.android.systemui", own))
        assertFalse(ServiceGate.keepsSave(true, own, own))
    }
}
