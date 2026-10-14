package com.codeheadsystems.vault.clip

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ClipboardTest {
    @Test
    fun echoesOfTheAppsOwnCopyAreNotForeign() {
        // API 36 delivers two change events within 15 ms of one copy.
        assertFalse(Clipboard.isForeign(copiedAt = 1_000, eventAt = 1_002))
        assertFalse(Clipboard.isForeign(copiedAt = 1_000, eventAt = 1_015))
        assertFalse(Clipboard.isForeign(copiedAt = 1_000, eventAt = 1_000 + Clipboard.ECHO_MS))
    }

    @Test
    fun aLaterChangeIsSomeoneElsesCopy() {
        assertTrue(Clipboard.isForeign(copiedAt = 1_000, eventAt = 1_001 + Clipboard.ECHO_MS))
    }
}
