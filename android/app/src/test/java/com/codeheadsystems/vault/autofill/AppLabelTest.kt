package com.codeheadsystems.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Test

class AppLabelTest {
    @Test
    fun bidirectionalControlsAreStripped() {
        // U+202E RIGHT-TO-LEFT OVERRIDE would reverse the text after it.
        assertEquals("'Bank evil' (com.evil)", AppLabel.display("Bank\u202E evil", "com.evil"))
        assertEquals("'ab' (p)", AppLabel.display("a\u200Fb\u2066", "p"))
    }

    @Test
    fun longLabelsAreShortened() {
        val shown = AppLabel.display("x".repeat(100), "p")
        assertEquals("'" + "x".repeat(AppLabel.MAX_CHARS) + "…' (p)", shown)
    }

    @Test
    fun theDescriptionAlwaysNamesThePackage() {
        assertEquals("com.example", AppLabel.display(null, "com.example"))
        assertEquals("com.example", AppLabel.display("\u202E", "com.example"))
    }
}
