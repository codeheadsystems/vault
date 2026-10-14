package com.codeheadsystems.vault.autofill

/**
 * An app's label is untrusted (docs/android.md, App matching): bidirectional and other format
 * controls are stripped, the label is shortened, and the package is always shown with it.
 */
object AppLabel {
    const val MAX_CHARS = 40

    fun display(label: CharSequence?, packageName: String): String {
        val clean = label?.toString().orEmpty()
            .filter { Character.getType(it) != Character.FORMAT.toInt() && !it.isISOControl() }
            .trim()
        val short = if (clean.codePointCount(0, clean.length) > MAX_CHARS) {
            clean.substring(0, clean.offsetByCodePoints(0, MAX_CHARS)) + "…"
        } else {
            clean
        }
        return if (short.isEmpty()) packageName else "'$short' ($packageName)"
    }
}
