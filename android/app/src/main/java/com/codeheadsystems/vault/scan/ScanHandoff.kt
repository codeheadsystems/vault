package com.codeheadsystems.vault.scan

/**
 * Hands a scanned QR code's text (setup text or a secret key) from [ScanActivity] to the activity
 * that started it, inside the process: a result intent would carry it through `system_server`.
 */
object ScanHandoff {
    private var text: String? = null

    @Synchronized
    fun put(value: String) {
        text = value
    }

    /** The scanned text, once; null when nothing was scanned. */
    @Synchronized
    fun take(): String? = text.also { text = null }
}
