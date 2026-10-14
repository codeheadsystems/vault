package com.codeheadsystems.vault.clip

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.PersistableBundle
import android.os.SystemClock

/**
 * Copies a secret flagged sensitive and arranges the 45 s clear (docs/android.md, Clipboard).
 * Android 10 and later refuse clipboard reads from the background, so whether the clip is still
 * the app's own comes from a change listener registered before the copy: events within
 * [ECHO_MS] of the copy are its own echoes (API 36 delivers two), and any later one is a copy by
 * someone else.
 */
object Clipboard {
    const val CLEAR_AFTER_MS = 45_000L
    const val ECHO_MS = 500L

    private var copiedAt = 0L
    private var foreignChange = false
    private var listener: ClipboardManager.OnPrimaryClipChangedListener? = null

    /** Copies [text]; call from an activity in the foreground, which may start the service. */
    @Synchronized
    fun copySecret(context: Context, label: String, text: String) {
        val cm = context.getSystemService(ClipboardManager::class.java)
        listener?.let { cm.removePrimaryClipChangedListener(it) }
        val clip = ClipData.newPlainText(label, text)
        clip.description.extras = PersistableBundle().apply {
            putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else IS_SENSITIVE, true)
        }
        foreignChange = false
        copiedAt = SystemClock.elapsedRealtime()
        val l = ClipboardManager.OnPrimaryClipChangedListener { onChange(SystemClock.elapsedRealtime()) }
        listener = l
        cm.addPrimaryClipChangedListener(l)
        cm.setPrimaryClip(clip)
        context.startForegroundService(Intent(context, ClipClearService::class.java))
    }

    @Synchronized
    private fun onChange(now: Long) {
        if (isForeign(copiedAt, now)) foreignChange = true
    }

    /** Called by the service after [CLEAR_AFTER_MS]: clears when the clip is still the app's own. */
    @Synchronized
    fun clearIfOwn(context: Context): Boolean {
        val cm = context.getSystemService(ClipboardManager::class.java)
        listener?.let { cm.removePrimaryClipChangedListener(it) }
        listener = null
        if (foreignChange) return false
        cm.clearPrimaryClip()
        return true
    }

    /** Whether a change event at [eventAt] comes from someone else than a copy at [copiedAt]. */
    fun isForeign(copiedAt: Long, eventAt: Long) = eventAt - copiedAt > ECHO_MS

    /** `ClipDescription.EXTRA_IS_SENSITIVE`, which API 33 names; the string works below it. */
    private const val IS_SENSITIVE = "android.content.extra.IS_SENSITIVE"
}
