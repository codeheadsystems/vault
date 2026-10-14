package com.codeheadsystems.vault.lock

import com.codeheadsystems.vault.core.VaultCore

/**
 * The idle lock (docs/android.md, Idle lock). A frozen process runs no timer, so every entry point
 * (a fill request, the picker, an activity's `onStart`) calls [check] first: it locks when the app
 * has been out of the foreground for [BACKGROUND_LOCK_MS]; the core then applies its own idle rule,
 * which every session call also runs. [clock] is `SystemClock.elapsedRealtime()`. [onLocked] runs
 * once for each lock the guard sees: its own, the core's idle lock, or one made since the last
 * check, so the app can drop what only an unlocked session should hold.
 */
class LockGuard(private val core: VaultCore, private val clock: () -> Long, private val onLocked: () -> Unit = {}) {
    private var backgroundedAt: Long? = null
    private var lastUnlocked = false

    /** The process left the foreground (`ProcessLifecycleOwner` `ON_STOP`). */
    @Synchronized
    fun onBackground() {
        backgroundedAt = clock()
    }

    /** The process came to the foreground (`ON_START`): checks before clearing the mark. */
    @Synchronized
    fun onForeground() {
        check()
        backgroundedAt = null
    }

    /** The entry-point check. Returns whether the session is now locked when it was unlocked before. */
    @Synchronized
    fun check(): Boolean {
        val since = backgroundedAt
        if (since != null && clock() - since >= BACKGROUND_LOCK_MS && core.isUnlocked()) core.lock()
        core.lockIfIdle()
        val unlocked = core.isUnlocked()
        val locked = lastUnlocked && !unlocked
        lastUnlocked = unlocked
        if (locked) onLocked()
        return locked
    }

    /** An explicit lock from the app. */
    @Synchronized
    fun lock() {
        core.lock()
        lastUnlocked = false
        onLocked()
    }

    /** An action in the app's own activities. */
    fun recordActivity() = core.recordActivity()

    companion object {
        /** The app locks this long after it leaves the foreground. */
        const val BACKGROUND_LOCK_MS = 30_000L
    }
}
