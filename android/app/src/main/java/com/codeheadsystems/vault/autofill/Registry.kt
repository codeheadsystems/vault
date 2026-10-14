package com.codeheadsystems.vault.autofill

import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicInteger

/**
 * The in-process registry (docs/android.md, Autofill, step 2): what a fill or save response needs
 * later is kept here under a random single-use token that expires after [TTL_MS]; the picker and
 * save intents carry only the token. [peek] reads an entry without using it, so a cancelled
 * biometric prompt does not burn the token; [consume] uses it, when a dataset is returned or a
 * save is shown. A lock and a process death empty it.
 */
class Registry<T : Any>(private val clock: () -> Long, private val random: SecureRandom = SecureRandom()) {
    private class Entry<T>(val value: T, val expiresAt: Long)

    private val entries = HashMap<String, Entry<T>>()
    private val requestCodes = AtomicInteger(random.nextInt(Int.MAX_VALUE / 2))

    /** Stores [value] and returns its token: 32 lowercase hex characters. */
    @Synchronized
    fun put(value: T): String {
        purge()
        val bytes = ByteArray(TOKEN_BYTES).also { random.nextBytes(it) }
        val token = bytes.joinToString("") { "%02x".format(it) }
        entries[token] = Entry(value, clock() + TTL_MS)
        return token
    }

    /** The value for [token], left in place: an unknown, used, or expired token gives null. */
    @Synchronized
    fun peek(token: String?): T? {
        purge()
        return token?.let { entries[it]?.value }
    }

    /** The value for [token], once: an unknown, used, or expired token gives null. */
    @Synchronized
    fun consume(token: String?): T? {
        purge()
        return token?.let { entries.remove(it)?.value }
    }

    /** Forgets every entry: on a lock, so nothing filled or saved outlives the session. */
    @Synchronized
    fun clear() = entries.clear()

    /**
     * A request code for a response's `PendingIntent`, unique within the process. With a shared
     * code, `FLAG_UPDATE_CURRENT` gives an earlier response the later one's extras and
     * `FLAG_CANCEL_CURRENT` cancels the earlier one.
     */
    fun nextRequestCode(): Int = requestCodes.getAndIncrement()

    @Synchronized
    fun size(): Int {
        purge()
        return entries.size
    }

    private fun purge() {
        val now = clock()
        entries.values.removeAll { now >= it.expiresAt }
    }

    companion object {
        const val TTL_MS = 5 * 60_000L
        const val TOKEN_BYTES = 16

        /** The intent extra that carries the token. */
        const val EXTRA_TOKEN = "com.codeheadsystems.vault.TOKEN"
    }
}
