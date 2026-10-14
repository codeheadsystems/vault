package com.codeheadsystems.vault

import com.codeheadsystems.vault.core.VaultCore
import java.security.MessageDigest

/** A core for JVM tests: the idle rule and the pin check, as `vault-android` implements them. */
class FakeCore(private val clock: () -> Long = { 0L }, var idleMs: Long = 5 * 60_000L) : VaultCore {
    var unlocked = false
    var lastActivity = 0L
    var locks = 0

    fun unlock() {
        unlocked = true
        lastActivity = clock()
    }

    override fun isUnlocked() = unlocked

    override fun lockIfIdle(): Boolean {
        if (unlocked && clock() - lastActivity >= idleMs) {
            lock()
            return true
        }
        return false
    }

    override fun recordActivity() {
        lastActivity = clock()
    }

    override fun lock() {
        unlocked = false
        locks++
    }

    override fun pinMatches(fp: String, leafDer: ByteArray) =
        MessageDigest.getInstance("SHA-256").digest(leafDer).joinToString("") { "%02x".format(it) } == fp
}
