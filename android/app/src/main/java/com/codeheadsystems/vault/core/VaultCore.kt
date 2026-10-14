package com.codeheadsystems.vault.core

import uniffi.vault_android.Vault
import uniffi.vault_android.VaultException

/**
 * The part of `vault-android` that the lock guard and the transport use, so their JVM tests can
 * run against a fake. Everything else calls the generated [Vault] directly.
 */
interface VaultCore {
    fun isUnlocked(): Boolean

    /** The entry-point check of the idle lock (the clock is the host's): true when it locked. */
    fun lockIfIdle(): Boolean

    /** An action in the app's own activities; requests from other apps never call it. */
    fun recordActivity()

    fun lock()

    /** `vault-core`'s pin check: the SHA-256 of the leaf certificate's DER equals `fp`. */
    fun pinMatches(fp: String, leafDer: ByteArray): Boolean
}

/** [VaultCore] over the generated bindings. */
class NativeCore(private val vault: Vault) : VaultCore {
    override fun isUnlocked() = vault.isUnlocked()
    override fun lockIfIdle() = vault.lockIfIdle()
    override fun recordActivity() = vault.recordActivity()
    override fun lock() = vault.lock()
    override fun pinMatches(fp: String, leafDer: ByteArray) = uniffi.vault_android.pinMatches(fp, leafDer)
}

/** The stable code of a binding error, or `internal` for a Rust panic or anything else. */
fun Throwable.code(): String = when (this) {
    is VaultException.Failed -> code
    else -> "internal"
}
