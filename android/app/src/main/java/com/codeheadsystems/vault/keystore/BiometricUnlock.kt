package com.codeheadsystems.vault.keystore

import android.app.Activity
import android.security.keystore.KeyPermanentlyInvalidatedException
import com.codeheadsystems.vault.core.code
import com.codeheadsystems.vault.storage.KeySlots
import javax.crypto.Cipher
import uniffi.vault_android.Vault

/** What a biometric attempt came to. */
sealed interface BiometricResult {
    object Ok : BiometricResult

    /** A new enrolment invalidated the key, or the wrap belongs to old credentials: both are gone. */
    object Invalidated : BiometricResult

    class Failed(val message: CharSequence) : BiometricResult
}

/**
 * Biometric unlock (docs/android.md, Unlock and locking): the vault key from `Vault.vaultKey`
 * wrapped by the biometric key and stored with its `wrap_nonce`; an unwrap reopens the session
 * with `Vault.reopen`. The vault key is in a `ByteArray` only between the cipher and the library,
 * and is zeroed after.
 */
class BiometricUnlock(private val vault: Vault, private val slots: KeySlots) {

    /** Whether a wrap is stored and the device can unwrap it. */
    fun available(activity: Activity) = slots.getBiometricWrap() != null && Keys.hasBiometricKey() && BiometricGate.available(activity)

    /** Wraps the unlocked session's vault key after one prompt. */
    fun enable(activity: Activity, done: (BiometricResult) -> Unit) {
        val export = try {
            vault.vaultKey()
        } catch (e: Exception) {
            return done(BiometricResult.Failed(e.code()))
        }
        val cipher = try {
            Keys.generateBiometricKey()
            Keys.biometricCipher(Cipher.ENCRYPT_MODE)
        } catch (e: Exception) {
            export.vaultKey.fill(0)
            return done(BiometricResult.Failed(e.message ?: e.javaClass.simpleName))
        }
        BiometricGate.authenticate(activity, "Turn on fingerprint unlock", cipher, onSuccess = { c ->
            try {
                slots.putBiometricWrap(export.wrapNonce, c, export.vaultKey)
                done(BiometricResult.Ok)
            } catch (e: Exception) {
                done(BiometricResult.Failed(e.message ?: e.javaClass.simpleName))
            } finally {
                export.vaultKey.fill(0)
            }
        }, onFailure = {
            export.vaultKey.fill(0)
            done(BiometricResult.Failed(it))
        })
    }

    /** Unwraps the vault key after one prompt and reopens the session. */
    fun unlock(activity: Activity, title: String, done: (BiometricResult) -> Unit) {
        val wrap = slots.getBiometricWrap() ?: return done(BiometricResult.Invalidated)
        val cipher = try {
            Keys.biometricCipher(Cipher.DECRYPT_MODE, wrap.iv)
        } catch (_: KeyPermanentlyInvalidatedException) {
            disable()
            return done(BiometricResult.Invalidated)
        } catch (e: Exception) {
            return done(BiometricResult.Failed(e.message ?: e.javaClass.simpleName))
        }
        BiometricGate.authenticate(activity, title, cipher, onSuccess = { c ->
            var key: ByteArray? = null
            try {
                key = c.doFinal(wrap.ciphertext)
                vault.reopen(key, wrap.wrapNonce)
                done(BiometricResult.Ok)
            } catch (e: Exception) {
                if (e.code() == "biometric.stale") {
                    slots.deleteBiometricWrap()
                    done(BiometricResult.Invalidated)
                } else {
                    done(BiometricResult.Failed(e.code()))
                }
            } finally {
                key?.fill(0)
            }
        }, onFailure = { done(BiometricResult.Failed(it)) })
    }

    /**
     * A fresh biometric prompt that proves the user without changing the session, before a
     * credential change or a restore.
     */
    fun confirm(activity: Activity, title: String, done: (BiometricResult) -> Unit) {
        val wrap = slots.getBiometricWrap() ?: return done(BiometricResult.Invalidated)
        val cipher = try {
            Keys.biometricCipher(Cipher.DECRYPT_MODE, wrap.iv)
        } catch (_: KeyPermanentlyInvalidatedException) {
            disable()
            return done(BiometricResult.Invalidated)
        }
        BiometricGate.authenticate(activity, title, cipher, onSuccess = { c ->
            try {
                c.doFinal(wrap.ciphertext).fill(0)
                done(BiometricResult.Ok)
            } catch (e: Exception) {
                done(BiometricResult.Failed(e.message ?: e.javaClass.simpleName))
            }
        }, onFailure = { done(BiometricResult.Failed(it)) })
    }

    /** Deletes the key and the wrap. */
    fun disable() {
        Keys.deleteBiometricKey()
        slots.deleteBiometricWrap()
    }
}
