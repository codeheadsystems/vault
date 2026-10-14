package com.codeheadsystems.vault.storage

import com.codeheadsystems.vault.keystore.Keys
import javax.crypto.Cipher
import javax.crypto.SecretKey

/**
 * The key slots in `noBackupFilesDir` (docs/android.md, Storage): the secret key and a pending one,
 * each `iv || ciphertext` under the storage key, and the vault key wrapped by the biometric key,
 * stored as `wrap_nonce || iv || ciphertext` so that a commit changing `wrap_nonce` can drop it.
 */
class KeySlots(private val files: AtomicFiles, private val storageKey: () -> SecretKey) {

    /** Wraps and stores a secret key under the storage key. */
    fun putSecret(slot: Slot, secret: ByteArray) {
        val cipher = Keys.encryptCipher(storageKey())
        files.write(slot.file, cipher.iv + cipher.doFinal(secret))
    }

    /** The unwrapped secret key, or null when the slot is empty. The caller zeroes it. */
    fun getSecret(slot: Slot): ByteArray? {
        val b = files.read(slot.file) ?: return null
        require(b.size > Keys.GCM_IV_BYTES) { "short key slot ${slot.file}" }
        return Keys.decryptCipher(storageKey(), b.copyOfRange(0, Keys.GCM_IV_BYTES))
            .doFinal(b, Keys.GCM_IV_BYTES, b.size - Keys.GCM_IV_BYTES)
    }

    fun deleteSecret(slot: Slot) = files.delete(slot.file)

    /** Stores the vault key wrap that an authenticated biometric cipher produced. */
    fun putBiometricWrap(wrapNonce: ByteArray, cipher: Cipher, vaultKey: ByteArray) {
        require(wrapNonce.size == WRAP_NONCE_BYTES)
        files.write(BIOMETRIC_WRAP, wrapNonce + cipher.iv + cipher.doFinal(vaultKey))
    }

    /** The stored wrap, or null. */
    fun getBiometricWrap(): BiometricWrap? {
        val b = files.read(BIOMETRIC_WRAP) ?: return null
        val ivEnd = WRAP_NONCE_BYTES + Keys.GCM_IV_BYTES
        require(b.size > ivEnd) { "short biometric wrap" }
        return BiometricWrap(b.copyOfRange(0, WRAP_NONCE_BYTES), b.copyOfRange(WRAP_NONCE_BYTES, ivEnd), b.copyOfRange(ivEnd, b.size))
    }

    fun deleteBiometricWrap() = files.delete(BIOMETRIC_WRAP)

    /** Deletes the wrap when it belongs to another `wrap_nonce` than the state's current one. */
    fun dropStaleBiometricWrap(currentWrapNonce: ByteArray) {
        val w = getBiometricWrap() ?: return
        if (!w.wrapNonce.contentEquals(currentWrapNonce)) deleteBiometricWrap()
    }

    enum class Slot(val file: String) { SECRET_KEY("secret-key"), PENDING_SECRET_KEY("pending-secret-key") }

    class BiometricWrap(val wrapNonce: ByteArray, val iv: ByteArray, val ciphertext: ByteArray)

    companion object {
        const val WRAP_NONCE_BYTES = 24
        const val BIOMETRIC_WRAP = "biometric-wrap"
    }
}
