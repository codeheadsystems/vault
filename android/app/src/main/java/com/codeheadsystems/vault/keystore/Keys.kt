package com.codeheadsystems.vault.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The two Android Keystore keys (docs/android.md, Storage and Unlock and locking), both AES-256-GCM
 * and usable only while the device is unlocked:
 *
 * - the storage key, with no user authentication, which wraps the secret key;
 * - the biometric key, which needs a strong biometric for every use through a `CryptoObject`, is
 *   invalidated by a new enrolment, wraps the vault key, and is backed by StrongBox where the
 *   device has it.
 *
 * While the device is locked, `Cipher.init` on the storage key throws `InvalidKeyException` with
 * the cause "Device locked". On API 29 a locked device does not stop `Cipher.init` on the
 * biometric key; the per-use biometric still stops `doFinal`.
 */
object Keys {
    const val STORAGE = "vault-storage"
    const val BIOMETRIC = "vault-biometric"
    const val GCM_IV_BYTES = 12
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val TAG_BITS = 128

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    private fun spec(alias: String) =
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUnlockedDeviceRequired(true)

    private fun generate(spec: KeyGenParameterSpec) {
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply {
            init(spec)
            generateKey()
        }
    }

    /** The storage key, generated on first use. */
    fun storageKey(): SecretKey {
        val ks = keyStore()
        if (!ks.containsAlias(STORAGE)) generate(spec(STORAGE).build())
        return ks.getKey(STORAGE, null) as SecretKey
    }

    /** Replaces the biometric key. Needs a strong biometric enrolled and a secure lock screen. */
    fun generateBiometricKey() {
        keyStore().deleteEntry(BIOMETRIC)
        fun builder(strongBox: Boolean) = spec(BIOMETRIC)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .setIsStrongBoxBacked(strongBox)
            .also {
                if (Build.VERSION.SDK_INT >= 30) {
                    it.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                } else {
                    // Every use needs a biometric through a CryptoObject; the device credential never.
                    @Suppress("DEPRECATION")
                    it.setUserAuthenticationValidityDurationSeconds(-1)
                }
            }
        try {
            generate(builder(strongBox = true).build())
        } catch (_: StrongBoxUnavailableException) {
            generate(builder(strongBox = false).build())
        }
    }

    fun hasBiometricKey() = keyStore().containsAlias(BIOMETRIC)

    fun deleteBiometricKey() = keyStore().deleteEntry(BIOMETRIC)

    /** An encrypting cipher with a fresh IV chosen by the Keystore. */
    fun encryptCipher(key: SecretKey): Cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }

    fun decryptCipher(key: SecretKey, iv: ByteArray): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv)) }

    /**
     * The biometric key's cipher. Throws `KeyPermanentlyInvalidatedException` after a new enrolment,
     * before any prompt; the caller then deletes the key and the wrap.
     */
    fun biometricCipher(mode: Int, iv: ByteArray? = null): Cipher {
        val key = keyStore().getKey(BIOMETRIC, null) as SecretKey? ?: throw IllegalStateException("no biometric key")
        return if (mode == Cipher.ENCRYPT_MODE) encryptCipher(key) else decryptCipher(key, requireNotNull(iv))
    }
}
