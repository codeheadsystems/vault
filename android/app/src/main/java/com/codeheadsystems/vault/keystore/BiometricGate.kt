package com.codeheadsystems.vault.keystore

import android.app.Activity
import android.hardware.biometrics.BiometricManager
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import javax.crypto.Cipher

/**
 * The platform `BiometricPrompt` with a `CryptoObject` (docs/android.md, Unlock and locking);
 * `androidx.biometric` is not used. Android draws the prompt, so another app cannot imitate it.
 */
object BiometricGate {

    /** Whether a strong biometric is enrolled and usable. */
    fun available(activity: Activity): Boolean {
        val bm = activity.getSystemService(BiometricManager::class.java)
        val status = if (Build.VERSION.SDK_INT >= 30) {
            bm.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            bm.canAuthenticate()
        }
        return status == BiometricManager.BIOMETRIC_SUCCESS
    }

    /**
     * Shows the prompt for [cipher]. [onSuccess] receives the authenticated cipher; [onFailure]
     * receives a message for an error or a cancellation. A biometric that is not recognised lets the
     * user try again inside the prompt.
     */
    fun authenticate(
        activity: Activity,
        title: String,
        cipher: Cipher,
        onSuccess: (Cipher) -> Unit,
        onFailure: (CharSequence) -> Unit,
    ): CancellationSignal {
        val builder = BiometricPrompt.Builder(activity).setTitle(title)
        if (Build.VERSION.SDK_INT >= 30) {
            builder.setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        }
        builder.setNegativeButton(activity.getString(android.R.string.cancel), activity.mainExecutor) { _, _ ->
            onFailure(activity.getString(android.R.string.cancel))
        }
        val cancel = CancellationSignal()
        builder.build().authenticate(
            BiometricPrompt.CryptoObject(cipher),
            cancel,
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val c = result.cryptoObject?.cipher
                    if (c == null) onFailure("no cipher") else onSuccess(c)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) = onFailure(errString)
            },
        )
        return cancel
    }
}
