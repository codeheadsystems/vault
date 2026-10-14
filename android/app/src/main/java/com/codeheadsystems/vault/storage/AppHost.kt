package com.codeheadsystems.vault.storage

import android.os.SystemClock
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import uniffi.vault_android.Host
import uniffi.vault_android.KeySlot
import uniffi.vault_android.VaultException

/**
 * The library's storage and clocks (`vault-android` `Host`): `local.json` in `filesDir`, the
 * device ID and the key slots in `noBackupFilesDir`. The library calls these methods while it
 * holds its state lock, so none of them calls back into it. A failure is
 * `VaultException.Failed` with `host.device_locked` when the storage key refuses on a locked
 * device, and `host.io` otherwise.
 */
class AppHost(
    private val files: AtomicFiles,
    private val noBackup: AtomicFiles,
    private val slots: KeySlots,
) : Host {
    override fun readState(): ByteArray? = io { files.read(STATE) }

    override fun writeState(state: ByteArray) = io { files.write(STATE, state) }

    override fun readKey(slot: KeySlot): ByteArray? = io { slots.getSecret(slot.slot()) }

    /** Wraps and stores the key, then zeroes the array: the library hands it over for this only. */
    override fun writeKey(slot: KeySlot, key: ByteArray) = try {
        io { slots.putSecret(slot.slot(), key) }
    } finally {
        key.fill(0)
    }

    override fun deleteKey(slot: KeySlot) = io { slots.deleteSecret(slot.slot()) }

    override fun deleteBiometricWrap() = io { slots.deleteBiometricWrap() }

    override fun readDeviceId(): ByteArray? = io { noBackup.read(DEVICE_ID) }

    override fun writeDeviceId(id: ByteArray) = io { noBackup.write(DEVICE_ID, id) }

    override fun nowMs(): ULong = System.currentTimeMillis().toULong()

    override fun elapsedRealtimeMs(): ULong = SystemClock.elapsedRealtime().toULong()

    private fun KeySlot.slot() = when (this) {
        KeySlot.CURRENT -> KeySlots.Slot.SECRET_KEY
        KeySlot.PENDING -> KeySlots.Slot.PENDING_SECRET_KEY
    }

    private fun <T> io(block: () -> T): T = try {
        block()
    } catch (e: InvalidKeyException) {
        throw if (deviceLocked(e)) VaultException.Failed("host.device_locked", "the device is locked") else failed(e)
    } catch (e: GeneralSecurityException) {
        throw failed(e)
    } catch (e: IOException) {
        throw failed(e)
    } catch (e: IllegalArgumentException) {
        throw failed(e)
    }

    private fun failed(e: Exception) = VaultException.Failed("host.io", e.javaClass.simpleName + ": " + e.message)

    companion object {
        const val STATE = "local.json"
        const val DEVICE_ID = "device-id"

        /** Whether the Keystore refused because the device is locked (`setUnlockedDeviceRequired`). */
        fun deviceLocked(e: Throwable): Boolean {
            var t: Throwable? = e
            while (t != null) {
                if (t.message?.contains("Device locked", ignoreCase = true) == true) return true
                t = t.cause
            }
            return false
        }
    }
}
