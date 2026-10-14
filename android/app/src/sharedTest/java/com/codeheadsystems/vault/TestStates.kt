package com.codeheadsystems.vault

import org.json.JSONArray
import org.json.JSONObject
import uniffi.vault_android.Host
import uniffi.vault_android.KeySlot

/** The app's storage in memory, for the vector and release gate tests. */
class MemHost(var state: ByteArray?, var current: ByteArray?) : Host {
    var pending: ByteArray? = null
    var device: ByteArray? = null

    override fun readState() = state
    override fun writeState(state: ByteArray) {
        this.state = state
    }
    override fun readKey(slot: KeySlot) = if (slot == KeySlot.CURRENT) current else pending
    override fun writeKey(slot: KeySlot, key: ByteArray) {
        if (slot == KeySlot.CURRENT) current = key else pending = key
    }
    override fun deleteKey(slot: KeySlot) {
        if (slot == KeySlot.CURRENT) current = null else pending = null
    }
    override fun deleteBiometricWrap() = Unit
    override fun readDeviceId() = device
    override fun writeDeviceId(id: ByteArray) {
        device = id
    }
    override fun nowMs(): ULong = 1_800_000_000_000uL
    override fun elapsedRealtimeMs(): ULong = 1_000uL
}

object TestStates {
    fun hex(s: String): ByteArray = s.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    fun hex(b: ByteArray): String = b.joinToString("") { "%02x".format(it) }

    /** `local.json` as vault-client writes it, over [file]. */
    fun state(
        file: ByteArray,
        vaultId: String = "00".repeat(16),
        accepted: JSONObject? = null,
        wrapNonce: String = "00".repeat(24),
        retired: List<String> = emptyList(),
    ): ByteArray = JSONObject().apply {
        put("v", 1)
        put("vault_id", vaultId)
        put("accepted", accepted ?: JSONObject.NULL)
        put("wrap_nonce", wrapNonce)
        put("retired", JSONArray(retired.map { JSONObject().put("nonce", it).put("revision", JSONObject.NULL) }))
        put("refused", JSONArray())
        put("secret_key_store", "file")
        put("pending_secret_key", false)
        put("stopped", JSONObject.NULL)
        put("dropped", JSONArray())
        put("last_sync", JSONObject.NULL)
        put("file", hex(file))
    }.toString().toByteArray()
}
