package com.codeheadsystems.vault.net

import com.codeheadsystems.vault.storage.AtomicFiles
import org.json.JSONObject
import uniffi.vault_android.SetupText

/**
 * The server URL, token, and certificate fingerprint (docs/android.md, Storage), in `filesDir`
 * as `server.json`, as the CLI keeps them. The library never sees it: the app makes every request.
 */
data class ServerConfig(val url: String, val token: String, val fp: String?) {
    /** The URL of a request path such as `/v1/vault`. */
    fun resolve(path: String) = url.trimEnd('/') + path

    fun toJson(): ByteArray = JSONObject().apply {
        put("url", url)
        put("token", token)
        put("fp", fp ?: JSONObject.NULL)
    }.toString().toByteArray()

    companion object {
        const val FILE = "server.json"

        fun of(setup: SetupText) = ServerConfig(setup.url, setup.token, setup.fp)

        fun read(files: AtomicFiles): ServerConfig? {
            val bytes = files.read(FILE) ?: return null
            val o = JSONObject(String(bytes))
            return ServerConfig(o.getString("url"), o.getString("token"), if (o.isNull("fp")) null else o.getString("fp"))
        }

        fun write(files: AtomicFiles, config: ServerConfig) = files.write(FILE, config.toJson())
    }
}
