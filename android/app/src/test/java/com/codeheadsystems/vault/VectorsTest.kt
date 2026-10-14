package com.codeheadsystems.vault

import java.io.File
import java.security.MessageDigest
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import uniffi.vault_android.AppMatch
import uniffi.vault_android.AppPage
import uniffi.vault_android.Input
import uniffi.vault_android.KnownSuffix
import uniffi.vault_android.Outcome
import uniffi.vault_android.Page
import uniffi.vault_android.Request
import uniffi.vault_android.SaveOffer
import uniffi.vault_android.Step
import uniffi.vault_android.SyncMode
import uniffi.vault_android.Vault
import uniffi.vault_android.VaultException
import uniffi.vault_android.androidWebPage
import uniffi.vault_android.appsAfterFill
import uniffi.vault_android.decodeSecretKey
import uniffi.vault_android.encodeSecretKey
import uniffi.vault_android.pageCandidates
import uniffi.vault_android.pageSaveOffer
import uniffi.vault_android.parseSetupText

/**
 * The spec vectors through the generated Kotlin and JNA against a host build of vault-android
 * (docs/android.md, Build and tests), as crates/vault-android/tests/vectors.rs runs them in Rust:
 * secret key text, setup text, opening and unlocking files with a build's release expectations,
 * the sync header checks through a sync procedure, and the Android autofill cases.
 */
class VectorsTest {
    private val dir = File(System.getProperty("vault.vectors")!!)

    private fun cases(name: String): List<JSONObject> {
        val v = JSONObject(File(dir, "$name.json").readText())
        val arr = v.getJSONArray("cases")
        return (0 until arr.length()).map { i ->
            arr.getJSONObject(i).also { c ->
                // Top-level inputs travel with each case.
                for (k in v.keys()) if (k != "cases" && !c.has(k)) c.put(k, v.get(k))
            }
        }
    }

    private fun hex(s: String) = TestStates.hex(s)
    private fun hex(b: ByteArray) = TestStates.hex(b)
    private fun state(file: ByteArray, vaultId: String = "00".repeat(16), accepted: JSONObject? = null, wrapNonce: String = "00".repeat(24), retired: List<String> = emptyList()) =
        TestStates.state(file, vaultId, accepted, wrapNonce, retired)
    private fun JSONObject.h(k: String) = hex(getString(k))

    private fun code(block: () -> Any?): String = try {
        block()
        "ok"
    } catch (e: VaultException.Failed) {
        e.code
    }

    /** The release expectation: the `release_` field when present. */
    private fun expected(c: JSONObject, key: String): String = when {
        c.has("release_$key") -> c.getString("release_$key")
        c.has("release_error") && (key == "error" || key == "result") -> c.getString("release_error")
        c.has(key) && !c.isNull(key) -> c.getString(key)
        else -> "ok"
    }

    private fun vaultOver(state: ByteArray, secretKey: ByteArray) = Vault(MemHost(state, secretKey))

    @Test
    fun secretKeyText() {
        for (c in cases("secret-key")) {
            val name = c.getString("name")
            if (c.getString("op") == "encode") {
                assertEquals(name, c.getString("text"), encodeSecretKey(c.h("secret_key")))
            } else {
                val got = try {
                    hex(decodeSecretKey(c.getString("input")))
                } catch (e: VaultException.Failed) {
                    e.code
                }
                assertEquals(name, if (c.has("error")) c.getString("error") else c.getString("secret_key"), got)
            }
        }
        assertEquals("usage", code { encodeSecretKey(ByteArray(15)) })
    }

    @Test
    fun setupText() {
        for (c in cases("setup").filter { it.getString("op") == "parse" }) {
            val name = c.getString("name")
            try {
                val v = parseSetupText(c.getString("input"))
                assertEquals(name, c.getString("url"), v.url)
                assertEquals(name, if (c.isNull("fp")) null else c.getString("fp"), v.fp)
                // The token's text form is the Crockford encoding the spec tests elsewhere.
                assertEquals(name, 32, v.token.length)
            } catch (e: VaultException.Failed) {
                assertEquals(name, c.getString("error"), e.code)
            }
        }
    }

    @Test
    fun openingFiles() {
        fun reopen(file: ByteArray, vk: ByteArray) = code { vaultOver(state(file), ByteArray(16)).reopen(vk, ByteArray(24)) }
        for (c in cases("tamper")) {
            val name = c.getString("name")
            val file = c.h("file")
            if (c.has("offset")) file[c.getInt("offset")] = (file[c.getInt("offset")].toInt() xor c.getInt("xor")).toByte()
            assertEquals("tamper $name", expected(c, "error_open"), reopen(file, c.h("vault_key")))
            val pw = String(c.h("password_hex"))
            assertEquals("tamper $name", expected(c, "error_unlock"), code { vaultOver(state(file), c.h("secret_key")).unlock(pw) })
        }
        for (c in cases("malformed")) {
            assertEquals("malformed ${c.getString("name")}", c.getString("result"), reopen(c.h("file"), c.h("vault_key")))
        }
        for (c in cases("vault-file").filter { it.getString("op") == "open" }) {
            assertEquals("vault-file ${c.getString("name")}", expected(c, "result"), reopen(c.h("file"), c.h("vault_key")))
        }
        // Credential change files use the test parameters, which the bindings refuse.
        for (c in cases("credentials").filter { it.has("file") }) {
            val pw = if (c.has("password_hex")) String(c.h("password_hex")) else ""
            assertEquals("credentials ${c.getString("name")}", c.getString("release_error"), code { vaultOver(state(c.h("file")), ByteArray(16)).unlock(pw) })
        }
    }

    /** The spec's server API over a list of stored files. */
    private class Server(val files: MutableList<ByteArray>) {
        fun handle(r: Request): Input = when {
            r.method == "GET" && r.path == "/v1/vault" ->
                files.lastOrNull()?.let { Input.Response(200u, it, null) } ?: Input.Response(404u, ByteArray(0), null)
            r.method == "PUT" && r.path == "/v1/vault" -> {
                val current = files.lastOrNull()?.let { etag(it) }
                val pass = (r.ifMatch != null && r.ifMatch == current) || (r.ifNoneMatch != null && current == null)
                if (pass) {
                    files += r.body!!
                    Input.Response(200u, ByteArray(0), null)
                } else {
                    Input.Response(412u, ByteArray(0), null)
                }
            }
            else -> Input.Response(400u, ByteArray(0), null)
        }

        fun etag(f: ByteArray) = "\"" + MessageDigest.getInstance("SHA-256").digest(f).joinToString("") { "%02x".format(it) } + "\""
    }

    @Test
    fun syncHeaderChecksThroughAProcedure() {
        val all = cases("sync")
        val accepted = all.first { it.getString("name") == "the accepted file itself" }
        var n = 0
        for (c in all.filter { it.getString("op") == "check_remote" }) {
            val name = c.getString("name")
            val st = c.getJSONObject("state")
            val acc = if (st.isNull("accepted")) null else st.getJSONObject("accepted").let {
                JSONObject().put("generation", it.getLong("generation")).put("hash", it.getString("file_hash"))
            }
            val retired = st.getJSONArray("retired_wrap_nonces").let { a -> (0 until a.length()).map { a.getString(it) } }
            val vault = vaultOver(state(accepted.h("file"), st.getString("vault_id"), acc, st.getString("wrap_nonce"), retired), ByteArray(16))
            vault.reopen(c.h("vault_key"), hex(st.getString("wrap_nonce")))
            val p = vault.beginSync(SyncMode.BACKGROUND)
            val server = Server(mutableListOf(c.h("file")))
            var step = p.start()
            while (step is Step.Request) step = p.step(server.handle(step.request))
            val error = when {
                c.has("error") && !c.isNull("error") -> c.getString("error")
                c.has("open") && c.getString("open") != "ok" -> c.getString("open")
                c.optString("wrap") == "changed" -> "sync.credentials_changed"
                else -> null
            }
            when {
                error != null && step is Step.Failed -> assertEquals(name, error, step.error.code)
                error == null && step is Step.Done -> Unit
                else -> fail("$name: $step")
            }
            n++
        }
        assertTrue("$n sync cases", n > 5)
    }

    /** The vectors' known-suffix lookup, as tests/vectors.rs defines it. */
    private class Table(val c: JSONObject) : KnownSuffix {
        override fun knownSuffix(host: String): String? {
            c.optJSONObject("suffix_answers")?.let { a -> if (a.has(host)) return if (a.isNull(host)) null else a.getString(host) }
            val known = c.getJSONArray("known_suffixes")
            return (0 until known.length()).map { known.getString(it) }
                .filter { host == it || host.endsWith(".$it") }
                .maxByOrNull { it.length }
        }
    }

    /** The vectors' compact items as body-schema items. */
    private fun itemsJson(items: JSONArray): String = JSONArray((0 until items.length()).map { i ->
        val c = items.getJSONObject(i)
        JSONObject().apply {
            put("id", c.get("id")); put("type", c.get("type")); put("name", c.get("name")); put("folder", "")
            put("favourite", false); put("notes", ""); put("fields", JSONArray()); put("password_history", JSONArray())
            put("created", 0); put("modified", 0); put("modified_by", "00".repeat(16))
            if (c.getString("type") == "login") {
                put("login", JSONObject().apply {
                    put("username", c.get("username")); put("password", c.get("password")); put("uris", c.get("uris"))
                    put("apps", c.optJSONArray("apps") ?: JSONArray()); put("totp", JSONObject.NULL); put("passkeys", JSONArray())
                })
            }
        }
    }).toString()

    private fun app(v: JSONObject): AppPage {
        fun list(k: String) = v.getJSONArray(k).let { a -> (0 until a.length()).map { a.getString(it) } }
        return AppPage(v.getString("package"), list("signers"), list("history"), v.getBoolean("multiple_signers"))
    }

    private fun outcome(o: Outcome) = if (o == Outcome.FILL) "fill" else "confirm"

    private fun offer(o: SaveOffer): Any = when (o) {
        SaveOffer.None -> JSONObject().put("action", "none")
        is SaveOffer.Update -> JSONObject().put("action", "update").put("id", o.id)
        is SaveOffer.New -> JSONObject().put("action", "new").put("name", o.name)
            .put("uris", JSONArray(o.uris.map { JSONObject().put("uri", it.uri).put("match", it.matchValue) }))
            .put("apps", JSONArray(o.apps.map { JSONObject().put("package", it.packageName).put("cert_sha256", it.certSha256) }))
    }

    /** An Android case through the free functions, or null for a web case. */
    private fun androidCase(c: JSONObject): Any? {
        val suffixes = Table(c)
        val web = { Page.AndroidWeb(c.getString("scheme"), c.getString("host")) }
        fun candidates(page: Page, items: JSONArray) = pageCandidates(page, itemsJson(items), suffixes)
        return when (c.getString("op")) {
            "android_page" -> androidWebPage(c.getString("scheme"), c.getString("host"))?.let {
                JSONObject().put("scheme", it.scheme).put("host", it.host).put("port", JSONObject.NULL)
                    .put("path_query", "/").put("origin", it.origin)
            } ?: JSONObject.NULL
            "android_match" -> {
                val item = JSONArray().put(JSONObject().put("id", "00000000-0000-4000-8000-000000000001").put("type", "login")
                    .put("name", "n").put("username", "u").put("password", "p")
                    .put("uris", JSONArray().put(JSONObject().put("uri", c.get("uri")).put("match", c.get("match")))))
                candidates(web(), item).firstOrNull()?.let { outcome(it.outcome) } ?: "none"
            }
            "android_items" -> JSONArray(candidates(web(), c.getJSONArray("items")).map { JSONObject().put("id", it.id).put("outcome", outcome(it.outcome)) })
            "android_save" -> offer(pageSaveOffer(web(), c.getString("username"), c.getString("password"), itemsJson(c.getJSONArray("items")), suffixes))
            "app_items" -> JSONArray(candidates(Page.App(app(c.getJSONObject("app"))), c.getJSONArray("items")).map {
                val kind = when (it.appMatch!!) {
                    AppMatch.FILL -> "fill"
                    AppMatch.REBIND -> "rebind"
                    AppMatch.SIGNATURE_CHANGED -> "signature_changed"
                    AppMatch.BIND -> "bind"
                    AppMatch.UNVERIFIED -> "unverified"
                }
                JSONObject().put("id", it.id).put("outcome", outcome(it.outcome)).put("kind", kind)
            })
            "app_bind" -> {
                val item = itemsJson(JSONArray().put(c.getJSONObject("item"))).removePrefix("[").removeSuffix("]")
                appsAfterFill(item, app(c.getJSONObject("app")))?.let { apps ->
                    JSONArray(apps.map { JSONObject().put("package", it.packageName).put("cert_sha256", it.certSha256) })
                } ?: JSONObject.NULL
            }
            "app_save" -> offer(pageSaveOffer(Page.App(app(c.getJSONObject("app"))), c.getString("username"), c.getString("password"), itemsJson(c.getJSONArray("items")), suffixes))
            else -> null
        }
    }

    /** A JSON value as text with sorted keys, so equality ignores key order. */
    private fun canon(v: Any?): String = when (v) {
        null, JSONObject.NULL -> "null"
        is JSONObject -> v.keys().asSequence().sorted().joinToString(",", "{", "}") { "\"$it\":" + canon(v.get(it)) }
        is JSONArray -> (0 until v.length()).joinToString(",", "[", "]") { canon(v.get(it)) }
        is String -> JSONObject.quote(v)
        is Number -> v.toLong().toString()
        else -> v.toString()
    }

    private fun same(a: Any?, b: Any?) = canon(a) == canon(b)

    @Test
    fun androidAutofillVectors() {
        var n = 0
        for (c in cases("autofill")) {
            val got = androidCase(c) ?: continue
            assertTrue("${c.getString("name")}: got $got, want ${c.get("result")}", same(got, c.get("result")))
            n++
        }
        assertTrue("$n Android cases", n >= 60)
    }
}
