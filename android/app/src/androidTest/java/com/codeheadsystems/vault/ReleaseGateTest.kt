package com.codeheadsystems.vault

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import uniffi.vault_android.Vault
import uniffi.vault_android.VaultException

/**
 * The release gate against the library inside the APK under test (docs/android.md, Build and
 * tests): every credentials vector file uses the test KDF parameters, which a release library
 * refuses before any key derivation. Run it against the release APK with
 * `./gradlew connectedAndroidTest -Pvault.testBuildType=release` and this class.
 */
@RunWith(AndroidJUnit4::class)
class ReleaseGateTest {
    @Test
    fun theShippedLibraryRefusesTestKdfHeaders() {
        val assets = InstrumentationRegistry.getInstrumentation().context.assets
        val v = JSONObject(assets.open("credentials.json").bufferedReader().readText())
        val cases = v.getJSONArray("cases")
        var n = 0
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            if (!c.has("file")) continue
            val pw = if (c.has("password_hex")) String(TestStates.hex(c.getString("password_hex"))) else ""
            val vault = Vault(MemHost(TestStates.state(TestStates.hex(c.getString("file"))), ByteArray(16)))
            val code = try {
                vault.unlock(pw)
                "ok"
            } catch (e: VaultException.Failed) {
                e.code
            }
            assertEquals(c.getString("name"), "integrity.test_kdf_in_release", code)
            assertEquals(c.getString("name"), c.getString("release_error"), code)
            n++
        }
        assertTrue("$n credential files", n > 0)
    }
}
