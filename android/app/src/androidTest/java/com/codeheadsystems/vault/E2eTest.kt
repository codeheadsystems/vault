package com.codeheadsystems.vault

import android.content.ClipboardManager
import android.content.Intent
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.UiObject2
import androidx.test.uiautomator.Until
import com.codeheadsystems.vault.autofill.PickerActivity
import com.codeheadsystems.vault.autofill.Registry
import com.codeheadsystems.vault.clip.Clipboard
import com.codeheadsystems.vault.flow.Outcome
import com.codeheadsystems.vault.flow.ProcedureUi
import com.codeheadsystems.vault.keystore.BiometricResult
import com.codeheadsystems.vault.net.Http
import com.codeheadsystems.vault.net.ServerConfig
import com.codeheadsystems.vault.net.TransportRefused
import com.codeheadsystems.vault.net.TransportRules
import com.codeheadsystems.vault.ui.MainActivity
import android.view.accessibility.AccessibilityEvent
import android.view.autofill.AutofillManager
import androidx.lifecycle.Lifecycle
import com.codeheadsystems.vault.autofill.PendingFill
import java.io.IOException
import java.util.concurrent.TimeoutException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import uniffi.vault_android.Answer
import uniffi.vault_android.AppPage
import uniffi.vault_android.Page
import uniffi.vault_android.NewItem
import uniffi.vault_android.PasswdChange
import uniffi.vault_android.Procedure
import uniffi.vault_android.Prompt
import uniffi.vault_android.Purpose
import uniffi.vault_android.Report
import uniffi.vault_android.SyncMode
import uniffi.vault_android.decodeSecretKey
import uniffi.vault_android.parseRevisions
import uniffi.vault_android.parseSetupText

/**
 * The end-to-end steps against a real `vault serve` and the CLI (docs/android.md, Build and
 * tests). `android/e2e/run.sh` runs the methods one at a time, in name order, and does the host's
 * part between them: CLI edits and credential changes, a garbage push, finger touches on the
 * emulator, and a new fingerprint enrolment. Arguments come from the driver.
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class E2eTest {
    private val args = InstrumentationRegistry.getArguments()
    private val app = ApplicationProvider.getApplicationContext<VaultApplication>()
    private val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())

    private fun arg(name: String): String = args.getString(name) ?: error("missing instrumentation argument $name")

    /** Answers prompts as a user who knows [password] (and [old] for the revision before it). */
    private inner class Scripted(val password: String, val newPassword: String? = null, val old: String? = null) : ProcedureUi {
        val asked = mutableListOf<Prompt>()
        override suspend fun answer(prompt: Prompt): Answer {
            asked += prompt
            return when (prompt) {
                is Prompt.MasterPassword ->
                    Answer.Password(if (prompt.purpose == Purpose.REVISION && old != null) old else password)
                is Prompt.OldMasterPassword -> Answer.Password(password)
                is Prompt.NewMasterPassword -> Answer.Password(newPassword ?: error("no new password"))
                Prompt.SecretKey -> Answer.SecretKey(decodeSecretKey(arg("sk")))
                Prompt.KitVaultId -> Answer.VaultId(null)
                is Prompt.MasterPasswordAndSecretKey -> Answer.PasswordAndSecretKey(password, decodeSecretKey(arg("sk")))
                is Prompt.Confirm -> Answer.Confirmed(true)
            }
        }

        override suspend fun keepKit(kit: String, vaultId: String) = true
    }

    private fun run(p: Procedure, ui: ProcedureUi, background: Boolean = false, close: Boolean = true): Outcome =
        runBlocking { app.runner.run(p, app.server()!!, ui, background, close) }

    private fun names() = app.vault.list(null, null).map { it.name }

    private fun unlock(password: String) {
        if (app.vault.isUnlocked()) app.vault.lock()
        val o = run(app.vault.beginUnlock(), Scripted(password))
        assertNull(o.error?.let { "${it.code}: ${it.message}" }, o.error)
        assertTrue(app.vault.isUnlocked())
    }

    private fun finger(n: Int) = Log.i(TAG, "finger $n")

    @Test
    fun e01_setup() {
        assertNull("the app holds no vault", app.vault.stateSummary())
        val config = ServerConfig.of(parseSetupText(arg("setup")))
        val o = runBlocking { app.runner.run(app.vault.beginSetup(), config, Scripted(arg("pw")), false) }
        assertNull(o.error?.let { "${it.code}: ${it.message}" }, o.error)
        assertTrue(o.applied!!.unlocked)
        app.saveServer(config)
        assertTrue(names().toString(), "cli-item-1" in names())
    }

    @Test
    fun e02_refusals() {
        val config = app.server()!!
        // A wrong pin never connects.
        val wrong = "00".repeat(32)
        assertThrows(IOException::class.java) { app.http.request("GET", config.resolve("/v1/vault"), config.token, wrong) }
        // The right pin does.
        assertEquals(200, app.http.request("GET", config.resolve("/v1/vault"), config.token, config.fp).code)
        // Release refuses http loopback included; debug allows loopback only.
        assertThrows(TransportRefused::class.java) { TransportRules.target("http://127.0.0.1:8080/", debug = false) }
        assertThrows(TransportRefused::class.java) { Http(app.core, debug = true).request("GET", "http://10.0.2.2:18080/", "t", null) }
        // The network security configuration refuses cleartext to a non-loopback host by itself.
        val conn = java.net.URL("http://10.0.2.2:18080/").openConnection()
        val e = assertThrows(IOException::class.java) { conn.getInputStream() }
        assertTrue(e.message, e.message!!.contains("Cleartext"))
        // A forged picker intent, from inside the app's own process, finds no token and finishes.
        val forged = Intent(app, PickerActivity::class.java).putExtra(Registry.EXTRA_TOKEN, "0".repeat(32))
        ActivityScenario.launch<PickerActivity>(forged).use { s ->
            assertEquals(Lifecycle.State.DESTROYED, s.state)
        }
        val page = Page.App(AppPage(TARGET, emptyList(), emptyList(), false))
        // A used token is as good as none.
        val used = app.fillRegistry.put(PendingFill(page, (page as Page.App).app, emptyList()))
        assertNotNull(app.fillRegistry.consume(used))
        ActivityScenario.launch<PickerActivity>(Intent(app, PickerActivity::class.java).putExtra(Registry.EXTRA_TOKEN, used)).use { s ->
            assertEquals(Lifecycle.State.DESTROYED, s.state)
        }
        // An extra the requesting app added, here a forged EXTRA_ASSIST_STRUCTURE, is never read:
        // the picker opens for the registered page, and the token stays usable until a fill.
        unlock(arg("pw"))
        val live = app.fillRegistry.put(PendingFill(page, page.app, emptyList()))
        val withExtra = Intent(app, PickerActivity::class.java)
            .putExtra(Registry.EXTRA_TOKEN, live)
            .putExtra(AutofillManager.EXTRA_ASSIST_STRUCTURE, "forged")
        ActivityScenario.launch<PickerActivity>(withExtra).use { s ->
            assertEquals(Lifecycle.State.RESUMED, s.state)
            assertNotNull(device.wait(Until.findObject(By.textStartsWith("Fill ")), 5_000))
        }
        assertNotNull(app.fillRegistry.peek(live))
    }

    @Test
    fun e03_unlockPullsAndPushes() {
        unlock(arg("pw"))
        assertTrue(names().toString(), "cli-item-2" in names())
        app.vault.add(NewItem("login", "phone-item", "", false, "", "phone-user", "phone-pass", emptyList()))
        val o = run(app.vault.beginSync(SyncMode.INTERACTIVE), Scripted(arg("pw")))
        assertNull(o.error?.code, o.error)
        val report = o.report as Report.Sync
        assertEquals("PUSHED", report.sync.outcome.name)
    }

    @Test
    fun e04_credentialChangeOnTheCli() {
        // The CLI changed the master password to pw2: a sync asks once for the new one.
        val ui = Scripted(arg("pw2"))
        val o = run(app.vault.beginSync(SyncMode.INTERACTIVE_ASK_AGAIN), ui)
        assertNull(o.error?.code, o.error)
        assertTrue(ui.asked.toString(), ui.asked.any { it is Prompt.MasterPassword && it.purpose == Purpose.CREDENTIALS_CHANGED })
        unlock(arg("pw2"))
    }

    @Test
    fun e05_credentialChangeHere() {
        unlock(arg("pw2"))
        val o = run(app.vault.beginPasswd(PasswdChange.NEW_PASSWORD, null), Scripted(arg("pw2"), arg("pw3")))
        assertNull(o.error?.code, o.error)
        assertTrue("a credential change gives a new wrap_nonce", o.applied!!.wrapChanged)
        unlock(arg("pw3"))
    }

    @Test
    fun e06_recovery() {
        // The driver pushed a garbage file with another token: the sync stops on integrity.
        unlock(arg("pw3"))
        run(app.vault.beginSync(SyncMode.BACKGROUND), Scripted(arg("pw3")), background = true)
        val stopped = app.vault.stateSummary()!!.stopped
        assertNotNull("sync stopped", stopped)
        assertEquals("integrity", stopped!!.reason)
        val o = run(app.vault.beginRecover(), Scripted(arg("pw3")))
        assertNull(o.error?.let { "${it.code}: ${it.message}" }, o.error)
        assertNull(app.vault.stateSummary()!!.stopped)
        assertTrue("phone-item" in names())
    }

    @Test
    fun e07_restore() {
        unlock(arg("pw3"))
        app.vault.remove(app.vault.list(null, "phone-item").single().id)
        run(app.vault.beginSync(SyncMode.INTERACTIVE), Scripted(arg("pw3")))
        assertFalse("phone-item" in names())
        val config = app.server()!!
        val list = parseRevisions(app.http.request("GET", config.resolve("/v1/revisions"), config.token, config.fp).body)
        // The newest revision that still held phone-item: the one before the removal's push.
        val revision = list[1]
        val p = app.vault.beginFetchRevision(revision.id)
        // The revision procedure stays open for the preview and the restore, then is closed.
        try {
            val o = run(p, Scripted(arg("pw3"), old = arg("pw2")), close = false)
            assertNull(o.error?.let { "${it.code}: ${it.message}" }, o.error)
            val preview = p.restorePreview(null)
            assertTrue("$preview", preview.added >= 1uL)
            p.restore(null)
            assertTrue("phone-item" in names())
            assertNull(run(app.vault.beginSync(SyncMode.INTERACTIVE), Scripted(arg("pw3"))).error)
        } finally {
            p.close()
        }
    }

    /** Runs [block] with the main activity and waits for its biometric result; the driver touches the sensor. */
    private fun biometric(block: (MainActivity, (BiometricResult) -> Unit) -> Unit): BiometricResult {
        var result: BiometricResult? = null
        val done = CountDownLatch(1)
        ActivityScenario.launch(MainActivity::class.java).use { s ->
            s.onActivity { a ->
                block(a) {
                    result = it
                    done.countDown()
                }
            }
            Thread.sleep(2_000)
            finger(1)
            assertTrue("no biometric result", done.await(30, TimeUnit.SECONDS))
        }
        return result!!
    }

    @Test
    fun e08_biometricUnlock() {
        unlock(arg("pw3"))
        assertEquals(BiometricResult.Ok, biometric { a, done -> app.biometric.enable(a, done) })
        app.vault.lock()
        assertEquals(BiometricResult.Ok, biometric { a, done -> app.biometric.unlock(a, "Unlock vault", done) })
        assertTrue(app.vault.isUnlocked())
    }

    /** Fills the target through the picker's own biometric unlock; the driver touches the sensor. */
    private fun fillWithBiometric(confirm: Boolean) {
        app.lock()
        launchTarget()
        openFill()
        finger(1)
        device.wait(Until.findObject(By.textStartsWith("e2e-app")), 30_000)!!.click()
        if (confirm) device.wait(Until.findObject(label("Fill")), 10_000)!!.click()
        assertFilled()
    }

    private fun apps(): Int =
        org.json.JSONObject(app.vault.item(app.vault.list(null, "e2e-app").single().id)).getJSONObject("login").getJSONArray("apps").length()

    @Test
    fun e08b_pickerBiometricUnlockBindsAfterItsPull() {
        // The daily path: locked, the picker unlocks by fingerprint, and a confirmed app fill binds
        // once the picker's sync has pulled.
        fillWithBiometric(confirm = true)
        val deadline = System.currentTimeMillis() + 20_000
        while (apps() == 0 && System.currentTimeMillis() < deadline) Thread.sleep(500)
        assertEquals("the confirmed fill bound the item", 1, apps())

        // Bound now: the next fill asks nothing, and no "without binding" message appears.
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        val warned = try {
            automation.executeAndWaitForEvent({ fillWithBiometric(confirm = false) }, { e ->
                e.eventType == AccessibilityEvent.TYPE_NOTIFICATION_STATE_CHANGED && e.text.any { "without binding" in it }
            }, 8_000)
            true
        } catch (_: TimeoutException) {
            false
        }
        assertFalse("a bound fill reported a missing binding", warned)
        assertEquals(1, apps())
    }

    @Test
    fun e09_biometricInvalidatedByEnrolment() {
        // The driver enrolled a second fingerprint.
        app.vault.lock()
        var result: BiometricResult? = null
        ActivityScenario.launch(MainActivity::class.java).use { s ->
            s.onActivity { a -> app.biometric.unlock(a, "Unlock vault") { result = it } }
        }
        assertEquals(BiometricResult.Invalidated, result)
        assertNull(app.keySlots.getBiometricWrap())
        assertFalse(app.vault.isUnlocked())
    }

    /** A label, whatever case the theme shows it in (buttons are upper case on some themes). */
    private fun label(text: String) = By.text(Pattern.compile("(?i)^" + Pattern.quote(text) + "$"))

    /** The framework fills after the picker returns; shows the fields until the values are in. */
    private fun assertFilled() {
        var filled: Any? = null
        for (attempt in 1..10) {
            device.wait(Until.findObject(label("Show")), 10_000)!!.click()
            filled = device.wait(Until.findObject(By.text("e2e-user|e2e-pass")), 1_000)
            if (filled != null) break
        }
        assertNotNull("the target's fields were not filled", filled)
    }

    private fun launchTarget() {
        val i = app.packageManager.getLaunchIntentForPackage(TARGET)!!.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        app.startActivity(i)
        assertTrue(device.wait(Until.hasObject(By.pkg(TARGET).depth(0)), 10_000))
    }

    private fun focusUsername() {
        device.wait(Until.findObject(By.text("Username")), 10_000)!!.click()
    }

    /** Focuses the username field until the vault's dropdown shows, and taps it. */
    private fun openFill() {
        repeat(3) {
            focusUsername()
            device.wait(Until.findObject(By.text("Fill with vault")), 5_000)?.let {
                it.click()
                return
            }
            // A focus change makes a new fill request.
            device.findObject(By.text("Password"))?.click()
        }
        error("no Fill with vault dropdown")
    }

    @Test
    fun e10_idleLockAtTheNextEntryPoint() {
        // Without a biometric wrap, the picker can only send the user to the app.
        app.biometric.disable()
        unlock(arg("pw3"))
        app.vault.setIdleTime(1_500uL)
        Thread.sleep(2_000)
        // A fill request is an entry point: it locks first, and the picker then has no session.
        launchTarget()
        openFill()
        assertNotNull(device.wait(Until.findObject(label("Open vault to unlock")), 10_000))
        assertFalse(app.vault.isUnlocked())
        device.pressBack()
        app.vault.setIdleTime(300_000uL)
    }

    @Test
    fun e11_appFill() {
        unlock(arg("pw3"))
        launchTarget()
        openFill()
        // The CLI's item for androidapp://<target> is an unbound association: a confirmation.
        device.wait(Until.findObject(By.textStartsWith("e2e-app")), 10_000)!!.click()
        // e08b bound the item already: a confirmation appears only for an unbound one.
        device.wait(Until.findObject(label("Fill")), 3_000)?.click()
        assertFilled()
        assertEquals("bound to the target's certificate once", 1, apps())
    }

    @Test
    fun e12_saveOffer() {
        unlock(arg("pw3"))
        launchTarget()
        focusUsername()
        device.pressBack() // the dropdown
        device.findObject(By.text("Username")).text = "saved-user"
        device.findObject(By.text("Password")).text = "saved-pass"
        device.findObject(label("Sign in")).click()
        device.wait(Until.findObject(By.res("android:id/autofill_save_yes")), 10_000)!!.click()
        device.wait(Until.findObject(label("Save")), 10_000)!!.click()
        assertTrue(device.wait(Until.gone(By.pkg(app.packageName)), 10_000))
        val saved = app.vault.list(null, "saved-user")
        assertEquals(saved.toString(), 1, saved.size)
        assertEquals(TARGET, saved.single().name)
    }

    /** Opens [url] in Firefox past any first-run screen or nag, and returns its username field. */
    private fun openInFirefox(url: String): UiObject2 {
        val i = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)).setPackage(FIREFOX).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        app.startActivity(i)
        // Firefox may show its first-run screens, or ask to become the default browser or to send
        // notifications, before the page.
        val dismiss = By.text(Pattern.compile("(?i)^(continue|not now|no thanks|cancel|don.t ask again)$"))
        var field = device.wait(Until.findObject(By.res("username")), 5_000)
        var last: String? = null
        repeat(20) { attempt ->
            if (field != null) return@repeat
            val prompt = device.findObject(dismiss)
            val text = prompt?.text
            // First-run screens can swallow the URL: with nothing new to dismiss (a home-page card
            // can keep a "Continue" button on screen), open it again.
            if (prompt != null && text != last) {
                Log.i(TAG, "firefox attempt $attempt: $text")
                prompt.click()
            } else {
                Log.i(TAG, "firefox attempt $attempt: opening the page again")
                app.startActivity(i)
            }
            last = text
            field = device.wait(Until.findObject(By.res("username")), 4_000)
        }
        return field!!
    }

    @Test
    fun e13_webFill() {
        val url = args.getString("webUrl") ?: return
        unlock(arg("pw3"))
        openInFirefox(url).click()
        device.wait(Until.findObject(By.text("Fill with vault")), 10_000)!!.click()
        device.wait(Until.findObject(By.textStartsWith("e2e-web")), 10_000)!!.click()
        // A private address over http is a local host: the scheme rule asks first.
        device.wait(Until.findObject(label("Fill")), 5_000)?.click()
        assertNotNull(device.wait(Until.findObject(By.text("web-user")), 10_000))
    }

    @Test
    fun e13b_webSaveOffer() {
        val url = args.getString("webUrl") ?: return
        unlock(arg("pw3"))
        // Each field is focused first; the vault's dropdown may then cover the page, and Back
        // closes it without leaving the page.
        fun type(field: UiObject2, text: String) {
            field.click()
            if (device.wait(Until.findObject(By.text("Fill with vault")), 2_000) != null) device.pressBack()
            field.text = text
        }
        type(openInFirefox(url), "webnew-user")
        type(device.findObject(By.res("password"))!!, "webnew-pass")
        // The keyboard can hide the button: Enter in the focused password field submits the form too.
        device.wait(Until.findObject(label("Sign in")), 2_000)?.click() ?: device.pressEnter()
        device.wait(Until.findObject(By.res("android:id/autofill_save_yes")), 15_000)!!.click()
        device.wait(Until.findObject(label("Save")), 10_000)!!.click()
        val deadline = System.currentTimeMillis() + 10_000
        var saved = app.vault.list(null, "webnew-user")
        while (saved.isEmpty() && System.currentTimeMillis() < deadline) {
            Thread.sleep(500)
            saved = app.vault.list(null, "webnew-user")
        }
        assertEquals(saved.toString(), 1, saved.size)
        // A web save records the page's scheme and host, with no port or path.
        val uris = saved.single().uris
        assertTrue(uris.toString(), uris.any { it.startsWith("http://10.0.2.2") && !it.contains(":18081") })
    }

    @Test
    fun e14_clipboardClear() {
        ActivityScenario.launch(MainActivity::class.java).use { s ->
            s.onActivity { a -> Clipboard.copySecret(a, "password", "clip-secret") }
            Thread.sleep(1_000)
            var text: CharSequence? = null
            s.onActivity { a -> text = a.getSystemService(ClipboardManager::class.java).primaryClip?.getItemAt(0)?.text }
            assertEquals("clip-secret", text?.toString())
            Thread.sleep(Clipboard.CLEAR_AFTER_MS + 2_000)
            var after: Boolean? = null
            s.onActivity { a -> after = a.getSystemService(ClipboardManager::class.java).hasPrimaryClip() }
            assertEquals(false, after)
        }
    }

    companion object {
        const val TAG = "VAULTE2E"
        const val TARGET = "com.codeheadsystems.vault.e2etarget"
        const val FIREFOX = "org.mozilla.firefox"
    }
}
