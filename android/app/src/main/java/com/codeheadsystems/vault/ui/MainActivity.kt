package com.codeheadsystems.vault.ui

import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.lifecycleScope
import com.codeheadsystems.vault.BuildConfig
import com.codeheadsystems.vault.clip.Clipboard
import com.codeheadsystems.vault.core.code
import com.codeheadsystems.vault.flow.Outcome
import com.codeheadsystems.vault.keystore.BiometricGate
import com.codeheadsystems.vault.keystore.BiometricResult
import com.codeheadsystems.vault.net.ServerConfig
import com.codeheadsystems.vault.scan.ScanActivity
import com.codeheadsystems.vault.scan.ScanHandoff
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.vault_android.PasswdChange
import uniffi.vault_android.Report
import uniffi.vault_android.RevisionInfo
import uniffi.vault_android.StateSummary
import uniffi.vault_android.parseRevisions
import uniffi.vault_android.parseSetupText

/** The app's screens. */
sealed interface Screen {
    object Setup : Screen
    object SetupDone : Screen
    object Locked : Screen
    object Items : Screen
    data class Item(val id: String) : Screen
    data class Edit(val id: String?) : Screen
    object Generate : Screen
    object Passwd : Screen
    data class KeyShow(val text: String?) : Screen
    data class Restore(val revisions: List<RevisionInfo>) : Screen
    object RepairToken : Screen
}

/**
 * The launcher activity: `MAIN` and `LAUNCHER` only, and it reads no extras. It holds the one
 * screen state, runs procedures through [PromptHost], and keeps secrets out of saved state: no
 * `rememberSaveable`, no retained `ViewModel`, and secret fields in plain views.
 */
class MainActivity : ProtectedActivity() {
    var screen by mutableStateOf<Screen>(Screen.Locked)
    var busy by mutableStateOf<String?>(null)
    var message by mutableStateOf<String?>(null)
    var summary by mutableStateOf<StateSummary?>(null)

    private var onScanned: ((String) -> Unit)? = null
    private val scanLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        // The text never travels in the result intent: ScanActivity hands it over in-process.
        ScanHandoff.take()?.let { text -> onScanned?.invoke(text) }
        onScanned = null
    }

    val prompts get() = app.prompts

    fun scan(onText: (String) -> Unit) {
        onScanned = onText
        scanLauncher.launch(Intent(this, ScanActivity::class.java))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // Item views and the secret key are on this activity's screens (Screen and memory).
        if (Build.VERSION.SDK_INT >= 34) window.decorView.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
        prompts.scanner = ::scan
        refresh()
        setContent {
            Screens(this)
            BackHandler(enabled = screen !is Screen.Items && screen !is Screen.Locked && screen !is Screen.Setup) {
                screen = if (app.vault.isUnlocked()) Screen.Items else Screen.Locked
            }
        }
        lifecycleScope.launch { app.changes.collect { refresh() } }
    }

    override fun onStart() {
        super.onStart()
        refresh()
    }

    override fun onLocked() = refresh()

    override fun onDestroy() {
        // A prompt nobody can answer any more is declined, so its procedure ends.
        if (isFinishing) prompts.declineAll()
        if (prompts.scanner != null) prompts.scanner = null
        super.onDestroy()
    }

    /** Reloads the state summary and moves to the screen the vault's state calls for. */
    fun refresh() {
        summary = try {
            app.vault.stateSummary()
        } catch (e: Exception) {
            message = "State unreadable: ${e.code()}"
            null
        }
        screen = when {
            summary == null -> if (screen == Screen.SetupDone) screen else Screen.Setup
            !app.vault.isUnlocked() -> Screen.Locked
            screen is Screen.Locked || screen is Screen.Setup -> Screen.Items
            else -> screen
        }
    }

    /** Runs [block] off the main thread with [label] shown; an exception becomes the message. */
    fun work(label: String, block: suspend () -> Unit) {
        busy = label
        message = null
        app.scope.launch {
            try {
                block()
            } catch (e: Exception) {
                message = "$label failed: ${e.code()}"
            } finally {
                busy = null
                refresh()
            }
        }
    }

    private suspend fun <T> io(block: () -> T): T = withContext(Dispatchers.IO) { block() }

    private fun describe(o: Outcome): String? = o.error?.let { "${it.code}: ${it.message}" }

    // Setup (docs/android.md, Setup).

    fun setup(text: String) {
        val setup = try {
            parseSetupText(text.trim())
        } catch (e: Exception) {
            message = "Setup text refused: ${e.code()}"
            return
        }
        if (setup.loopbackHttp && !BuildConfig.DEBUG) {
            message = "Plain http is refused in release builds."
            return
        }
        val config = ServerConfig.of(setup)
        work("Setup") {
            val outcome = app.runner.run(io { app.vault.beginSetup() }, config, prompts, background = false)
            app.procedureFinished(outcome)
            if (outcome.error != null) {
                message = "Setup failed: ${describe(outcome)}"
            } else {
                io { app.saveServer(config) }
                screen = Screen.SetupDone
            }
        }
    }

    // Unlocking.

    fun unlockWithPassword() {
        val config = app.server()
        if (config == null) {
            screen = Screen.RepairToken
            return
        }
        work("Unlock") {
            val outcome = app.runner.run(io { app.vault.beginUnlock() }, config, prompts, background = false)
            app.procedureFinished(outcome)
            when {
                outcome.error != null -> message = "Unlock failed: ${describe(outcome)}"
                (outcome.report as? Report.Unlock)?.syncError != null -> message = "Offline: opened the local copy."
            }
            if (app.vault.isUnlocked() && !app.biometric.available(this) && BiometricGate.available(this)) app.rewrapOffer.value = true
        }
    }

    fun unlockWithBiometric() {
        app.biometric.unlock(this, "Unlock vault") { r ->
            when (r) {
                BiometricResult.Ok -> {
                    app.sync.request()
                    refresh()
                }
                BiometricResult.Invalidated -> message = "Fingerprint unlock was reset; unlock with the master password."
                is BiometricResult.Failed -> message = r.message.toString()
            }
        }
    }

    fun enableBiometric() {
        app.biometric.enable(this) { r ->
            app.rewrapOffer.value = false
            message = when (r) {
                BiometricResult.Ok -> "Fingerprint unlock is on."
                BiometricResult.Invalidated -> null
                is BiometricResult.Failed -> "Fingerprint unlock failed: ${r.message}"
            }
        }
    }

    fun lock() {
        app.lock()
        refresh()
    }

    // Sync and repair.

    fun syncNow(askAgain: Boolean = false) = work("Sync") {
        val outcome = app.sync.interactive(prompts, askAgain) ?: return@work
        if (outcome.error != null) message = "Sync stopped: ${describe(outcome)}"
    }

    fun recover() {
        val config = app.server() ?: return
        work("Recovery") {
            val outcome = app.runner.run(io { app.vault.beginRecover() }, config, prompts, background = false)
            app.procedureFinished(outcome)
            message = describe(outcome)?.let { "Recovery failed: $it" } ?: "Recovered."
        }
    }

    /** Token repair: new setup text for the same vault, after the server revoked the old token. */
    fun repairToken(text: String) {
        val setup = try {
            parseSetupText(text.trim())
        } catch (e: Exception) {
            message = "Setup text refused: ${e.code()}"
            return
        }
        if (setup.loopbackHttp && !BuildConfig.DEBUG) {
            message = "Plain http is refused in release builds."
            return
        }
        val config = ServerConfig.of(setup)
        work("Token repair") {
            val outcome = app.runner.run(io { app.vault.beginRepairToken() }, config, prompts, background = false)
            app.procedureFinished(outcome)
            if (outcome.error == null) {
                io { app.saveServer(config) }
                message = "Server token replaced."
                screen = if (app.vault.isUnlocked()) Screen.Items else Screen.Locked
            } else {
                message = "Token repair failed: ${describe(outcome)}"
            }
        }
    }

    // Fresh authentication before a credential change or a restore (Unlock and locking).

    fun freshAuth(title: String, then: () -> Unit) {
        if (app.biometric.available(this)) {
            app.biometric.confirm(this, title) { r ->
                when (r) {
                    BiometricResult.Ok -> then()
                    else -> passwordThen(title, then)
                }
            }
        } else {
            passwordThen(title, then)
        }
    }

    private fun passwordThen(title: String, then: () -> Unit) = work(title) {
        val answer = prompts.answer(uniffi.vault_android.Prompt.MasterPassword(uniffi.vault_android.Purpose.UNLOCK, 0u))
        val pw = (answer as? uniffi.vault_android.Answer.Password)?.password ?: return@work
        // Unlocking again checks the password against the local file; the session stays open.
        io { app.vault.unlock(pw) }
        then()
    }

    fun passwd(change: PasswdChange) {
        val config = app.server() ?: return
        work("Credential change") {
            val outcome = app.runner.run(io { app.vault.beginPasswd(change, null) }, config, prompts, background = false)
            app.procedureFinished(outcome)
            message = describe(outcome)?.let { "Credential change failed: $it" } ?: "Credentials changed."
            if (outcome.error == null) screen = Screen.Items
        }
    }

    fun showSecretKey() = work("Secret key") {
        val answer = prompts.answer(uniffi.vault_android.Prompt.MasterPassword(uniffi.vault_android.Purpose.UNLOCK, 0u))
        val pw = (answer as? uniffi.vault_android.Answer.Password)?.password ?: return@work
        val text = io { app.vault.secretKeyText(pw) }
        screen = Screen.KeyShow(text)
    }

    // Restore (CLI: vault restore).

    fun listRevisions() {
        val config = app.server() ?: return
        freshAuth("Restore") {
            work("Revisions") {
                val response = io { app.http.request("GET", config.resolve("/v1/revisions"), config.token, config.fp) }
                if (response.code != 200) {
                    message = "Revisions unavailable: HTTP ${response.code}"
                    return@work
                }
                screen = Screen.Restore(parseRevisions(response.body))
            }
        }
    }

    fun restore(revision: RevisionInfo) {
        val config = app.server() ?: return
        work("Restore") {
            val proc = io { app.vault.beginFetchRevision(revision.id) }
            try {
                val outcome = app.runner.run(proc, config, prompts, background = false, close = false)
                if (outcome.error != null) {
                    message = "Revision unavailable: ${describe(outcome)}"
                    return@work
                }
                val preview = io { proc.restorePreview(null) }
                val question = "Restore revision ${revision.id} (${revision.created})? " +
                    "${preview.added} added, ${preview.changed} changed, ${preview.removed} removed."
                if (!prompts.confirm(question)) return@work
                val done = io { proc.restore(null) }
                app.localChange()
                message = "Restored: ${done.added} added, ${done.changed} changed, ${done.removed} removed."
                screen = Screen.Items
            } finally {
                // The revision's keys go with the procedure.
                proc.close()
            }
        }
    }

    /** One item's credential, read from the vault now; null with a message when it cannot be. */
    fun credential(id: String): uniffi.vault_android.Credential? = try {
        app.vault.credential(id)
    } catch (e: Exception) {
        message = "Unavailable: ${e.code()}"
        refresh()
        null
    }

    /** Copies the username or password, read from the vault at the moment of the copy. */
    fun copyCredential(id: String, password: Boolean) {
        val c = credential(id) ?: return
        Clipboard.copySecret(this, if (password) "password" else "username", if (password) c.password else c.username)
    }

    /** Opens the system's autofill service choice for this app. */
    fun openAutofillSettings() {
        startActivity(Intent(Settings.ACTION_REQUEST_SET_AUTOFILL_SERVICE, Uri.parse("package:$packageName")))
    }
}
