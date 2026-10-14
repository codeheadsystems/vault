package com.codeheadsystems.vault.autofill

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.Presentations
import android.util.Log
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.Button
import android.widget.LinearLayout
import android.widget.RemoteViews
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import com.codeheadsystems.vault.VaultApplication
import com.codeheadsystems.vault.core.code
import com.codeheadsystems.vault.keystore.BiometricResult
import com.codeheadsystems.vault.ui.MainActivity
import com.codeheadsystems.vault.ui.ProtectedActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.vault_android.AppPage
import uniffi.vault_android.Binding
import uniffi.vault_android.Page
import uniffi.vault_android.explicitChoiceAllowed

/**
 * The dataset authentication target (docs/android.md, Autofill, step 3). It reads the registry
 * token and no other extra: the requesting app starts this activity's `IntentSender` in its own
 * process and can add extras, `EXTRA_ASSIST_STRUCTURE` included. The token is used only when a
 * dataset is returned, so a cancelled biometric prompt leaves it valid until it expires. It unlocks
 * only by biometric prompt; without one, it sends the user to the app. Every confirmation is drawn
 * in this activity's own protected window, never in a dialog.
 */
class PickerActivity : ProtectedActivity() {
    // Started for another app: its requests never count as activity (Idle lock).
    override val recordsActivity = false
    private var token: String? = null
    private lateinit var pending: PendingFill
    private lateinit var content: LinearLayout

    /** A choice to fill, with the question to ask first (null: none). */
    private class Choice(val id: String, val name: String, val username: String, val confirm: String?)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setResult(RESULT_CANCELED)
        // An entry point: the idle lock runs before the vault is read.
        app.lockGuard.check()
        token = intent.getStringExtra(Registry.EXTRA_TOKEN)
        val p = app.fillRegistry.peek(token)
        if (p == null) {
            finish()
            return
        }
        pending = p
        content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
        }
        setContentView(ScrollView(this).apply { addView(content) })
        markSensitive(content)
        if (app.vault.isUnlocked()) showCandidates() else unlock()
    }

    override fun onLocked() = finish()

    private fun message(text: String) {
        content.removeAllViews()
        content.addView(TextView(this).apply { this.text = text })
    }

    private fun button(text: String, action: () -> Unit) = Button(this).apply {
        this.text = text
        isAllCaps = false
        setOnClickListener { action() }
    }

    private fun unlock() {
        if (!app.biometric.available(this)) return openVault()
        app.biometric.unlock(this, "Unlock vault") { result ->
            when (result) {
                BiometricResult.Ok -> {
                    // A biometric reopen does not pull; a sync now lets a confirmed app fill bind.
                    app.sync.request()
                    showCandidates()
                }
                BiometricResult.Invalidated -> openVault()
                is BiometricResult.Failed -> finish()
            }
        }
    }

    /** No biometric: the master password is typed in the app's own task, never here. */
    private fun openVault() {
        content.removeAllViews()
        content.addView(TextView(this).apply { text = "The vault is locked." })
        content.addView(button("Open vault to unlock") {
            startActivity(Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            finish()
        })
    }

    private fun showCandidates() {
        val candidates = try {
            app.vault.candidates(pending.page)
        } catch (e: Exception) {
            return message("No candidates: ${e.code()}")
        }
        content.removeAllViews()
        content.addView(TextView(this).apply { text = "Fill ${destination()}" })
        for (c in candidates) {
            addChoice(Choice(c.id, c.name, c.username, Confirmations.forCandidate(c.outcome, c.appMatch, c.name, destination())))
        }
        if (candidates.isEmpty()) content.addView(TextView(this).apply { text = "No matching item." })
        if (explicitChoiceAllowed(pending.page)) {
            content.addView(button("Choose another item") { showAll(candidates.map { it.id }.toSet()) })
        }
    }

    /** Every other login; each needs a confirmation that names the item and the destination. */
    private fun showAll(listed: Set<String>) {
        val entries = try {
            app.vault.list(null, null).filter { it.itemType == "login" && it.supported && it.id !in listed }
        } catch (e: Exception) {
            return message("No items: ${e.code()}")
        }
        content.removeAllViews()
        content.addView(TextView(this).apply { text = "Fill ${destination()} with another item" })
        for (e in entries) addChoice(Choice(e.id, e.name, e.username, Confirmations.forExplicitChoice(e.name, destination())))
    }

    private fun addChoice(c: Choice) {
        content.addView(button(if (c.username.isEmpty()) c.name else "${c.name} (${c.username})") { pick(c) })
    }

    private fun destination(): String = when (val page = pending.page) {
        is Page.AndroidWeb -> "${page.scheme}://${page.host}"
        is Page.App -> AppLabel.display(appLabel(page.app.packageName), page.app.packageName)
    }

    private fun appLabel(pkg: String): CharSequence? = try {
        packageManager.getApplicationLabel(packageManager.getApplicationInfo(pkg, 0))
    } catch (_: Exception) {
        null
    }

    /** The confirmation, in this window: the overlay protection covers its buttons. */
    private fun pick(c: Choice) {
        val question = c.confirm ?: return fill(c)
        content.removeAllViews()
        content.addView(TextView(this).apply { text = question })
        content.addView(button("Fill") { fill(c) })
        content.addView(button("Cancel") { showCandidates() })
    }

    private fun fill(c: Choice) {
        if (app.fillRegistry.consume(token) == null) return finish()
        val credential = try {
            app.vault.credential(c.id)
        } catch (e: Exception) {
            return message("Fill failed: ${e.code()}")
        }
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1)
        val builder = if (Build.VERSION.SDK_INT >= 33) {
            Dataset.Builder(Presentations.Builder().setMenuPresentation(presentation).build())
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(presentation)
        }
        for ((id, kind) in pending.fields) {
            val value = if (kind == FieldKind.PASSWORD) credential.password else credential.username
            @Suppress("DEPRECATION")
            builder.setValue(id, AutofillValue.forText(value))
        }
        setResult(RESULT_OK, Intent().putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, builder.build()))
        Log.i(TAG, "dataset returned with ${pending.fields.size} fields")
        val page = pending.page
        if (page is Page.App) bindAfterFill(app, c.id, pending.requester)
        finish()
    }

    companion object {
        private const val TAG = "VaultPicker"

        /**
         * Records a confirmed app fill as a binding, after the fill itself went back to the app.
         * The library binds only after a pull in this unlock; when it says so, one background sync
         * runs first. A fill that still cannot bind stays unbound, and the user is told why.
         */
        fun bindAfterFill(app: VaultApplication, id: String, requester: AppPage) {
            app.scope.launch {
                suspend fun record() = withContext(Dispatchers.IO) { app.vault.recordAppFill(id, requester) }
                val binding = try {
                    var b = record()
                    if (b == Binding.NOT_PULLED && app.sync.backgroundNow()?.error == null) b = record()
                    b
                } catch (e: Exception) {
                    Log.w(TAG, "binding failed: ${e.code()}")
                    return@launch
                }
                Log.i(TAG, "binding $binding")
                when (binding) {
                    Binding.RECORDED -> app.localChange()
                    Binding.NOT_PULLED -> toast(app, "Filled without binding to the app: the vault could not sync")
                    Binding.UNCHANGED -> Unit
                }
            }
        }

        private fun toast(context: Context, text: String) = Toast.makeText(context, text, Toast.LENGTH_LONG).show()
    }
}
