package com.codeheadsystems.vault.autofill

import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import com.codeheadsystems.vault.core.code
import com.codeheadsystems.vault.ui.ProtectedActivity
import org.json.JSONObject
import uniffi.vault_android.Page
import uniffi.vault_android.SaveOffer

/**
 * The save offer (docs/android.md, Save offers). Its intent carries only a registry token; the
 * submitted values stay in the process. Nothing is saved without the user's confirmation.
 */
class SaveActivity : ProtectedActivity() {
    // Started for another app: its requests never count as activity (Idle lock).
    override val recordsActivity = false

    override fun onLocked() = finish()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // An entry point: the idle lock runs before the vault is read.
        app.lockGuard.check()
        val pending = app.saveRegistry.consume(intent.getStringExtra(Registry.EXTRA_TOKEN))
        if (pending == null || !app.vault.isUnlocked()) {
            finish()
            return
        }
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
        }
        setContentView(content)
        markSensitive(content)
        val offer = try {
            app.vault.saveOffer(pending.page, pending.username, pending.password)
        } catch (e: Exception) {
            content.addView(TextView(this).apply { text = "No save offer: ${e.code()}" })
            return
        }
        val description = describe(offer, pending) ?: return finish()
        content.addView(TextView(this).apply { text = description })
        content.addView(Button(this).apply {
            text = "Save"
            setOnClickListener {
                try {
                    app.vault.applySaveOffer(offer, pending.username, pending.password)
                } catch (e: Exception) {
                    content.addView(TextView(this@SaveActivity).apply { text = "Save failed: ${e.code()}" })
                    return@setOnClickListener
                }
                app.localChange()
                finish()
            }
        })
        content.addView(Button(this).apply {
            text = "Not now"
            setOnClickListener { finish() }
        })
    }

    private fun describe(offer: SaveOffer, pending: PendingSave): String? {
        val destination = when (val page = pending.page) {
            is Page.AndroidWeb -> "${page.scheme}://${page.host}"
            is Page.App -> page.app.packageName
        }
        val user = if (pending.username.isEmpty()) "" else " for ${pending.username}"
        return when (offer) {
            SaveOffer.None -> null
            is SaveOffer.Update -> {
                val name = try {
                    JSONObject(app.vault.item(offer.id)).optString("name")
                } catch (_: Exception) {
                    "the item"
                }
                "Update the password of '$name'$user on $destination?"
            }
            is SaveOffer.New -> "Save a new login '${offer.name}'$user for $destination?"
        }
    }
}
