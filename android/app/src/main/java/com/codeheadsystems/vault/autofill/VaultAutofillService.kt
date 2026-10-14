package com.codeheadsystems.vault.autofill

import android.app.PendingIntent
import android.content.Intent
import android.content.IntentSender
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.AutofillService
import android.service.autofill.Dataset
import android.service.autofill.FillCallback
import android.service.autofill.FillRequest
import android.service.autofill.FillResponse
import android.service.autofill.Presentations
import android.service.autofill.SaveCallback
import android.service.autofill.SaveInfo
import android.service.autofill.SaveRequest
import android.view.autofill.AutofillId
import android.widget.RemoteViews
import com.codeheadsystems.vault.R
import com.codeheadsystems.vault.VaultApplication
import uniffi.vault_android.AppPage
import uniffi.vault_android.Page

/**
 * The autofill service (docs/android.md, Autofill). Nothing about the vault reaches `system_server`
 * or the requesting app here: the response has one dataset with every value `null`, authenticated
 * by an `IntentSender` to [PickerActivity] that carries only a registry token.
 */
class VaultAutofillService : AutofillService() {
    private val app get() = application as VaultApplication

    override fun onFillRequest(request: FillRequest, cancellationSignal: CancellationSignal, callback: FillCallback) {
        app.lockGuard.check()
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess(null)
        val pkg = structure.activityComponent.packageName
        if (!ServiceGate.servesFill(request.flags, pkg, packageName)) return callback.onSuccess(null)
        val window = Structure.parse(ViewNodeAdapter.windows(structure)) ?: return callback.onSuccess(null)
        val requester = SigningLookup.of(packageManager, pkg)
        val target = FillTargets.of(requester, window)
        if (target.fields.isEmpty()) return callback.onSuccess(null)

        val token = app.fillRegistry.put(PendingFill(target.page, requester, target.fields.map { it.id to it.kind }))
        val sender = senderFor(PickerActivity::class.java, token, app.fillRegistry.nextRequestCode())
        val label = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, getString(R.string.fill_with_vault))
        }
        val dataset = if (Build.VERSION.SDK_INT >= 33) {
            Dataset.Builder(Presentations.Builder().setMenuPresentation(label).build())
        } else {
            @Suppress("DEPRECATION")
            Dataset.Builder(label)
        }
        for (f in target.fields) {
            @Suppress("DEPRECATION")
            dataset.setValue(f.id, null)
        }
        dataset.setAuthentication(sender)

        val response = FillResponse.Builder().addDataset(dataset.build())
        val passwords = target.fields.filter { it.kind == FieldKind.PASSWORD }.map { it.id }
        if (passwords.isNotEmpty()) {
            val usernames = target.fields.filter { it.kind == FieldKind.USERNAME }.map { it.id }
            val save = SaveInfo.Builder(SaveInfo.SAVE_DATA_TYPE_PASSWORD or SaveInfo.SAVE_DATA_TYPE_USERNAME, passwords.toTypedArray())
                .setFlags(SaveInfo.FLAG_SAVE_ON_ALL_VIEWS_INVISIBLE)
            if (usernames.isNotEmpty()) save.setOptionalIds(usernames.toTypedArray())
            response.setSaveInfo(save.build())
        }
        callback.onSuccess(response.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        app.lockGuard.check()
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess()
        val pkg = structure.activityComponent.packageName
        // A save request that arrives while the vault is locked, or from a refused package, is dropped.
        if (!ServiceGate.keepsSave(app.vault.isUnlocked(), pkg, packageName)) return callback.onSuccess()
        val window = Structure.parse(ViewNodeAdapter.windows(structure)) ?: return callback.onSuccess()
        val target = FillTargets.of(SigningLookup.of(packageManager, pkg), window)
        val password = target.fields.firstOrNull { it.kind == FieldKind.PASSWORD }?.value
        if (password.isNullOrEmpty()) return callback.onSuccess()
        val username = target.fields.firstOrNull { it.kind == FieldKind.USERNAME }?.value.orEmpty()
        val token = app.saveRegistry.put(PendingSave(target.page, username, password))
        callback.onSuccess(senderFor(SaveActivity::class.java, token, app.saveRegistry.nextRequestCode()))
    }

    private fun senderFor(activity: Class<*>, token: String, requestCode: Int): IntentSender {
        val intent = Intent(this, activity).putExtra(Registry.EXTRA_TOKEN, token)
        // FLAG_MUTABLE because the framework fills in its own extras; FLAG_CANCEL_CURRENT so a
        // request code left by an earlier process never lends this response its extras.
        val flags = PendingIntent.FLAG_CANCEL_CURRENT or
            (if (Build.VERSION.SDK_INT >= 31) PendingIntent.FLAG_MUTABLE else 0)
        return PendingIntent.getActivity(this, requestCode, intent, flags).intentSender
    }
}

/** What the picker needs: the page, the requesting app, and the fillable fields. */
class PendingFill(val page: Page, val requester: AppPage, val fields: List<Pair<AutofillId, FieldKind>>)

/** What the save activity needs: the page and the submitted values. */
class PendingSave(val page: Page, val username: String, val password: String)
