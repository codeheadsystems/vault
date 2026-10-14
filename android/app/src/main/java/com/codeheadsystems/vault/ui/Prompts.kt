package com.codeheadsystems.vault.ui

import android.widget.EditText
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.codeheadsystems.vault.core.code
import com.codeheadsystems.vault.flow.ProcedureUi
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.vault_android.Answer
import uniffi.vault_android.ConfirmKind
import uniffi.vault_android.Prompt
import uniffi.vault_android.Purpose
import uniffi.vault_android.decodeSecretKey

/**
 * The procedures' prompts, and the app's own questions, drawn inside the main activity's content,
 * never in a dialog window: the activity's overlay protection and `FLAG_SECURE` cover them. The
 * master password and the secret key are typed only here, in the app's own activity. The host
 * lives in the application, so a parked prompt survives a configuration change; [declineAll]
 * answers whatever is pending when the activity goes away for good, so no procedure waits forever.
 */
class PromptHost(private val main: CoroutineContext = Dispatchers.Main) : ProcedureUi {
    /** The prompt on screen: a procedure prompt, a kit, or a question, with the reply it waits for. */
    class Pending(
        val prompt: Prompt?,
        val kit: String?,
        val vaultId: String?,
        val reply: CompletableDeferred<Any>,
        val question: String? = null,
    ) {
        /** The answer that declines this prompt. */
        val declined: Any get() = if (prompt != null) Answer.Declined else false
    }

    var pending by mutableStateOf<Pending?>(null)
        private set

    /** Scans a QR code for the secret key field; set by the activity on screen. */
    var scanner: (((String) -> Unit) -> Unit)? = null

    override suspend fun answer(prompt: Prompt): Answer = ask(Pending(prompt, null, null, CompletableDeferred())) as Answer

    override suspend fun keepKit(kit: String, vaultId: String): Boolean =
        ask(Pending(null, kit, vaultId, CompletableDeferred())) as Boolean

    /** A yes-or-no question of the app's own. */
    suspend fun confirm(question: String): Boolean =
        ask(Pending(null, null, null, CompletableDeferred(), question)) as Boolean

    /** Declines whatever is pending: the activity that would answer it is gone. */
    fun declineAll() {
        pending?.let { it.reply.complete(it.declined) }
    }

    private suspend fun ask(p: Pending): Any = withContext(main) {
        // One prompt at a time: an earlier one that nobody answered is declined.
        declineAll()
        pending = p
        try {
            p.reply.await()
        } finally {
            if (pending === p) pending = null
        }
    }

    /** Draws the pending prompt in place of the screen; false when nothing is pending. */
    @Composable
    fun content(): Boolean {
        val p = pending ?: return false
        when {
            p.question != null -> Panel(null) {
                Text(p.question)
                Buttons("Yes" to { p.reply.complete(true) }, "No" to { p.reply.complete(false) })
            }
            p.kit != null -> Kit(p)
            else -> PromptPanel(p, p.prompt!!)
        }
        return true
    }

    @Composable
    private fun Panel(title: String?, body: @Composable () -> Unit) {
        Column(Modifier.fillMaxWidth().verticalScroll(rememberScrollState()).padding(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            title?.let { Text(it, style = MaterialTheme.typography.headlineSmall) }
            body()
        }
    }

    @Composable
    private fun Buttons(vararg buttons: Pair<String, () -> Unit>) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            buttons.forEachIndexed { i, (label, action) ->
                if (i == 0) Button(onClick = action) { Text(label) } else OutlinedButton(onClick = action) { Text(label) }
            }
        }
    }

    @Composable
    private fun Kit(p: Pending) {
        val qr = remember(p.kit) { QrImage.encode(p.kit!!, 600) }
        Panel("Emergency kit") {
            Text("The new secret key. Store it with the emergency kit before going on; a new device needs it.")
            Text(p.kit!!, style = MaterialTheme.typography.titleMedium)
            Text("Vault ID: ${p.vaultId}")
            Image(qr.asImageBitmap(), "Secret key QR code", Modifier.size(220.dp))
            Buttons("I kept it" to { p.reply.complete(true) }, "Cancel" to { p.reply.complete(false) })
        }
    }

    @Composable
    private fun PromptPanel(p: Pending, prompt: Prompt) {
        var error by remember(prompt) { mutableStateOf<String?>(null) }
        // The fields' views, kept across recompositions; their text never enters Compose state.
        val fields = remember(prompt) { arrayOfNulls<EditText>(2) }
        var plain by remember(prompt) { mutableStateOf("") }

        fun text(e: EditText?): String = e?.text?.toString().orEmpty().also { e?.text?.clear() }

        val (title, body) = when (prompt) {
            is Prompt.MasterPassword -> purposeTitle(prompt.purpose) to (if (prompt.failed > 0u) "Wrong master password." else null)
            is Prompt.MasterPasswordAndSecretKey -> purposeTitle(prompt.purpose) to "The master password and the secret key changed on another device."
            is Prompt.OldMasterPassword -> "Current master password" to (if (prompt.failed > 0u) "Wrong master password." else null)
            is Prompt.NewMasterPassword -> "New master password" to prompt.rejected?.let { "Refused: $it" }
            Prompt.SecretKey -> "Secret key" to "Scan the QR code from vault key show or the emergency kit, or type the VLT1- text."
            Prompt.KitVaultId -> "Vault ID (optional)" to "The vault ID from the emergency kit, or leave it empty."
            is Prompt.Confirm -> confirmTitle(prompt.confirmation) to prompt.description
        }

        fun submit() {
            val answer: Answer? = when (prompt) {
                is Prompt.MasterPassword, is Prompt.OldMasterPassword -> Answer.Password(text(fields[0]))
                is Prompt.NewMasterPassword -> {
                    val a = text(fields[0])
                    val b = text(fields[1])
                    if (a != b) {
                        error = "The two passwords differ."
                        null
                    } else {
                        Answer.Password(a)
                    }
                }
                is Prompt.MasterPasswordAndSecretKey -> secretKey(text(fields[1]), { error = it }) { key ->
                    Answer.PasswordAndSecretKey(text(fields[0]), key)
                }
                Prompt.SecretKey -> secretKey(text(fields[0]), { error = it }) { Answer.SecretKey(it) }
                Prompt.KitVaultId -> vaultId(plain) { error = it }
                is Prompt.Confirm -> Answer.Confirmed(true)
            }
            if (answer != null) p.reply.complete(answer)
        }

        Panel(title) {
            body?.let { Text(it) }
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            when (prompt) {
                is Prompt.MasterPassword, is Prompt.OldMasterPassword ->
                    SecretField("Master password", Modifier.fillMaxWidth()) { fields[0] = it }
                is Prompt.NewMasterPassword -> {
                    SecretField("New master password", Modifier.fillMaxWidth()) { fields[0] = it }
                    SecretField("Again", Modifier.fillMaxWidth()) { fields[1] = it }
                }
                is Prompt.MasterPasswordAndSecretKey -> {
                    SecretField("Master password", Modifier.fillMaxWidth()) { fields[0] = it }
                    SecretField("Secret key (VLT1-...)", Modifier.fillMaxWidth()) { fields[1] = it }
                }
                Prompt.SecretKey -> {
                    SecretField("VLT1-...", Modifier.fillMaxWidth()) { fields[0] = it }
                    scanner?.let { scan ->
                        OutlinedButton(onClick = { scan { scanned -> fields[0]?.setText(scanned) } }) { Text("Scan QR code") }
                    }
                }
                Prompt.KitVaultId -> OutlinedTextField(plain, { plain = it }, Modifier.fillMaxWidth(), label = { Text("32 hex characters") })
                is Prompt.Confirm -> Unit
            }
            if (prompt is Prompt.Confirm) {
                Buttons("Yes" to { submit() }, "No" to { p.reply.complete(Answer.Confirmed(false)) })
            } else {
                Buttons("OK" to { submit() }, "Cancel" to { p.reply.complete(Answer.Declined) })
            }
        }
    }

    companion object {
        /** A typed or scanned secret key, decoded; the bytes cross into the library and are zeroed after. */
        fun secretKey(text: String, error: (String) -> Unit, answer: (ByteArray) -> Answer): Answer? = try {
            answer(decodeSecretKey(text))
        } catch (e: Exception) {
            error(if (e.code() == "secret_key_typo") "The secret key has a typo." else "Not a secret key (${e.code()}).")
            null
        }

        /** The optional vault ID from the kit: empty for none, else 32 hex characters. */
        fun vaultId(text: String, error: (String) -> Unit): Answer? {
            val t = text.trim().lowercase()
            return when {
                t.isEmpty() -> Answer.VaultId(null)
                !t.matches(Regex("[0-9a-f]{32}")) -> {
                    error("A vault ID is 32 hex characters.")
                    null
                }
                else -> Answer.VaultId(t.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
            }
        }

        private fun purposeTitle(p: Purpose) = when (p) {
            Purpose.UNLOCK -> "Master password"
            Purpose.CREDENTIALS_CHANGED -> "The master password changed on another device"
            Purpose.PENDING_SECRET_KEY -> "Master password, for the new secret key"
            Purpose.RECOVERY -> "Master password, for recovery"
            Purpose.REVISION -> "Master password of that revision"
        }

        private fun confirmTitle(k: ConfirmKind) = when (k) {
            ConfirmKind.DISCARD_LOCAL_CHANGES -> "Discard local changes?"
            ConfirmKind.NO_CREDENTIAL_CHANGE -> "No credential change?"
        }
    }
}
