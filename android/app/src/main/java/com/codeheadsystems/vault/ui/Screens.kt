package com.codeheadsystems.vault.ui

import android.widget.EditText
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.unit.dp
import com.codeheadsystems.vault.clip.Clipboard
import com.codeheadsystems.vault.core.code
import com.codeheadsystems.vault.keystore.BiometricGate
import org.json.JSONArray
import org.json.JSONObject
import uniffi.vault_android.Entry
import uniffi.vault_android.ItemUri
import uniffi.vault_android.NewItem
import uniffi.vault_android.PasswdChange
import uniffi.vault_android.PasswordOptions
import uniffi.vault_android.generatePassphrase
import uniffi.vault_android.generatePassword

/** The plain UI of every screen. */
@Composable
fun Screens(a: MainActivity) {
    MaterialTheme {
        Column(Modifier.fillMaxSize().safeDrawingPadding().padding(12.dp)) {
            a.busy?.let { Text("$it…", color = MaterialTheme.colorScheme.primary) }
            a.message?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(bottom = 8.dp)) }
            // A pending prompt replaces the screen, inside this activity's protected content.
            if (!a.prompts.content()) when (val s = a.screen) {
                Screen.Setup -> SetupScreen(a)
                Screen.SetupDone -> SetupDoneScreen(a)
                Screen.Locked -> LockedScreen(a)
                Screen.Items -> ItemsScreen(a)
                is Screen.Item -> ItemScreen(a, s.id)
                is Screen.Edit -> EditScreen(a, s.id)
                Screen.Generate -> GenerateScreen(a)
                Screen.Passwd -> PasswdScreen(a)
                is Screen.KeyShow -> KeyShowScreen(a, s.text)
                is Screen.Restore -> RestoreScreen(a, s)
                Screen.RepairToken -> SetupTextScreen(a, "Repair the server token", "Use the new setup text") { a.repairToken(it) }
            }
        }
    }
}

@Composable
private fun SetupScreen(a: MainActivity) = SetupTextScreen(a, "Set up this phone", "Continue") { a.setup(it) }

/** Setup text from `vault serve token add`, scanned or pasted. */
@Composable
private fun SetupTextScreen(a: MainActivity, title: String, action: String, use: (String) -> Unit) {
    val field = remember { arrayOfNulls<EditText>(1) }
    Column {
        Text(title, style = MaterialTheme.typography.headlineSmall)
        Text("Scan the QR code from vault serve token add, or paste its setup text.")
        Button(onClick = { a.scan(use) }, enabled = a.busy == null) { Text("Scan setup QR code") }
        SecretField("vault://setup?...", Modifier.fillMaxWidth()) { field[0] = it }
        Button(onClick = {
            val f = field[0] ?: return@Button
            val text = f.text.toString()
            f.text.clear()
            use(text)
        }, enabled = a.busy == null) { Text(action) }
    }
}

@Composable
private fun SetupDoneScreen(a: MainActivity) {
    Column(Modifier.verticalScroll(rememberScrollState())) {
        Text("This phone is set up", style = MaterialTheme.typography.headlineSmall)
        if (BiometricGate.available(a) && a.app.vault.isUnlocked()) {
            Text("Unlock with a fingerprint from now on? The master password stays the way back.")
            Button(onClick = { a.enableBiometric() }) { Text("Turn on fingerprint unlock") }
        }
        HorizontalDivider(Modifier.padding(vertical = 8.dp))
        Text("Autofill", style = MaterialTheme.typography.titleMedium)
        Text("Choose Vault as the autofill service. Firefox needs nothing else.")
        Button(onClick = { a.openAutofillSettings() }) { Text("Choose the autofill service") }
        Text(
            "Chrome fills through another service only after you turn on Settings, Autofill services, " +
                "\"Autofill using another service\" in Chrome, and restart Chrome.",
        )
        Button(onClick = { a.screen = Screen.Items; a.refresh() }) { Text("Done") }
    }
}

@Composable
private fun LockedScreen(a: MainActivity) {
    Column {
        Text("Vault is locked", style = MaterialTheme.typography.headlineSmall)
        if (a.app.biometric.available(a)) {
            Button(onClick = { a.unlockWithBiometric() }, enabled = a.busy == null) { Text("Unlock with fingerprint") }
        }
        Button(onClick = { a.unlockWithPassword() }, enabled = a.busy == null) { Text("Unlock with master password") }
    }
}

@Composable
private fun ItemsScreen(a: MainActivity) {
    var query by remember { mutableStateOf("") }
    val version by a.app.changes.collectAsState()
    val rewrap by a.app.rewrapOffer.collectAsState()
    var entries by remember { mutableStateOf<List<Entry>>(emptyList()) }
    LaunchedEffect(query, version) {
        entries = try {
            a.app.vault.list(null, query.ifBlank { null })
        } catch (e: Exception) {
            a.message = "List failed: ${e.code()}"
            emptyList()
        }
    }
    Column {
        a.summary?.stopped?.let { st ->
            Text("Sync stopped: ${st.code}", color = MaterialTheme.colorScheme.error)
            when (st.reason) {
                "integrity" -> Button(onClick = { a.recover() }) { Text("Recover") }
                "token" -> Button(onClick = { a.screen = Screen.RepairToken }) { Text("Repair the server token") }
                else -> Button(onClick = { a.syncNow(askAgain = true) }) { Text("Enter the new credentials") }
            }
        }
        a.summary?.dropped?.takeIf { it.isNotEmpty() }?.let { dropped ->
            Text("Dropped by a sync, older than the purge horizon: ${dropped.joinToString()}")
            OutlinedButton(onClick = { a.app.vault.clearDropped(); a.refresh() }) { Text("OK") }
        }
        if (rewrap && BiometricGate.available(a)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Fingerprint unlock needs the new vault key.", Modifier.weight(1f))
                OutlinedButton(onClick = { a.enableBiometric() }) { Text("Turn on") }
            }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { a.screen = Screen.Edit(null) }) { Text("Add") }
            OutlinedButton(onClick = { a.syncNow() }, enabled = a.busy == null) { Text("Sync") }
            OutlinedButton(onClick = { a.lock() }) { Text("Lock") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { a.screen = Screen.Generate }) { Text("Generate") }
            OutlinedButton(onClick = { a.freshAuth("Change credentials") { a.screen = Screen.Passwd } }) { Text("Credentials") }
            OutlinedButton(onClick = { a.showSecretKey() }) { Text("Secret key") }
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { a.listRevisions() }) { Text("Restore") }
            OutlinedButton(onClick = { a.screen = Screen.RepairToken }) { Text("Server token") }
        }
        OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth(), label = { Text("Search") }, singleLine = true)
        if (a.app.vault.readOnly()) Text("A newer client wrote this vault: it opens read-only.")
        LazyColumn {
            items(entries, key = { it.id }) { e ->
                Column(Modifier.fillMaxWidth().clickable { a.screen = Screen.Item(e.id) }.padding(vertical = 8.dp)) {
                    Text(e.name, style = MaterialTheme.typography.titleMedium)
                    Text(listOf(e.folder, e.username).filter { it.isNotEmpty() }.joinToString(" · "))
                }
                HorizontalDivider()
            }
        }
    }
}

/** An item as the body schema defines it, read from `Vault.item`. */
private class ItemView(json: String) {
    val o = JSONObject(json)
    val name: String = o.optString("name")
    val folder: String = o.optString("folder")
    val notes: String = o.optString("notes")
    val type: String = o.optString("type")
    val login: JSONObject? = o.optJSONObject("login")
    val username: String = login?.optString("username").orEmpty()
    val password: String = login?.optString("password").orEmpty()
    val uris: List<Pair<String, String>> = login?.optJSONArray("uris")?.let { arr ->
        (0 until arr.length()).map { arr.getJSONObject(it).let { u -> u.optString("uri") to u.optString("match", "base_domain") } }
    }.orEmpty()
}

@Composable
private fun ItemScreen(a: MainActivity, id: String) {
    val item = remember(id) {
        try {
            ItemView(a.app.vault.item(id))
        } catch (e: Exception) {
            a.message = "Item unavailable: ${e.code()}"
            null
        }
    } ?: return
    // The password is fetched from the vault when shown or copied, never from this cached copy.
    var shown by remember { mutableStateOf<String?>(null) }
    Column(Modifier.verticalScroll(rememberScrollState())) {
        Text(item.name, style = MaterialTheme.typography.headlineSmall)
        if (item.folder.isNotEmpty()) Text("Folder: ${item.folder}")
        if (item.login != null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Username: ${item.username}", Modifier.weight(1f))
                OutlinedButton(onClick = { a.copyCredential(id, password = false) }) { Text("Copy") }
            }
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text("Password: " + (shown ?: "••••••••"), Modifier.weight(1f))
                OutlinedButton(onClick = {
                    shown = if (shown != null) null else a.credential(id)?.password
                }) { Text(if (shown != null) "Hide" else "Show") }
                OutlinedButton(onClick = { a.copyCredential(id, password = true) }) { Text("Copy") }
            }
            item.uris.forEach { (uri, match) -> Text("$uri ($match)") }
        }
        if (item.notes.isNotEmpty()) Text(item.notes, Modifier.padding(vertical = 8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = { a.screen = Screen.Edit(id) }) { Text("Edit") }
            OutlinedButton(onClick = {
                a.work("Delete") {
                    if (!a.prompts.confirm("Delete '${item.name}'?")) return@work
                    a.app.vault.remove(id)
                    a.app.localChange()
                    a.screen = Screen.Items
                }
            }) { Text("Delete") }
            OutlinedButton(onClick = { a.screen = Screen.Items }) { Text("Back") }
        }
    }
}

@Composable
private fun EditScreen(a: MainActivity, id: String?) {
    val base = remember(id) { id?.let { runCatching { a.app.vault.item(it) }.getOrNull() } }
    val item = remember(base) { base?.let { ItemView(it) } }
    var name by remember { mutableStateOf(item?.name.orEmpty()) }
    var folder by remember { mutableStateOf(item?.folder.orEmpty()) }
    var username by remember { mutableStateOf(item?.username.orEmpty()) }
    var uris by remember { mutableStateOf(item?.uris?.joinToString("\n") { it.first }.orEmpty()) }
    var notes by remember { mutableStateOf(item?.notes.orEmpty()) }
    var note by remember { mutableStateOf(item?.type == "note") }
    val password = remember { arrayOfNulls<EditText>(1) }
    Column(Modifier.verticalScroll(rememberScrollState())) {
        Text(if (id == null) "Add" else "Edit", style = MaterialTheme.typography.headlineSmall)
        if (id == null) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Checkbox(note, { note = it })
                Text("Secure note")
            }
        }
        OutlinedTextField(name, { name = it }, Modifier.fillMaxWidth(), label = { Text("Name") })
        OutlinedTextField(folder, { folder = it }, Modifier.fillMaxWidth(), label = { Text("Folder") })
        if (!note) {
            OutlinedTextField(username, { username = it }, Modifier.fillMaxWidth(), label = { Text("Username") })
            SecretField(if (id == null) "Password" else "New password (empty keeps it)", Modifier.fillMaxWidth()) { password[0] = it }
            OutlinedButton(onClick = {
                password[0]?.setText(generatePassword(PasswordOptions(20u, true, true, true, true, true)).value)
            }) { Text("Generate") }
            OutlinedTextField(uris, { uris = it }, Modifier.fillMaxWidth(), label = { Text("URIs, one per line") })
        }
        OutlinedTextField(notes, { notes = it }, Modifier.fillMaxWidth(), label = { Text("Notes") })
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(onClick = {
                val pw = password[0]?.text?.toString().orEmpty()
                password[0]?.text?.clear()
                val uriList = uris.lines().map { it.trim() }.filter { it.isNotEmpty() }
                a.work("Save") {
                    if (id == null) {
                        val newId = a.app.vault.add(
                            NewItem(if (note) "note" else "login", name, folder, false, notes, username, pw,
                                uriList.map { ItemUri(it, "base_domain") }),
                        )
                        a.screen = Screen.Item(newId)
                    } else {
                        a.app.vault.update(id, base!!, edited(base, name, folder, notes, username, pw, uriList))
                        a.screen = Screen.Item(id)
                    }
                    a.app.localChange()
                }
            }, enabled = a.busy == null && name.isNotBlank()) { Text("Save") }
            OutlinedButton(onClick = { a.screen = id?.let { Screen.Item(it) } ?: Screen.Items }) { Text("Cancel") }
        }
    }
}

/** The user's edited copy of [base]: the changed keys, keeping each kept URI's match mode. */
private fun edited(base: String, name: String, folder: String, notes: String, username: String, password: String, uris: List<String>): String {
    val o = JSONObject(base)
    o.put("name", name)
    o.put("folder", folder)
    o.put("notes", notes)
    o.optJSONObject("login")?.let { login ->
        login.put("username", username)
        if (password.isNotEmpty()) login.put("password", password)
        val old = login.optJSONArray("uris") ?: JSONArray()
        val byUri = (0 until old.length()).associate { old.getJSONObject(it).let { u -> u.optString("uri") to u } }
        login.put("uris", JSONArray(uris.map { byUri[it] ?: JSONObject().put("uri", it).put("match", "base_domain") }))
    }
    return o.toString()
}

@Composable
private fun GenerateScreen(a: MainActivity) {
    var length by remember { mutableStateOf("20") }
    var symbols by remember { mutableStateOf(true) }
    var avoidAmbiguous by remember { mutableStateOf(true) }
    var words by remember { mutableStateOf("6") }
    var value by remember { mutableStateOf<String?>(null) }
    Column {
        Text("Generate", style = MaterialTheme.typography.headlineSmall)
        OutlinedTextField(length, { length = it }, label = { Text("Length") })
        Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(symbols, { symbols = it }); Text("Symbols") }
        Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(avoidAmbiguous, { avoidAmbiguous = it }); Text("Avoid ambiguous characters") }
        Button(onClick = {
            value = try {
                generatePassword(PasswordOptions(length.toUInt(), true, true, true, symbols, avoidAmbiguous)).value
            } catch (e: Exception) {
                a.message = "Generator: ${e.code()}"
                null
            }
        }) { Text("Password") }
        OutlinedTextField(words, { words = it }, label = { Text("Words") })
        Button(onClick = {
            value = try {
                generatePassphrase(words.toUInt(), "-").value
            } catch (e: Exception) {
                a.message = "Generator: ${e.code()}"
                null
            }
        }) { Text("Passphrase") }
        value?.let {
            Text(it, Modifier.padding(vertical = 8.dp))
            OutlinedButton(onClick = { Clipboard.copySecret(a, "password", it) }) { Text("Copy") }
        }
        OutlinedButton(onClick = { value = null; a.screen = Screen.Items }) { Text("Back") }
    }
}

@Composable
private fun PasswdScreen(a: MainActivity) {
    var change by remember { mutableStateOf(PasswdChange.NEW_PASSWORD) }
    val options = listOf(
        PasswdChange.NEW_PASSWORD to "New master password",
        PasswdChange.REKEY to "New vault key only",
        PasswdChange.NEW_SECRET_KEY to "New secret key (after a lost device)",
        PasswdChange.NEW_SECRET_KEY_AND_PASSWORD to "New secret key and master password",
    )
    Column {
        Text("Change credentials", style = MaterialTheme.typography.headlineSmall)
        Text("Every change gives the vault a new vault key; other devices then ask for the master password once.")
        options.forEach { (c, label) ->
            Row(Modifier.clickable { change = c }, verticalAlignment = Alignment.CenterVertically) {
                RadioButton(change == c, { change = c })
                Text(label)
            }
        }
        Button(onClick = { a.passwd(change) }, enabled = a.busy == null) { Text("Change") }
        OutlinedButton(onClick = { a.screen = Screen.Items }) { Text("Cancel") }
    }
}

/** AND-8: the secret key as text and a QR code, after the master password. */
@Composable
private fun KeyShowScreen(a: MainActivity, text: String?) {
    text ?: return
    val qr = remember(text) { QrImage.encode(text, 600) }
    Column {
        Text("Secret key", style = MaterialTheme.typography.headlineSmall)
        Text(text, style = MaterialTheme.typography.titleMedium)
        Image(qr.asImageBitmap(), "Secret key QR code", Modifier.size(260.dp))
        Text("A new device needs this and the master password. It is never written to disk.")
        Button(onClick = { a.screen = Screen.Items }) { Text("Done") }
    }
}

@Composable
private fun RestoreScreen(a: MainActivity, s: Screen.Restore) {
    Column {
        Text("Restore a revision", style = MaterialTheme.typography.headlineSmall)
        LazyColumn(Modifier.weight(1f)) {
            items(s.revisions, key = { it.id.toString() }) { r ->
                Text(
                    "${r.id}  ${r.created}  ${r.token}  ${r.size} bytes",
                    Modifier.fillMaxWidth().clickable { a.restore(r) }.padding(vertical = 8.dp),
                )
                HorizontalDivider()
            }
        }
        OutlinedButton(onClick = { a.screen = Screen.Items }) { Text("Back") }
    }
}
