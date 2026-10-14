package com.codeheadsystems.vault.ui

import android.text.InputType
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.EditText
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.viewinterop.AndroidView

/**
 * A secret text field (docs/android.md, Screen and memory): a password keyboard type with learning
 * off, excluded from autofill. The caller clears it on submit through [onCreated]'s view. Its text
 * lives in the view only, never in saved state.
 */
@Composable
fun SecretField(hint: String, modifier: Modifier = Modifier, onCreated: (EditText) -> Unit = {}) {
    AndroidView(
        modifier = modifier,
        factory = { context ->
            EditText(context).apply {
                this.hint = hint
                inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
                imeOptions = imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
                importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
                isSaveEnabled = false
                onCreated(this)
            }
        },
    )
}
