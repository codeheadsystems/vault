package com.codeheadsystems.vault.e2etarget

import android.app.Activity
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** A login form: "Show" displays what was filled, "Sign in" submits and finishes. */
class LoginActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val user = EditText(this).apply {
            hint = "Username"
            setAutofillHints(View.AUTOFILL_HINT_USERNAME)
        }
        val pass = EditText(this).apply {
            hint = "Password"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setAutofillHints(View.AUTOFILL_HINT_PASSWORD)
        }
        val shown = TextView(this).apply { contentDescription = "filled" }
        setContentView(LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            fitsSystemWindows = true
            addView(user)
            addView(pass)
            addView(Button(this@LoginActivity).apply {
                text = "Show"
                setOnClickListener { shown.text = "${user.text}|${pass.text}" }
            })
            addView(Button(this@LoginActivity).apply {
                text = "Sign in"
                setOnClickListener { finish() }
            })
            addView(shown)
        })
    }
}
