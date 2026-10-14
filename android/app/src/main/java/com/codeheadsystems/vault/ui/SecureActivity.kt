package com.codeheadsystems.vault.ui

import android.os.Build
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import com.codeheadsystems.vault.VaultApplication

/**
 * The base of every activity (docs/android.md, Screen and memory): `FLAG_SECURE`, and the idle
 * lock's entry-point check in `onStart`. A touch in the app's own activities is activity.
 */
abstract class SecureActivity : ComponentActivity() {
    val app get() = application as VaultApplication

    /** Whether touches here count as activity; not in activities started for another app. */
    protected open val recordsActivity = true

    override fun onCreate(savedInstanceState: Bundle?) {
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        super.onCreate(savedInstanceState)
    }

    override fun onStart() {
        super.onStart()
        if (app.lockGuard.check()) onLocked()
    }

    /**
     * A touch first runs the idle check, so a screen showing the unlocked vault moves to the lock
     * screen instead of acting; only then does it count as activity.
     */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (ev.actionMasked == MotionEvent.ACTION_DOWN) {
            if (app.lockGuard.check()) {
                onLocked()
                return true
            }
            if (recordsActivity) app.lockGuard.recordActivity()
        }
        return super.dispatchTouchEvent(ev)
    }

    /** The session locked under this screen. */
    protected open fun onLocked() = Unit

    /** Marks a view's content as sensitive to accessibility services, on API 34 and later. */
    protected fun markSensitive(view: View) {
        if (Build.VERSION.SDK_INT >= 34) view.setAccessibilityDataSensitive(View.ACCESSIBILITY_DATA_SENSITIVE_YES)
    }
}

/**
 * The picker, save, and unlock screens: touches through or under another window are dropped, and
 * on API 31 and later other apps' overlays are hidden, so an overlay cannot steer a confirmation.
 */
abstract class ProtectedActivity : SecureActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= 31) window.setHideOverlayWindows(true)
    }

    override fun onContentChanged() {
        super.onContentChanged()
        window.decorView.filterTouchesWhenObscured = true
    }

    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (obscured(ev.flags)) return false
        return super.dispatchTouchEvent(ev)
    }

    companion object {
        /** Whether a touch went through or arrived under another visible window. */
        fun obscured(flags: Int) =
            flags and (MotionEvent.FLAG_WINDOW_IS_OBSCURED or MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED) != 0
    }
}
