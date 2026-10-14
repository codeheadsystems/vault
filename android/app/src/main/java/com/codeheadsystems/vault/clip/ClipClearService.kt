package com.codeheadsystems.vault.clip

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import com.codeheadsystems.vault.R

/**
 * Keeps the process out of the cached-app freezer for the clipboard clear: a foreground service,
 * `shortService` on API 34 and later, an ordinary one below. It receives no extras.
 */
class ClipClearService : Service() {
    private val main = Handler(Looper.getMainLooper())
    private val clear = Runnable {
        Clipboard.clearIfOwn(this)
        stopSelf()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.clip_channel), NotificationManager.IMPORTANCE_LOW))
        val n = Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.clip_clearing))
            .setSmallIcon(android.R.drawable.ic_menu_close_clear_cancel)
            .build()
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SHORT_SERVICE)
        } else {
            startForeground(NOTIFICATION_ID, n)
        }
        // A second copy restarts the countdown.
        main.removeCallbacks(clear)
        main.postDelayed(clear, Clipboard.CLEAR_AFTER_MS)
        return START_NOT_STICKY
    }

    /**
     * A shortService that outlives its limit clears at once rather than being stopped uncleared:
     * API 34 calls the one-argument form, API 35 and later the two-argument one.
     */
    override fun onTimeout(startId: Int) {
        main.removeCallbacks(clear)
        clear.run()
    }

    override fun onTimeout(startId: Int, fgsType: Int) = onTimeout(startId)

    override fun onDestroy() {
        main.removeCallbacks(clear)
        super.onDestroy()
    }

    private companion object {
        const val CHANNEL = "clipboard"
        const val NOTIFICATION_ID = 1
    }
}
