package com.codeheadsystems.vault.flow

import com.codeheadsystems.vault.net.ServerConfig
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import uniffi.vault_android.SyncMode

/**
 * Background sync (docs/android.md, Sync): after every local change and every 5 minutes while
 * unlocked and in the foreground. One sync runs at a time; a request during a sync, background or
 * interactive, runs one more afterwards. A locked vault cannot merge, so nothing runs while locked.
 * A background sync never prompts: what needs a prompt is recorded as `stopped`, which the main
 * screen shows. [newSync] builds a sync procedure; it runs on [io], as everything that touches the
 * library does.
 */
class SyncController(
    private val scope: CoroutineScope,
    private val runner: ProcedureRunner,
    private val isUnlocked: () -> Boolean,
    private val newSync: (SyncMode) -> Steps,
    private val server: () -> ServerConfig?,
    private val onFinished: (Outcome) -> Unit,
    private val io: CoroutineContext = Dispatchers.IO,
) {
    private val running = Mutex()
    @Volatile private var again = false
    private var periodic: Job? = null

    /** Requests a background sync; returns at once. */
    fun request() {
        scope.launch {
            if (!running.tryLock()) {
                again = true
                return@launch
            }
            try {
                do {
                    again = false
                    syncOnce(SyncMode.BACKGROUND, Declining, background = true)
                } while (again)
            } finally {
                running.unlock()
            }
        }
    }

    /**
     * An interactive sync, which may prompt; it waits for a background one to finish. A request
     * that arrives meanwhile runs afterwards.
     */
    suspend fun interactive(ui: ProcedureUi, askAgain: Boolean = false): Outcome? {
        try {
            return running.withLock {
                again = false
                syncOnce(if (askAgain) SyncMode.INTERACTIVE_ASK_AGAIN else SyncMode.INTERACTIVE, ui, background = false)
            }
        } finally {
            if (again) request()
        }
    }

    /** A background sync now, waiting for one already running; for a pull before an app binding. */
    suspend fun backgroundNow(): Outcome? {
        try {
            return running.withLock {
                again = false
                syncOnce(SyncMode.BACKGROUND, Declining, background = true)
            }
        } finally {
            if (again) request()
        }
    }

    private suspend fun syncOnce(mode: SyncMode, ui: ProcedureUi, background: Boolean): Outcome? {
        val config = server() ?: return null
        val steps = withContext(io) { if (isUnlocked()) newSync(mode) else null } ?: return null
        val outcome = try {
            runner.run(steps, config, ui, background)
        } catch (e: Exception) {
            if (!background) throw e
            return null
        }
        onFinished(outcome)
        return outcome
    }

    /** Starts the 5-minute sync while in the foreground. */
    fun startPeriodic() {
        periodic?.cancel()
        periodic = scope.launch {
            while (isActive) {
                delay(PERIOD_MS)
                if (withContext(io) { isUnlocked() }) request()
            }
        }
    }

    fun stopPeriodic() {
        periodic?.cancel()
        periodic = null
    }

    companion object {
        const val PERIOD_MS = 5 * 60_000L
    }
}
