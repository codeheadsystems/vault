package com.codeheadsystems.vault

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import com.codeheadsystems.vault.autofill.PendingFill
import com.codeheadsystems.vault.autofill.PendingSave
import com.codeheadsystems.vault.autofill.Registry
import com.codeheadsystems.vault.core.NativeCore
import com.codeheadsystems.vault.flow.Outcome
import com.codeheadsystems.vault.flow.ProcedureRunner
import com.codeheadsystems.vault.flow.ProcedureSteps
import com.codeheadsystems.vault.flow.SyncController
import com.codeheadsystems.vault.keystore.BiometricUnlock
import com.codeheadsystems.vault.keystore.Keys
import com.codeheadsystems.vault.lock.LockGuard
import com.codeheadsystems.vault.net.Http
import com.codeheadsystems.vault.net.ServerConfig
import com.codeheadsystems.vault.storage.AppHost
import com.codeheadsystems.vault.storage.AtomicFiles
import com.codeheadsystems.vault.storage.KeySlots
import com.codeheadsystems.vault.ui.PromptHost
import java.io.File
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import uniffi.vault_android.Vault

/** The one process, its one `Vault`, and the services around it (docs/android.md, Components). */
class VaultApplication : Application() {
    /** The local state and `server.json`. */
    val files by lazy { AtomicFiles(filesDir, ::fsyncDirectory) }

    /** The device ID and the wrapped keys, which no backup or transfer copies. */
    val noBackupFiles by lazy { AtomicFiles(noBackupFilesDir, ::fsyncDirectory) }
    val keySlots by lazy { KeySlots(noBackupFiles, Keys::storageKey) }

    val vault by lazy { Vault(AppHost(files, noBackupFiles, keySlots)) }
    val core by lazy { NativeCore(vault) }
    val lockGuard by lazy { LockGuard(core, SystemClock::elapsedRealtime, ::locked) }
    val biometric by lazy { BiometricUnlock(vault, keySlots) }
    val fillRegistry by lazy { Registry<PendingFill>(SystemClock::elapsedRealtime) }
    val saveRegistry by lazy { Registry<PendingSave>(SystemClock::elapsedRealtime) }

    val http by lazy { Http(core, BuildConfig.DEBUG) }
    val runner by lazy { ProcedureRunner(http) }

    /** Application-lifetime work: syncs, and procedures that must finish after a screen closes. */
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    val sync by lazy {
        SyncController(
            scope, runner, isUnlocked = { vault.isUnlocked() }, newSync = { ProcedureSteps(vault.beginSync(it)) },
            server = ::server, onFinished = ::procedureFinished,
        )
    }

    /** The procedures' prompts, held here so a configuration change does not strand one. */
    val prompts = PromptHost()

    /** Locks the session, and drops what only an unlocked session should hold. */
    fun lock() = lockGuard.lock()

    /** Every lock: the registries' pages, fields, and submitted values go with the session. */
    private fun locked() {
        fillRegistry.clear()
        saveRegistry.clear()
    }

    /** Bumped after every commit, so screens reload. */
    val changes = MutableStateFlow(0)

    /** Set when a commit changed `wrap_nonce`: the app offers to wrap the new vault key. */
    val rewrapOffer = MutableStateFlow(false)

    @Volatile private var serverCache: ServerConfig? = null

    /** The stored server URL, token, and fingerprint, or null before setup. */
    fun server(): ServerConfig? = serverCache ?: ServerConfig.read(files).also { serverCache = it }

    fun saveServer(config: ServerConfig) {
        ServerConfig.write(files, config)
        serverCache = config
    }

    /** After every procedure: a changed `wrap_nonce` offers a re-wrap, and screens reload. */
    fun procedureFinished(outcome: Outcome) {
        if (outcome.applied?.wrapChanged == true) rewrapOffer.value = true
        changes.value++
    }

    /** After a local edit: screens reload, and a background sync pushes it. */
    fun localChange() {
        changes.value++
        sync.request()
    }

    private val main = Handler(Looper.getMainLooper())
    private val backgroundCheck = Runnable { lockGuard.check() }

    override fun onCreate() {
        super.onCreate()
        ProcessLifecycleOwner.get().lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onStart(owner: LifecycleOwner) {
                main.removeCallbacks(backgroundCheck)
                lockGuard.onForeground()
                sync.startPeriodic()
            }

            override fun onStop(owner: LifecycleOwner) {
                lockGuard.onBackground()
                sync.stopPeriodic()
                // Runs only while the process is not frozen; the entry-point check covers the rest.
                main.postDelayed(backgroundCheck, LockGuard.BACKGROUND_LOCK_MS)
            }
        })
    }

    private fun fsyncDirectory(dir: File) {
        val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }
}
