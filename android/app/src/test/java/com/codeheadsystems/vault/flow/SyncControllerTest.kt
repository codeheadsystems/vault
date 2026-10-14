package com.codeheadsystems.vault.flow

import com.codeheadsystems.vault.net.ServerConfig
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import uniffi.vault_android.Applied
import uniffi.vault_android.Input
import uniffi.vault_android.Report
import uniffi.vault_android.Step
import uniffi.vault_android.SyncMode

class SyncControllerTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private val server = ServerConfig("https://nas.lan:8443/", "T", null)
    private val started = AtomicInteger()
    private val finished = AtomicInteger()
    private val modes = mutableListOf<SyncMode>()
    @Volatile private var unlocked = true
    @Volatile private var gate = CompletableDeferred<Unit>().apply { complete(Unit) }
    @Volatile private var fail = false

    /** A sync machine that waits at [gate] in its first step. */
    private inner class Gated : Steps {
        override fun start(): Step {
            started.incrementAndGet()
            runBlocking { gate.await() }
            if (fail) throw IllegalStateException("boom")
            return Step.Done(Report.RepairToken)
        }
        override fun step(input: Input) = error("no step")
        override fun applySave() = Unit
        override fun apply(background: Boolean) = Applied(true, false, false, emptyList(), false, false, true)
        override fun close() = Unit
    }

    private val sync = SyncController(
        scope, ProcedureRunner({ _, _ -> Input.Unreachable }, Dispatchers.Default), { unlocked },
        { mode -> synchronized(modes) { modes += mode }; Gated() }, { server }, { finished.incrementAndGet() }, Dispatchers.Default,
    )

    private fun waitFor(n: Int, counter: AtomicInteger) = runBlocking {
        withTimeout(5_000) { while (counter.get() < n) delay(10) }
    }

    @Test
    fun aRequestDuringASyncRunsOneMoreAfterwards() {
        gate = CompletableDeferred()
        sync.request()
        waitFor(1, started)
        sync.request()
        sync.request()
        gate.complete(Unit)
        waitFor(2, finished)
        runBlocking { delay(200) }
        assertEquals("two requests during a sync give one more, not two", 2, started.get())
    }

    @Test
    fun aRequestDuringAnInteractiveSyncRunsAfterIt() = runBlocking {
        gate = CompletableDeferred()
        val interactive = async(Dispatchers.Default) { sync.interactive(Declining) }
        waitFor(1, started)
        sync.request()
        gate.complete(Unit)
        assertNotNull(interactive.await())
        waitFor(2, finished)
        assertEquals(listOf(SyncMode.INTERACTIVE, SyncMode.BACKGROUND), synchronized(modes) { modes.toList() })
    }

    @Test
    fun aFailedInteractiveSyncReleasesTheLock() {
        fail = true
        assertThrows(IllegalStateException::class.java) { runBlocking { sync.interactive(Declining) } }
        fail = false
        assertNotNull("the next sync runs", runBlocking { withTimeout(5_000) { sync.backgroundNow() } })
    }

    @Test
    fun nothingSyncsWhileLocked() {
        unlocked = false
        assertNull(runBlocking { sync.backgroundNow() })
        sync.request()
        runBlocking { delay(200) }
        assertEquals(0, started.get())
    }
}
