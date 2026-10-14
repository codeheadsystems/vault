package com.codeheadsystems.vault.lock

import com.codeheadsystems.vault.FakeCore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LockGuardTest {
    private var now = 0L
    private val core = FakeCore({ now }).apply { unlock() }
    private var events = 0
    private val guard = LockGuard(core, { now }) { events++ }

    @Test
    fun locksAtTheEntryPointAfterTheIdleTime() {
        now = core.idleMs - 1
        assertFalse(guard.check())
        assertTrue(core.isUnlocked())
        now = core.idleMs
        assertTrue(guard.check())
        assertFalse(core.isUnlocked())
    }

    @Test
    fun activityInTheAppPostponesTheIdleLock() {
        now = core.idleMs - 1
        guard.recordActivity()
        now = core.idleMs + 1000
        assertFalse(guard.check())
    }

    @Test
    fun locksThirtySecondsAfterLeavingTheForegroundEvenWhenNoTimerRan() {
        guard.recordActivity()
        guard.onBackground()
        now += LockGuard.BACKGROUND_LOCK_MS - 1
        assertFalse(guard.check())
        now += 1
        // A frozen process ran no timer: the first entry point after the thaw locks.
        assertTrue(guard.check())
        assertFalse(core.isUnlocked())
    }

    @Test
    fun returningToTheForegroundInTimeKeepsTheSession() {
        guard.onBackground()
        now += LockGuard.BACKGROUND_LOCK_MS - 1
        guard.onForeground()
        now += LockGuard.BACKGROUND_LOCK_MS
        assertFalse(guard.check())
        assertTrue(core.isUnlocked())
    }

    @Test
    fun returningToTheForegroundLateLocks() {
        guard.onBackground()
        now += LockGuard.BACKGROUND_LOCK_MS
        guard.onForeground()
        assertFalse(core.isUnlocked())
    }

    @Test
    fun everyLockIsReportedOnce() {
        guard.check()
        now = core.idleMs
        assertTrue(guard.check())
        assertFalse(guard.check())
        assertEquals(1, events)
    }

    @Test
    fun aLockMadeElsewhereIsReportedAtTheNextCheck() {
        guard.check()
        // The core locked by itself during a session call.
        core.lock()
        assertTrue(guard.check())
        assertEquals(1, events)
    }

    @Test
    fun anExplicitLockIsReported() {
        guard.lock()
        assertFalse(core.isUnlocked())
        assertEquals(1, events)
    }
}
