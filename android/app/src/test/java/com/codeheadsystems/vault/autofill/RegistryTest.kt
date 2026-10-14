package com.codeheadsystems.vault.autofill

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class RegistryTest {
    private var now = 1_000L
    private val registry = Registry<String>({ now })

    @Test
    fun aTokenIsConsumedOnce() {
        val t = registry.put("page")
        assertEquals("page", registry.consume(t))
        assertNull(registry.consume(t))
        assertNull(registry.peek(t))
    }

    @Test
    fun peekingLeavesTheTokenUsable() {
        // A cancelled biometric prompt peeks; the token still works when the picker is reopened.
        val t = registry.put("page")
        assertEquals("page", registry.peek(t))
        assertEquals("page", registry.peek(t))
        assertEquals("page", registry.consume(t))
    }

    @Test
    fun aTokenExpiresAfterFiveMinutes() {
        val t = registry.put("page")
        now += Registry.TTL_MS - 1
        assertEquals("page", registry.peek(t))
        now += 1
        assertNull(registry.peek(t))
        assertNull(registry.consume(t))
    }

    @Test
    fun unknownAndMissingTokensGiveNothing() {
        registry.put("page")
        assertNull(registry.consume("0".repeat(32)))
        assertNull(registry.consume(null))
        assertNull(registry.peek(""))
    }

    @Test
    fun aLockClearsEveryEntry() {
        val t = registry.put("page")
        val u = registry.put("other")
        registry.clear()
        assertNull(registry.peek(t))
        assertNull(registry.consume(u))
        assertEquals(0, registry.size())
    }

    @Test
    fun tokensAreRandomHex() {
        val tokens = (1..100).map { registry.put("v$it") }
        assertEquals(100, tokens.toSet().size)
        assertTrue(tokens.all { it.matches(Regex("[0-9a-f]{32}")) })
    }

    @Test
    fun expiredEntriesArePurgedOnEveryRead() {
        repeat(3) { registry.put("v$it") }
        now += Registry.TTL_MS
        assertNull(registry.consume("absent"))
        assertEquals(0, registry.size())
    }

    @Test
    fun requestCodesAreUnique() {
        val codes = (1..1000).map { registry.nextRequestCode() }
        assertEquals(1000, codes.toSet().size)
        assertNotEquals(codes[0], codes[1])
    }
}
