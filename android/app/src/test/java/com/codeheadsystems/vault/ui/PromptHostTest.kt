package com.codeheadsystems.vault.ui

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.yield
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.vault_android.Answer
import uniffi.vault_android.Prompt

class PromptHostTest {
    private val host = PromptHost(Dispatchers.Unconfined)

    private suspend fun waitPending(): PromptHost.Pending {
        while (host.pending == null) yield()
        return host.pending!!
    }

    @Test
    fun anAnswerReachesTheProcedure() = runBlocking {
        val asked = async(Dispatchers.Default) { host.answer(Prompt.SecretKey) }
        waitPending().reply.complete(Answer.Password("pw"))
        assertEquals(Answer.Password("pw"), asked.await())
        assertNull(host.pending)
    }

    @Test
    fun declineAllEndsAPromptAKitAndAQuestion() = runBlocking {
        val prompt = async(Dispatchers.Default) { host.answer(Prompt.KitVaultId) }
        waitPending()
        host.declineAll()
        assertSame(Answer.Declined, prompt.await())

        val kit = async(Dispatchers.Default) { host.keepKit("VLT1-...", "00") }
        waitPending()
        host.declineAll()
        assertFalse(kit.await())

        val question = async(Dispatchers.Default) { host.confirm("Delete?") }
        waitPending()
        host.declineAll()
        assertFalse(question.await())
    }

    @Test
    fun aNewPromptDeclinesAnUnansweredOne() = runBlocking {
        val first = async(Dispatchers.Default) { host.answer(Prompt.SecretKey) }
        val p1 = waitPending()
        val second = async(Dispatchers.Default) { host.confirm("Restore?") }
        assertSame(Answer.Declined, first.await())
        while (host.pending === p1 || host.pending == null) yield()
        host.pending!!.reply.complete(true)
        assertTrue(second.await())
    }

    @Test
    fun theKitVaultIdIsOptionalHex() {
        var error: String? = null
        assertEquals(Answer.VaultId(null), PromptHost.vaultId("  ") { error = it })
        val id = PromptHost.vaultId("00".repeat(15) + "Ab") { error = it } as Answer.VaultId
        assertArrayEquals(ByteArray(15) + byteArrayOf(0xab.toByte()), id.vaultId)
        assertNull(PromptHost.vaultId("xyz") { error = it })
        assertEquals("A vault ID is 32 hex characters.", error)
    }

    @Test
    fun aSecretKeyTypoIsReportedBeforeAnyDerivation() {
        var error: String? = null
        assertNull(PromptHost.secretKey("VLT1-0000-0000-0000-0000-0000-0000-0000-0000", { error = it }) { Answer.SecretKey(it) })
        assertEquals("The secret key has a typo.", error)
    }
}
