package com.codeheadsystems.vault.flow

import com.codeheadsystems.vault.FakeCore
import com.codeheadsystems.vault.net.Http
import com.codeheadsystems.vault.net.ServerConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.vault_android.Answer
import uniffi.vault_android.Applied
import uniffi.vault_android.ErrorInfo
import uniffi.vault_android.Input
import uniffi.vault_android.KeySlot
import uniffi.vault_android.Prompt
import uniffi.vault_android.Report
import uniffi.vault_android.Request
import uniffi.vault_android.Step

/** A scripted machine: it returns [steps] in order and records what it was given. */
class FakeSteps(vararg steps: Step) : Steps {
    private val queue = ArrayDeque(steps.toList())
    val inputs = mutableListOf<Input>()
    val calls = mutableListOf<String>()
    var closed = false

    override fun start(): Step = queue.removeFirst().also { calls += "start" }
    override fun step(input: Input): Step = queue.removeFirst().also { inputs += input; calls += "step" }
    override fun applySave() {
        calls += "applySave"
    }
    override fun apply(background: Boolean): Applied {
        calls += "apply($background)"
        return APPLIED
    }
    override fun close() {
        closed = true
    }

    companion object {
        val APPLIED = Applied(true, false, false, emptyList(), false, false, true)
    }
}

class ProcedureRunnerTest {
    private val server = ServerConfig("https://nas.lan:8443/", "TOKEN", null)
    private val get = Request("GET", "/v1/vault", null, null, null)
    private val ok = Input.Response(200u, ByteArray(0), null)
    private val sent = mutableListOf<Request>()
    private val runner = ProcedureRunner(Transport { _, r -> sent += r; ok }, Dispatchers.Unconfined)

    private class Answers(vararg val answers: Answer, val keep: Boolean = true) : ProcedureUi {
        var i = 0
        override suspend fun answer(prompt: Prompt) = answers[i++]
        override suspend fun keepKit(kit: String, vaultId: String) = keep
    }

    @Test
    fun aDoneProcedureIsAppliedAndClosed() {
        val steps = FakeSteps(Step.Request(get), Step.Done(Report.Setup))
        val o = runBlocking { runner.run(steps, server, Declining, background = true) }
        assertSame(Report.Setup, o.report)
        assertSame(FakeSteps.APPLIED, o.applied)
        assertEquals(listOf("start", "step", "apply(true)"), steps.calls)
        assertEquals(listOf(get), sent)
        assertEquals(listOf<Input>(ok), steps.inputs)
        assertTrue(steps.closed)
    }

    @Test
    fun aFailedProcedureIsAppliedToo() {
        val steps = FakeSteps(Step.Failed(ErrorInfo("sync.stopped", "x")))
        val o = runBlocking { runner.run(steps, server, Declining, background = false) }
        assertEquals("sync.stopped", o.error!!.code)
        assertEquals(listOf("start", "apply(false)"), steps.calls)
        assertTrue(steps.closed)
    }

    @Test
    fun aKeptKitIsSavedBeforeTheProcedureGoesOn() {
        val steps = FakeSteps(Step.Save(KeySlot.PENDING, "VLT1-...", "00"), Step.Done(Report.RepairToken))
        runBlocking { runner.run(steps, server, Answers(), background = false) }
        assertEquals(listOf("start", "applySave", "step", "apply(false)"), steps.calls)
        assertEquals(listOf<Input>(Input.Saved), steps.inputs)
    }

    @Test
    fun aCancelledKitStopsWithNothingApplied() {
        val steps = FakeSteps(Step.Save(KeySlot.PENDING, "VLT1-...", "00"))
        val o = runBlocking { runner.run(steps, server, Answers(keep = false), background = false) }
        assertEquals("cancelled", o.error!!.code)
        assertNull(o.applied)
        assertEquals(listOf("start"), steps.calls)
        assertTrue(steps.closed)
    }

    @Test
    fun aSecretKeyAnswerIsZeroedOnceItCrossed() {
        val key = ByteArray(16) { 7 }
        val steps = FakeSteps(Step.Prompt(Prompt.SecretKey), Step.Done(Report.Setup))
        runBlocking { runner.run(steps, server, Answers(Answer.SecretKey(key)), background = false) }
        assertArrayEquals(ByteArray(16), key)
    }

    @Test
    fun aKeptProcedureIsNotClosed() {
        val steps = FakeSteps(Step.Done(Report.Setup))
        runBlocking { runner.run(steps, server, Declining, background = false, close = false) }
        assertEquals(false, steps.closed)
    }

    @Test
    fun aTransportFailureIsUnreachable() {
        val http = HttpTransport(Http(FakeCore(), debug = false))
        // Release refuses plain http before connecting; nothing listens on port 1.
        assertSame(Input.Unreachable, http.send(ServerConfig("http://127.0.0.1:1/", "T", null), get))
        assertSame(Input.Unreachable, http.send(ServerConfig("https://127.0.0.1:1/", "T", null), get))
    }
}
