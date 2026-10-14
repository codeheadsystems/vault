package com.codeheadsystems.vault.flow

import com.codeheadsystems.vault.net.Http
import com.codeheadsystems.vault.net.ServerConfig
import com.codeheadsystems.vault.net.TransportRefused
import java.io.IOException
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.vault_android.Answer
import uniffi.vault_android.Applied
import uniffi.vault_android.ErrorInfo
import uniffi.vault_android.Input
import uniffi.vault_android.Procedure
import uniffi.vault_android.Prompt
import uniffi.vault_android.Report
import uniffi.vault_android.Request
import uniffi.vault_android.Step

/** What a procedure asks of the user. A background run declines every prompt. */
interface ProcedureUi {
    suspend fun answer(prompt: Prompt): Answer

    /**
     * Shows the emergency kit of a new secret key and returns once the user confirmed keeping it,
     * or false to stop before anything is saved.
     */
    suspend fun keepKit(kit: String, vaultId: String): Boolean
}

/** A UI for background procedures: every prompt is declined, and no kit is ever saved. */
object Declining : ProcedureUi {
    override suspend fun answer(prompt: Prompt): Answer = Answer.Declined
    override suspend fun keepKit(kit: String, vaultId: String) = false
}

/**
 * How a procedure ended: the report or the error, and what `apply` committed; [applied] is null
 * when the user stopped at the kit, before anything was saved.
 */
class Outcome(val report: Report?, val error: ErrorInfo?, val applied: Applied?)

/** A `vault-client` machine as the runner steps it: the generated `Procedure`, or a fake in tests. */
interface Steps : AutoCloseable {
    fun start(): Step
    fun step(input: Input): Step
    fun applySave()
    fun apply(background: Boolean): Applied
}

/** [Steps] over the generated binding. */
class ProcedureSteps(val procedure: Procedure) : Steps {
    override fun start() = procedure.start()
    override fun step(input: Input) = procedure.step(input)
    override fun applySave() = procedure.applySave()
    override fun apply(background: Boolean) = procedure.apply(background)
    override fun close() = procedure.close()
}

/** One request to the server: its response, or `Unreachable`. */
fun interface Transport {
    fun send(server: ServerConfig, request: Request): Input
}

/**
 * Steps a `vault-client` machine (crates/vault-android/API.md, Procedures): each request goes to
 * the server through [transport], each prompt to [ProcedureUi], and every end, `Done` or `Failed`,
 * is applied. The procedure is closed when the run ends, so the keys it cloned do not outlive it,
 * unless the caller keeps it ([close] false) for a restore. A secret key the user typed is zeroed
 * once it has crossed into the library.
 */
class ProcedureRunner(private val transport: Transport, private val io: CoroutineContext = Dispatchers.IO) {

    constructor(http: Http) : this(HttpTransport(http))

    suspend fun run(procedure: Procedure, server: ServerConfig, ui: ProcedureUi, background: Boolean, close: Boolean = true): Outcome =
        run(ProcedureSteps(procedure), server, ui, background, close)

    suspend fun run(steps: Steps, server: ServerConfig, ui: ProcedureUi, background: Boolean, close: Boolean = true): Outcome {
        try {
            var step = io { steps.start() }
            while (true) {
                val current = step
                step = when (current) {
                    is Step.Request -> {
                        val input = io { transport.send(server, current.request) }
                        io { steps.step(input) }
                    }
                    is Step.Prompt -> {
                        val answer = ui.answer(current.prompt)
                        try {
                            io { steps.step(Input.Answer(answer)) }
                        } finally {
                            zero(answer)
                        }
                    }
                    is Step.Save -> {
                        if (!ui.keepKit(current.kit, current.vaultId)) {
                            return Outcome(null, ErrorInfo("cancelled", "the emergency kit was not kept"), null)
                        }
                        io {
                            steps.applySave()
                            steps.step(Input.Saved)
                        }
                    }
                    is Step.Done -> return Outcome(current.report, null, io { steps.apply(background) })
                    is Step.Failed -> return Outcome(null, current.error, io { steps.apply(background) })
                }
            }
        } finally {
            if (close) steps.close()
        }
    }

    private fun zero(answer: Answer) {
        when (answer) {
            is Answer.SecretKey -> answer.secretKey.fill(0)
            is Answer.PasswordAndSecretKey -> answer.secretKey.fill(0)
            else -> Unit
        }
    }

    private suspend fun <T> io(block: () -> T): T = withContext(io) { block() }
}

/** Requests through [Http]: a transport failure, a refusal, or a pin mismatch is `Unreachable`. */
class HttpTransport(private val http: Http) : Transport {
    override fun send(server: ServerConfig, request: Request): Input {
        val headers = buildMap {
            request.ifMatch?.let { put("If-Match", it) }
            request.ifNoneMatch?.let { put("If-None-Match", it) }
            if (request.body != null) put("Content-Type", "application/octet-stream")
        }
        return try {
            val resp = http.request(request.method, server.resolve(request.path), server.token, server.fp, headers, request.body)
            Input.Response(resp.code.toUShort(), resp.body, resp.dateMs.takeIf { it > 0 }?.toULong())
        } catch (_: IOException) {
            Input.Unreachable
        } catch (_: TransportRefused) {
            Input.Unreachable
        }
    }
}
