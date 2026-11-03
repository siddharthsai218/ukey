package org.ukey

import java.security.Signature
import java.time.LocalTime
import java.time.format.DateTimeFormatter
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withTimeoutOrNull

enum class ConnectionPhase {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
}

data class ConnectionSnapshot(
    val phase: ConnectionPhase = ConnectionPhase.DISCONNECTED,
    val host: String = "127.0.0.1",
    val port: Int = 8443,
    val detail: String? = "Bridge not started",
)

enum class AuthKind {
    ASSERTION,
    ATTESTATION,
}

/**
 * A biometric request waiting for MainActivity. The Signature has already been
 * initialized with the hardware-backed key and fed the 32-byte host digest.
 */
data class AuthChallenge(
    val taskId: Long,
    val kind: AuthKind,
    val rpId: String,
    val credentialIdHex: String,
    val signature: Signature,
)

sealed class AuthOutcome {
    class Signed(val rawSignature: ByteArray) : AuthOutcome()
    data object Cancelled : AuthOutcome()
    data class Failure(val message: String) : AuthOutcome()
}

enum class LogOutcome {
    SUCCESS,
    CANCELLED,
    ERROR,
}

data class TransactionEntry(
    val time: String,
    val rpId: String,
    val action: String,
    val outcome: LogOutcome,
    val detail: String? = null,
)

/**
 * Process-wide bridge state shared by the foreground service and the activity.
 * The service owns the socket; the activity owns the BiometricPrompt.
 */
object BridgeState {
    private const val MAX_LOG_ENTRIES = 100
    private const val AUTH_TIMEOUT_MS = 25_000L
    private val timeFormat = DateTimeFormatter.ofPattern("HH:mm:ss")

    private val _connection = MutableStateFlow(ConnectionSnapshot())
    val connection: StateFlow<ConnectionSnapshot> = _connection.asStateFlow()

    private val _log = MutableStateFlow<List<TransactionEntry>>(emptyList())
    val log: StateFlow<List<TransactionEntry>> = _log.asStateFlow()

    private val _pending = MutableStateFlow<AuthChallenge?>(null)
    val pending: StateFlow<AuthChallenge?> = _pending.asStateFlow()

    private val lock = Any()
    private var waiter: CompletableDeferred<AuthOutcome>? = null
    private var waiterTaskId: Long = -1L

    /** True while MainActivity is resumed and can host a BiometricPrompt. */
    @Volatile
    var isUiResumed: Boolean = false

    fun setConnection(snapshot: ConnectionSnapshot) {
        _connection.value = snapshot
    }

    fun record(
        rpId: String,
        action: String,
        outcome: LogOutcome,
        detail: String? = null,
    ) {
        val entry = TransactionEntry(
            time = LocalTime.now().format(timeFormat),
            rpId = rpId.ifBlank { "(unknown RP)" },
            action = action,
            outcome = outcome,
            detail = detail,
        )
        _log.update { current -> (current + entry).takeLast(MAX_LOG_ENTRIES) }
    }

    fun clearLog() {
        _log.value = emptyList()
    }

    /**
     * Called by the socket handler. Suspends until the activity reports a
     * biometric result, the user/connection cancels, or the timeout expires.
     */
    suspend fun awaitAuthorization(challenge: AuthChallenge): AuthOutcome {
        val deferred = CompletableDeferred<AuthOutcome>()
        synchronized(lock) {
            if (waiter != null) {
                return AuthOutcome.Failure("authorization_already_pending")
            }
            waiter = deferred
            waiterTaskId = challenge.taskId
        }
        _pending.value = challenge

        return try {
            withTimeoutOrNull(AUTH_TIMEOUT_MS) { deferred.await() }
                ?: AuthOutcome.Failure("authorization_timed_out")
        } catch (cancelled: CancellationException) {
            throw cancelled
        } finally {
            synchronized(lock) {
                if (waiter === deferred) {
                    waiter = null
                    waiterTaskId = -1L
                }
            }
            if (_pending.value?.taskId == challenge.taskId) {
                _pending.value = null
            }
        }
    }

    /** Returns false when the request is no longer pending or was superseded. */
    fun submit(taskId: Long, outcome: AuthOutcome): Boolean {
        val deferred = synchronized(lock) {
            waiter?.takeIf { waiterTaskId == taskId }
        } ?: return false

        val accepted = deferred.complete(outcome)
        if (accepted) {
            if (_pending.value?.taskId == taskId) {
                _pending.value = null
            }
        }
        return accepted
    }

    fun cancelPending(reason: String) {
        val deferred = synchronized(lock) {
            waiter.also {
                waiter = null
                waiterTaskId = -1L
            }
        } ?: run {
            _pending.value = null
            return
        }
        _pending.value = null
        deferred.complete(AuthOutcome.Failure(reason))
    }

    fun resetForServiceStop(host: String, port: Int) {
        cancelPending("bridge_stopped")
        setConnection(
            ConnectionSnapshot(
                phase = ConnectionPhase.DISCONNECTED,
                host = host,
                port = port,
                detail = "Bridge stopped",
            ),
        )
    }
}
