package org.ukey.net

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.BufferedReader
import java.net.InetSocketAddress
import java.net.Socket
import kotlin.coroutines.cancellation.CancellationException
import kotlin.random.Random
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.ukey.BridgeState
import org.ukey.ConnectionPhase
import org.ukey.ConnectionSnapshot

/**
 * TCP client for the Linux daemon.
 *
 * The daemon may use either 4-byte big-endian length-prefixed UTF-8 JSON frames
 * or raw newline-delimited JSON. Framing is auto-detected from the first
 * message and responses mirror it, so the same client works with both.
 *
 * Auto-reconnect uses exponential backoff with jitter.
 */
class DaemonClient(
    private val host: String,
    private val port: Int,
    private val onMessage: suspend (String, JsonWire) -> Unit,
) : Closeable {

    @Volatile
    private var socket: Socket? = null

    @Volatile
    private var closed = false

    suspend fun run() {
        var backoffMs = INITIAL_BACKOFF_MS
        while (currentCoroutineContext().isActive && !closed) {
            BridgeState.setConnection(
                ConnectionSnapshot(
                    phase = ConnectionPhase.CONNECTING,
                    host = host,
                    port = port,
                    detail = "Connecting to daemon",
                ),
            )

            var connected = false
            var connectedAtNanos = 0L
            try {
                val connection = Socket()
                socket = connection
                connection.connect(InetSocketAddress(host, port), CONNECT_TIMEOUT_MS)
                connection.tcpNoDelay = true
                connection.keepAlive = true
                connected = true
                connectedAtNanos = System.nanoTime()

                BridgeState.setConnection(
                    ConnectionSnapshot(
                        phase = ConnectionPhase.CONNECTED,
                        host = host,
                        port = port,
                        detail = "Ready for biometric requests",
                    ),
                )
                serve(connection)
                if (!closed) {
                    BridgeState.setConnection(
                        ConnectionSnapshot(
                            phase = ConnectionPhase.DISCONNECTED,
                            host = host,
                            port = port,
                            detail = "Daemon disconnected",
                        ),
                    )
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (exc: Exception) {
                if (!closed) {
                    BridgeState.setConnection(
                        ConnectionSnapshot(
                            phase = ConnectionPhase.DISCONNECTED,
                            host = host,
                            port = port,
                            detail = exc.message ?: exc.javaClass.simpleName,
                        ),
                    )
                }
            } finally {
                closeSocket()
                BridgeState.cancelPending("connection_closed")
            }

            if (closed || !currentCoroutineContext().isActive) {
                break
            }

            val stableConnection = connected &&
                System.nanoTime() - connectedAtNanos >= STABLE_CONNECTION_NANOS
            if (stableConnection) {
                backoffMs = INITIAL_BACKOFF_MS
            }
            val jitter = Random.nextLong(0, 251)
            delay(backoffMs + jitter)
            backoffMs = (backoffMs * 2).coerceAtMost(MAX_BACKOFF_MS)
        }
    }

    override fun close() {
        closed = true
        closeSocket()
    }

    private suspend fun serve(connection: Socket) = coroutineScope {
        val wire = JsonWire(connection.getInputStream(), connection.getOutputStream())
        val incoming = Channel<String>(capacity = 1)
        val handler = launch {
            for (message in incoming) {
                onMessage(message, wire)
            }
        }

        try {
            while (isActive) {
                val message = wire.readMessage() ?: break
                incoming.send(message)
            }
        } finally {
            incoming.close()
            handler.cancel()
            BridgeState.cancelPending("connection_closed")
        }
    }

    private fun closeSocket() {
        val current = socket
        socket = null
        try {
            current?.close()
        } catch (_: IOException) {
            // Nothing useful to do during teardown.
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val INITIAL_BACKOFF_MS = 1_000L
        private const val MAX_BACKOFF_MS = 30_000L
        private const val STABLE_CONNECTION_NANOS = 5_000_000_000L
    }
}

class JsonWire(
    input: InputStream,
    output: OutputStream,
) {
    private enum class Framing {
        LINE,
        LENGTH_PREFIXED,
    }

    private val buffered = BufferedInputStream(input, BUFFER_SIZE)
    private val bufferedOutput = BufferedOutputStream(output, BUFFER_SIZE)
    private val writeLock = Any()
    private var framing: Framing? = null
    private var lineReader: BufferedReader? = null
    private var inputStream: InputStream? = null

    fun readMessage(): String? {
        return when (framing ?: detectFraming()) {
            Framing.LINE -> readLine()
            Framing.LENGTH_PREFIXED -> readFrame()
        }
    }

    fun writeMessage(message: String) {
        val payload = message.toByteArray(Charsets.UTF_8)
        require(payload.size <= MAX_MESSAGE_BYTES) { "response is too large" }

        synchronized(writeLock) {
            when (framing ?: Framing.LINE) {
                Framing.LINE -> {
                    bufferedOutput.write(payload)
                    bufferedOutput.write('\n'.code)
                }
                Framing.LENGTH_PREFIXED -> {
                    bufferedOutput.write(
                        byteArrayOf(
                            (payload.size ushr 24).toByte(),
                            (payload.size ushr 16).toByte(),
                            (payload.size ushr 8).toByte(),
                            payload.size.toByte(),
                        ),
                    )
                    bufferedOutput.write(payload)
                }
            }
            bufferedOutput.flush()
        }
    }

    private fun detectFraming(): Framing {
        buffered.mark(8)
        val first = buffered.read()
        if (first == -1) {
            throw EOFException("daemon closed the connection")
        }

        if (first == '{'.code || first == '\n'.code || first == '\r'.code ||
            first == ' '.code || first == '\t'.code
        ) {
            buffered.reset()
            return finishDetection(Framing.LINE)
        }

        val second = buffered.read()
        val third = buffered.read()
        val fourth = buffered.read()
        if (second == -1 || third == -1 || fourth == -1) {
            throw IOException("truncated length-prefixed frame header")
        }
        val length = (first shl 24) or (second shl 16) or (third shl 8) or fourth
        if (length !in 1..MAX_MESSAGE_BYTES) {
            throw IOException("invalid length-prefixed frame length: $length")
        }
        val firstPayloadByte = buffered.read()
        if (firstPayloadByte == -1) {
            throw EOFException("truncated length-prefixed frame")
        }
        if (firstPayloadByte != '{'.code && firstPayloadByte != ' '.code &&
            firstPayloadByte != '\t'.code && firstPayloadByte != '\r'.code &&
            firstPayloadByte != '\n'.code
        ) {
            throw IOException("unsupported daemon framing (expected JSON)")
        }

        buffered.reset()
        return finishDetection(Framing.LENGTH_PREFIXED)
    }

    private fun finishDetection(selected: Framing): Framing {
        framing = selected
        if (selected == Framing.LINE) {
            lineReader = BufferedReader(InputStreamReader(buffered, Charsets.UTF_8))
        } else {
            inputStream = buffered
        }
        return selected
    }

    private fun readLine(): String? {
        val reader = lineReader ?: error("line reader is not initialized")
        while (true) {
            val line = reader.readLine() ?: return null
            if (line.isBlank()) {
                continue
            }
            if (line.length > MAX_MESSAGE_BYTES) {
                throw IOException("newline-delimited JSON message is too large")
            }
            return line
        }
    }

    private fun readFrame(): String? {
        val stream = inputStream ?: error("frame input is not initialized")
        consumeOptionalSeparators(stream)
        val header = ByteArray(4)
        if (!readFully(stream, header, allowCleanEof = true)) {
            return null
        }
        val length = ((header[0].toInt() and 0xff) shl 24) or
            ((header[1].toInt() and 0xff) shl 16) or
            ((header[2].toInt() and 0xff) shl 8) or
            (header[3].toInt() and 0xff)
        if (length !in 1..MAX_MESSAGE_BYTES) {
            throw IOException("invalid length-prefixed frame length: $length")
        }
        val payload = ByteArray(length)
        if (!readFully(stream, payload, allowCleanEof = false)) {
            throw EOFException("truncated length-prefixed frame")
        }
        return String(payload, Charsets.UTF_8)
    }

    private fun consumeOptionalSeparators(stream: InputStream) {
        while (true) {
            stream.mark(1)
            val value = stream.read()
            if (value == -1) {
                return
            }
            if (value == '\r'.code || value == '\n'.code || value == ' '.code || value == '\t'.code) {
                continue
            }
            stream.reset()
            return
        }
    }

    private fun readFully(
        stream: InputStream,
        target: ByteArray,
        allowCleanEof: Boolean,
    ): Boolean {
        var offset = 0
        while (offset < target.size) {
            val read = stream.read(target, offset, target.size - offset)
            if (read == -1) {
                if (offset == 0 && allowCleanEof) {
                    return false
                }
                throw EOFException("unexpected end of stream")
            }
            offset += read
        }
        return true
    }

    companion object {
        private const val BUFFER_SIZE = 16 * 1024
        private const val MAX_MESSAGE_BYTES = 1024 * 1024
    }
}
