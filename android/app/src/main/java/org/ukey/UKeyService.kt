package org.ukey

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.IBinder
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import org.ukey.crypto.CredentialException
import org.ukey.crypto.Hex
import org.ukey.crypto.KeystoreManager
import org.ukey.net.DaemonClient
import org.ukey.net.JsonWire

/**
 * Foreground service that owns the reverse-tunneled TCP connection.
 *
 * It handles MakeCredential without user interaction, and routes assertion and
 * attestation requests through BridgeState to MainActivity for BiometricPrompt.
 * If the activity is not resumed, a high-priority notification asks the user to
 * open the app; background activity starts are deliberately not attempted.
 */
class UKeyService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private lateinit var keystore: KeystoreManager

    @Volatile
    private var connectionJob: Job? = null

    @Volatile
    private var client: DaemonClient? = null

    private var currentHost = DEFAULT_HOST
    private var currentPort = DEFAULT_PORT

    override fun onCreate() {
        super.onCreate()
        keystore = KeystoreManager(applicationContext)
        createNotificationChannels()
        startForegroundInternal(
            ConnectionSnapshot(
                phase = ConnectionPhase.DISCONNECTED,
                host = currentHost,
                port = currentPort,
                detail = "Starting bridge",
            ),
        )

        serviceScope.launch {
            BridgeState.connection.collect { snapshot ->
                updateStatusNotification(snapshot)
            }
        }
        serviceScope.launch {
            BridgeState.pending.collect { challenge ->
                if (challenge == null) {
                    cancelAuthNotification()
                } else if (!BridgeState.isUiResumed) {
                    showAuthNotification(challenge)
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                prefs().edit().putBoolean(KEY_ENABLED, false).apply()
                shutDown()
                return START_NOT_STICKY
            }

            ACTION_CONNECT -> {
                val host = intent.getStringExtra(EXTRA_HOST)
                    ?: prefs().getString(KEY_HOST, DEFAULT_HOST)
                    ?: DEFAULT_HOST
                val port = intent.getIntExtra(
                    EXTRA_PORT,
                    prefs().getInt(KEY_PORT, DEFAULT_PORT),
                )
                val pin = intent.getStringExtra(EXTRA_PAIRING_PIN)
                if (!isValidEndpoint(host, port)) {
                    BridgeState.setConnection(
                        ConnectionSnapshot(
                            phase = ConnectionPhase.DISCONNECTED,
                            host = host,
                            port = port,
                            detail = "Invalid host or port",
                        ),
                    )
                    return START_STICKY
                }
                val editor = prefs().edit()
                    .putString(KEY_HOST, host)
                    .putInt(KEY_PORT, port)
                    .putBoolean(KEY_ENABLED, true)
                if (!pin.isNullOrBlank()) {
                    editor.putString(KEY_PAIRING_PIN, pin.trim())
                }
                editor.apply()
                connect(host, port)
            }

            else -> {
                if (!prefs().getBoolean(KEY_ENABLED, true)) {
                    shutDown()
                    return START_NOT_STICKY
                }
                val host = prefs().getString(KEY_HOST, DEFAULT_HOST) ?: DEFAULT_HOST
                val port = prefs().getInt(KEY_PORT, DEFAULT_PORT)
                if (isValidEndpoint(host, port)) {
                    connect(host, port)
                } else {
                    shutDown()
                    return START_NOT_STICKY
                }
            }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        connectionJob?.cancel()
        client?.close()
        client = null
        BridgeState.cancelPending("service_destroyed")
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun connect(host: String, port: Int) {
        if (currentHost == host && currentPort == port && connectionJob?.isActive == true) {
            return
        }

        connectionJob?.cancel()
        connectionJob = null
        client?.close()
        client = null
        BridgeState.cancelPending("connection_restarted")

        currentHost = host
        currentPort = port
        val newClient = DaemonClient(
            host = host,
            port = port,
            deviceTokenProvider = { prefs().getString(KEY_DEVICE_TOKEN, null) },
            pairingPinProvider = { prefs().getString(KEY_PAIRING_PIN, null) },
            onTokenReceived = { token ->
                prefs().edit()
                    .putString(KEY_DEVICE_TOKEN, token)
                    .remove(KEY_PAIRING_PIN)
                    .apply()
                Log.i(TAG, "Device paired successfully with daemon; permanent token stored")
            },
            onAuthFailed = { error ->
                Log.w(TAG, "Daemon authentication failed: $error")
                if (error == "unauthorized" || error == "invalid_pin") {
                    prefs().edit()
                        .remove(KEY_DEVICE_TOKEN)
                        .remove(KEY_PAIRING_PIN)
                        .apply()
                }
            },
            onMessage = { message, wire ->
                handleMessage(message, wire)
            },
        )
        client = newClient
        connectionJob = serviceScope.launch {
            try {
                newClient.run()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (exc: Exception) {
                Log.w(TAG, "bridge loop stopped", exc)
                BridgeState.setConnection(
                    ConnectionSnapshot(
                        phase = ConnectionPhase.DISCONNECTED,
                        host = host,
                        port = port,
                        detail = exc.message ?: exc.javaClass.simpleName,
                    ),
                )
            }
        }
    }

    private suspend fun handleMessage(raw: String, wire: JsonWire) {
        val parsedId = Protocol.extractId(raw)
        val request = try {
            Protocol.parse(raw)
        } catch (exc: Exception) {
            Log.w(TAG, "rejected request: ${exc.message}")
            sendSafely(wire, Protocol.errorResponse(parsedId, Protocol.describeError(exc)))
            return
        }

        try {
            when (request.action) {
                "make_credential" -> handleMakeCredential(request, wire)
                "get_assertion" -> handleAuthorization(request, AuthKind.ASSERTION, wire)
                "attest" -> handleAuthorization(request, AuthKind.ATTESTATION, wire)
                else -> throw ProtocolException("unsupported_action: ${request.action}")
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (exc: Exception) {
            val message = Protocol.describeError(exc)
            Log.w(TAG, "${request.action} failed: $message")
            BridgeState.record(
                rpId = request.rpId,
                action = request.actionLabel,
                outcome = LogOutcome.ERROR,
                detail = message,
            )
            sendSafely(wire, Protocol.errorResponse(request.id, message))
        }
    }

    private fun handleMakeCredential(request: SignerRequest, wire: JsonWire) {
        requireStrongBiometric()
        val info = keystore.createCredential(request.rpId)
        Log.i(TAG, "created ${info.securityLevel} credential for ${request.rpId}")
        BridgeState.record(
            rpId = request.rpId,
            action = request.actionLabel,
            outcome = LogOutcome.SUCCESS,
            detail = "Credential created (${info.securityLevel})",
        )
        wire.writeMessage(Protocol.credentialResponse(request.id, info))
    }

    private suspend fun handleAuthorization(
        request: SignerRequest,
        kind: AuthKind,
        wire: JsonWire,
    ) {
        requireStrongBiometric()
        val credId = request.credId
            ?: throw ProtocolException("invalid_request: cred_id is required")
        val digest = request.digest
            ?: throw ProtocolException("invalid_request: digest is required")

        val prepared = keystore.prepareSignature(request.rpId, credId, digest)
        val challenge = AuthChallenge(
            taskId = request.taskId,
            kind = kind,
            rpId = request.rpId,
            credentialIdHex = Hex.encode(credId),
            signature = prepared.signature,
        )
        val outcome = BridgeState.awaitAuthorization(challenge)

        when (outcome) {
            is AuthOutcome.Signed -> {
                if (outcome.rawSignature.size != 64) {
                    throw CredentialException("signature_error: expected 64 raw bytes")
                }
                BridgeState.record(
                    rpId = request.rpId,
                    action = request.actionLabel,
                    outcome = LogOutcome.SUCCESS,
                    detail = "Authorized",
                )
                wire.writeMessage(Protocol.signatureResponse(request.id, outcome.rawSignature))
            }

            AuthOutcome.Cancelled -> {
                BridgeState.record(
                    rpId = request.rpId,
                    action = request.actionLabel,
                    outcome = LogOutcome.CANCELLED,
                    detail = "User cancelled",
                )
                wire.writeMessage(Protocol.errorResponse(request.id, "user_cancelled"))
            }

            is AuthOutcome.Failure -> {
                // These are connection-lifecycle races, not user-visible
                // failures. The daemon has already gone away.
                if (outcome.message in INTERNAL_CANCEL_REASONS) {
                    return
                }
                BridgeState.record(
                    rpId = request.rpId,
                    action = request.actionLabel,
                    outcome = LogOutcome.ERROR,
                    detail = outcome.message,
                )
                wire.writeMessage(Protocol.errorResponse(request.id, outcome.message))
            }
        }
    }

    private fun requireStrongBiometric() {
        if (!keystore.isDeviceSecure()) {
            throw CredentialException("device_not_secure: set a PIN, pattern or password")
        }
        val result = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (result != BiometricManager.BIOMETRIC_SUCCESS) {
            throw CredentialException("biometric_unavailable: no strong biometric is enrolled")
        }
    }

    private fun sendSafely(wire: JsonWire, payload: String) {
        try {
            wire.writeMessage(payload)
        } catch (exc: Exception) {
            Log.w(TAG, "could not send response: ${exc.message}")
        }
    }

    private fun isValidEndpoint(host: String, port: Int): Boolean =
        host.isNotBlank() && host.length <= 253 && port in 1..65535

    private fun prefs() = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)

    private fun createNotificationChannels() {
        val manager = getSystemService(NotificationManager::class.java) ?: return

        val status = NotificationChannel(
            CHANNEL_STATUS,
            getString(R.string.notification_channel_status),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = getString(R.string.notification_channel_status_description)
            setShowBadge(false)
        }

        val auth = NotificationChannel(
            CHANNEL_AUTH,
            getString(R.string.notification_channel_auth),
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = getString(R.string.notification_channel_auth_description)
            setShowBadge(true)
        }

        manager.createNotificationChannels(listOf(status, auth))
    }

    private fun startForegroundInternal(snapshot: ConnectionSnapshot) {
        val notification = buildStatusNotification(snapshot)
        ServiceCompat.startForeground(
            this,
            STATUS_NOTIFICATION_ID,
            notification,
            ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
        )
    }

    private fun updateStatusNotification(snapshot: ConnectionSnapshot) {
        try {
            NotificationManagerCompat.from(this)
                .notify(STATUS_NOTIFICATION_ID, buildStatusNotification(snapshot))
        } catch (exc: SecurityException) {
            Log.w(TAG, "status notification not permitted", exc)
        }
    }

    private fun buildStatusNotification(snapshot: ConnectionSnapshot): Notification {
        val title = when (snapshot.phase) {
            ConnectionPhase.CONNECTED -> "uKey Bridge: Connected to Linux"
            ConnectionPhase.CONNECTING -> "uKey Bridge: Connecting…"
            ConnectionPhase.DISCONNECTED -> "uKey Bridge: Disconnected"
        }
        val detail = snapshot.detail?.takeIf { it.isNotBlank() }
        val text = buildString {
            append(snapshot.host)
            append(':')
            append(snapshot.port)
            if (detail != null) {
                append(" · ")
                append(detail)
            }
        }

        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = Intent(this, UKeyService::class.java).setAction(ACTION_STOP)
        val stopPendingIntent = PendingIntent.getService(
            this,
            1,
            stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_STATUS)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(openPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .addAction(0, getString(R.string.notification_stop), stopPendingIntent)
            .build()
    }

    private fun showAuthNotification(challenge: AuthChallenge) {
        val manager = NotificationManagerCompat.from(this)
        if (!manager.areNotificationsEnabled()) {
            return
        }

        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val openPendingIntent = PendingIntent.getActivity(
            this,
            AUTH_NOTIFICATION_ID,
            openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_AUTH)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(getString(R.string.notification_auth_title))
            .setContentText(getString(R.string.notification_auth_text, challenge.rpId))
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText(getString(R.string.notification_auth_text, challenge.rpId)),
            )
            .setContentIntent(openPendingIntent)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_RECOMMENDATION)
            .setAutoCancel(true)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .build()

        try {
            manager.notify(AUTH_NOTIFICATION_ID, notification)
        } catch (exc: SecurityException) {
            Log.w(TAG, "authorization notification not permitted", exc)
        }
    }

    private fun cancelAuthNotification() {
        try {
            NotificationManagerCompat.from(this).cancel(AUTH_NOTIFICATION_ID)
        } catch (_: SecurityException) {
            // Permission may have been revoked while the service was running.
        }
    }

    private fun shutDown() {
        connectionJob?.cancel()
        connectionJob = null
        client?.close()
        client = null
        BridgeState.resetForServiceStop(currentHost, currentPort)
        cancelAuthNotification()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        private const val TAG = "UKeyService"

        const val PREFS_NAME = "ukey_bridge"
        const val KEY_HOST = "host"
        const val KEY_PORT = "port"
        const val KEY_ENABLED = "enabled"
        const val KEY_DEVICE_TOKEN = "device_token"
        const val KEY_PAIRING_PIN = "pairing_pin"
        const val DEFAULT_HOST = "127.0.0.1"
        const val DEFAULT_PORT = 8443

        const val ACTION_CONNECT = "org.ukey.action.CONNECT"
        const val ACTION_STOP = "org.ukey.action.STOP"
        const val EXTRA_HOST = "org.ukey.extra.HOST"
        const val EXTRA_PORT = "org.ukey.extra.PORT"
        const val EXTRA_PAIRING_PIN = "org.ukey.extra.PAIRING_PIN"

        private const val CHANNEL_STATUS = "ukey_bridge_status"
        private const val CHANNEL_AUTH = "ukey_auth_requests"
        private const val STATUS_NOTIFICATION_ID = 1
        const val AUTH_NOTIFICATION_ID = 2

        private val INTERNAL_CANCEL_REASONS = setOf(
            "connection_closed",
            "connection_restarted",
            "bridge_stopped",
            "service_destroyed",
        )
    }
}
