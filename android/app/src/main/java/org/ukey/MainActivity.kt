package org.ukey

import android.Manifest
import android.app.KeyguardManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowManager
import android.view.inputmethod.InputMethodManager
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import org.ukey.crypto.DerUtils
import org.ukey.crypto.KeystoreManager

class MainActivity : AppCompatActivity() {

    private lateinit var hostInput: EditText
    private lateinit var portInput: EditText
    private lateinit var statusPill: TextView
    private lateinit var statusDetail: TextView
    private lateinit var securityWarning: LinearLayout
    private lateinit var securityWarningBody: TextView
    private lateinit var logText: TextView
    private lateinit var logScroll: ScrollView

    private lateinit var keystore: KeystoreManager

    private var activePromptTaskId: Long? = null
    private var biometricPrompt: BiometricPrompt? = null

    private val prefs by lazy {
        getSharedPreferences(UKeyService.PREFS_NAME, MODE_PRIVATE)
    }

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted) {
            Toast.makeText(
                this,
                R.string.notification_permission_denied,
                Toast.LENGTH_LONG,
            ).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        setShowWhenLocked(true)
        setTurnScreenOn(true)

        setContentView(R.layout.activity_main)
        bindViews()
        keystore = KeystoreManager(applicationContext)

        hostInput.setText(prefs.getString(UKeyService.KEY_HOST, UKeyService.DEFAULT_HOST))
        portInput.setText(prefs.getInt(UKeyService.KEY_PORT, UKeyService.DEFAULT_PORT).toString())

        findViewById<Button>(R.id.connectButton).setOnClickListener {
            startBridge()
        }
        findViewById<Button>(R.id.stopButton).setOnClickListener {
            stopBridge()
        }
        findViewById<Button>(R.id.clearLogButton).setOnClickListener {
            BridgeState.clearLog()
            Toast.makeText(this, R.string.logs_cleared, Toast.LENGTH_SHORT).show()
        }

        observeBridgeState()
        checkDeviceSecurity()
        requestNotificationPermissionIfNeeded()

        if (prefs.getBoolean(UKeyService.KEY_ENABLED, true)) {
            startBridge(autoStart = true)
        } else {
            renderConnection(
                ConnectionSnapshot(
                    phase = ConnectionPhase.DISCONNECTED,
                    host = hostInput.text.toString(),
                    port = portInput.text.toString().toIntOrNull() ?: UKeyService.DEFAULT_PORT,
                    detail = getString(R.string.error_bridge_not_running),
                ),
            )
        }
    }

    override fun onResume() {
        super.onResume()
        BridgeState.isUiResumed = true
        NotificationManagerCompat.from(this).cancel(UKeyService.AUTH_NOTIFICATION_ID)
        checkDeviceSecurity()
        BridgeState.pending.value?.let { maybeShowPrompt(it) }
    }

    override fun onPause() {
        BridgeState.isUiResumed = false
        super.onPause()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        NotificationManagerCompat.from(this).cancel(UKeyService.AUTH_NOTIFICATION_ID)
        BridgeState.pending.value?.let { maybeShowPrompt(it) }
    }

    private fun bindViews() {
        hostInput = findViewById(R.id.hostInput)
        portInput = findViewById(R.id.portInput)
        statusPill = findViewById(R.id.statusPill)
        statusDetail = findViewById(R.id.statusDetail)
        securityWarning = findViewById(R.id.securityWarning)
        securityWarningBody = findViewById(R.id.securityWarningBody)
        logText = findViewById(R.id.logText)
        logScroll = findViewById(R.id.logScroll)
    }

    private fun observeBridgeState() {
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch {
                    BridgeState.connection.collect { snapshot ->
                        renderConnection(snapshot)
                    }
                }
                launch {
                    BridgeState.log.collect { entries ->
                        renderLog(entries)
                    }
                }
                launch {
                    BridgeState.pending.collect { challenge ->
                        if (challenge == null) {
                            cancelPromptIfActive()
                        } else {
                            maybeShowPrompt(challenge)
                        }
                    }
                }
            }
        }
    }

    private fun renderConnection(snapshot: ConnectionSnapshot) {
        val (label, background) = when (snapshot.phase) {
            ConnectionPhase.CONNECTED ->
                "🟢 Connected" to R.drawable.bg_status_connected
            ConnectionPhase.CONNECTING ->
                "🟡 Connecting" to R.drawable.bg_status_connecting
            ConnectionPhase.DISCONNECTED ->
                "🔴 Disconnected" to R.drawable.bg_status_disconnected
        }
        statusPill.setText(label)
        statusPill.setBackgroundResource(background)

        val endpoint = "${snapshot.host}:${snapshot.port}"
        statusDetail.text = snapshot.detail
            ?.takeIf { it.isNotBlank() }
            ?.let { "$endpoint · $it" }
            ?: endpoint
    }

    private fun renderLog(entries: List<TransactionEntry>) {
        if (entries.isEmpty()) {
            logText.setText(R.string.log_empty)
        } else {
            logText.text = buildString {
                entries.forEach { entry ->
                    val mark = when (entry.outcome) {
                        LogOutcome.SUCCESS -> "✓"
                        LogOutcome.CANCELLED -> "–"
                        LogOutcome.ERROR -> "✕"
                    }
                    append(entry.time)
                    append("  ")
                    append(entry.rpId)
                    append('\n')
                    append("          ")
                    append(entry.action)
                    append("  ")
                    append(mark)
                    entry.detail?.takeIf { it.isNotBlank() }?.let {
                        append(' ')
                        append(it)
                    }
                    append("\n\n")
                }
            }
        }
        logScroll.post {
            logScroll.fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun startBridge(autoStart: Boolean = false) {
        val host = hostInput.text.toString().trim()
        val port = portInput.text.toString().trim().toIntOrNull()

        if (host.isBlank() || host.length > 253 || host.any { it.isWhitespace() || it.code < 0x20 }) {
            toast("Enter a valid host")
            return
        }
        if (port == null || port !in 1..65535) {
            toast("Enter a port between 1 and 65535")
            return
        }

        prefs.edit()
            .putString(UKeyService.KEY_HOST, host)
            .putInt(UKeyService.KEY_PORT, port)
            .putBoolean(UKeyService.KEY_ENABLED, true)
            .apply()

        val intent = Intent(this, UKeyService::class.java)
            .setAction(UKeyService.ACTION_CONNECT)
            .putExtra(UKeyService.EXTRA_HOST, host)
            .putExtra(UKeyService.EXTRA_PORT, port)
        ContextCompat.startForegroundService(this, intent)

        if (!autoStart) {
            hideKeyboard()
        }
    }

    private fun stopBridge() {
        prefs.edit().putBoolean(UKeyService.KEY_ENABLED, false).apply()
        startService(
            Intent(this, UKeyService::class.java).setAction(UKeyService.ACTION_STOP),
        )
        BridgeState.cancelPending("bridge_stopped")
        renderConnection(
            ConnectionSnapshot(
                phase = ConnectionPhase.DISCONNECTED,
                host = hostInput.text.toString(),
                port = portInput.text.toString().toIntOrNull() ?: UKeyService.DEFAULT_PORT,
                detail = "Bridge stopped",
            ),
        )
    }

    private fun checkDeviceSecurity() {
        val keyguard = getSystemService(KEYGUARD_SERVICE) as? KeyguardManager
        val deviceSecure = keyguard?.isDeviceSecure == true
        val strongBiometric = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS

        when {
            !deviceSecure -> {
                securityWarning.visibility = View.VISIBLE
                securityWarningBody.setText(R.string.security_warning_no_lock)
            }
            !strongBiometric -> {
                securityWarning.visibility = View.VISIBLE
                securityWarningBody.setText(R.string.security_warning_no_biometric)
            }
            else -> {
                securityWarning.visibility = View.GONE
            }
        }
    }

    private fun maybeShowPrompt(challenge: AuthChallenge) {
        if (!BridgeState.isUiResumed ||
            !lifecycle.currentState.isAtLeast(Lifecycle.State.RESUMED)
        ) {
            return
        }
        if (activePromptTaskId == challenge.taskId) {
            return
        }
        if (activePromptTaskId != null) {
            // The daemon serializes requests, so this should not normally
            // happen. Fail closed rather than stacking biometric prompts.
            BridgeState.submit(
                challenge.taskId,
                AuthOutcome.Failure("authorization_busy: another prompt is active"),
            )
            return
        }

        if (!keystore.isDeviceSecure()) {
            BridgeState.submit(
                challenge.taskId,
                AuthOutcome.Failure(getString(R.string.error_device_not_secure)),
            )
            return
        }
        val biometricResult = BiometricManager.from(this)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)
        if (biometricResult != BiometricManager.BIOMETRIC_SUCCESS) {
            BridgeState.submit(
                challenge.taskId,
                AuthOutcome.Failure(getString(R.string.error_no_biometric)),
            )
            return
        }

        val prompt = BiometricPrompt(
            this,
            ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(
                    result: BiometricPrompt.AuthenticationResult,
                ) {
                    val outcome = try {
                        val signature = result.cryptoObject?.signature
                            ?: throw IllegalStateException("biometric result has no signature")
                        AuthOutcome.Signed(DerUtils.derToRaw(signature.sign()))
                    } catch (exc: Exception) {
                        AuthOutcome.Failure(
                            "signature_error: ${exc.message ?: exc.javaClass.simpleName}",
                        )
                    }
                    finishPrompt(challenge, outcome)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val outcome = when (errorCode) {
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_CANCELED,
                        -> AuthOutcome.Cancelled

                        else -> AuthOutcome.Failure("biometric_error_$errorCode: $errString")
                    }
                    finishPrompt(challenge, outcome)
                }

                override fun onAuthenticationFailed() {
                    // Keep the prompt open so the user can retry.
                }
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(getString(R.string.biometric_title))
            .setSubtitle(getString(R.string.biometric_subtitle, challenge.rpId))
            .setDescription(getString(R.string.biometric_description))
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText(getString(R.string.biometric_cancel))
            .build()

        activePromptTaskId = challenge.taskId
        biometricPrompt = prompt
        NotificationManagerCompat.from(this).cancel(UKeyService.AUTH_NOTIFICATION_ID)
        try {
            prompt.authenticate(info, BiometricPrompt.CryptoObject(challenge.signature))
        } catch (exc: Exception) {
            finishPrompt(
                challenge,
                AuthOutcome.Failure(
                    "biometric_prompt_failed: ${exc.message ?: exc.javaClass.simpleName}",
                ),
            )
        }
    }

    private fun finishPrompt(challenge: AuthChallenge, outcome: AuthOutcome) {
        if (activePromptTaskId != challenge.taskId) {
            return
        }
        activePromptTaskId = null
        biometricPrompt = null
        BridgeState.submit(challenge.taskId, outcome)
    }

    private fun cancelPromptIfActive() {
        val prompt = biometricPrompt ?: run {
            activePromptTaskId = null
            return
        }
        activePromptTaskId = null
        biometricPrompt = null
        prompt.cancelAuthentication()
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
            return
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun hideKeyboard() {
        val input = getSystemService(INPUT_METHOD_SERVICE) as? InputMethodManager
        input?.hideSoftInputFromWindow(currentFocus?.windowToken, 0)
        currentFocus?.clearFocus()
    }

    private fun toast(message: String) {
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
    }
}
