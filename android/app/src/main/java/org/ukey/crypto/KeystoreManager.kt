package org.ukey.crypto

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

class CredentialException(message: String, cause: Throwable? = null) : Exception(message, cause)

data class CredentialInfo(
    val credId: ByteArray,
    val x: ByteArray,
    val y: ByteArray,
    val alias: String,
    val securityLevel: String,
)

data class PreparedSignature(
    val signature: Signature,
    val alias: String,
)

/**
 * Hardware-backed P-256 credential management.
 *
 * Keys are created in AndroidKeyStore with per-use strong biometric
 * authentication. StrongBox is attempted first and TEE is used only when the
 * device reports that StrongBox is unavailable. Keys are rejected if the
 * provider does not confirm hardware isolation.
 */
class KeystoreManager(context: Context) {
    private val appContext = context.applicationContext
    private val keyStore: KeyStore

    init {
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
    }

    fun isDeviceSecure(): Boolean {
        val keyguard = appContext.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
        return keyguard?.isDeviceSecure == true
    }

    fun createCredential(rpId: String): CredentialInfo {
        if (!isDeviceSecure()) {
            throw CredentialException("device_not_secure: set a PIN, pattern or password")
        }

        val uuid = UUID.randomUUID()
        val alias = EcUtil.alias(uuid)
        if (keyStore.containsAlias(alias)) {
            throw CredentialException("credential_alias_collision: retry registration")
        }

        val securityLevel = try {
            generateWithStrongBoxFallback(alias)
        } catch (exc: CredentialException) {
            deleteAlias(alias)
            throw exc
        } catch (exc: Exception) {
            deleteAlias(alias)
            throw CredentialException("key_generation_failed: ${exc.message}", exc)
        }

        val publicKey = try {
            val certificate = keyStore.getCertificate(alias)
                ?: throw CredentialException("key_generation_failed: certificate is missing")
            certificate.publicKey as? java.security.interfaces.ECPublicKey
                ?: throw CredentialException("key_generation_failed: key is not an EC public key")
        } catch (exc: CredentialException) {
            deleteAlias(alias)
            throw exc
        } catch (exc: Exception) {
            deleteAlias(alias)
            throw CredentialException("key_generation_failed: ${exc.message}", exc)
        }

        return CredentialInfo(
            credId = EcUtil.credentialId(rpId, uuid),
            x = EcUtil.coordinate32(publicKey.w.affineX),
            y = EcUtil.coordinate32(publicKey.w.affineY),
            alias = alias,
            securityLevel = securityLevel,
        )
    }

    /**
     * Resolves the stateless credential ID, verifies its RP binding, and
     * returns a Signature initialized with the 32-byte digest.
     */
    fun prepareSignature(rpId: String, credId: ByteArray, digest: ByteArray): PreparedSignature {
        if (!isDeviceSecure()) {
            throw CredentialException("device_not_secure: set a PIN, pattern or password")
        }
        if (credId.size != EcUtil.CREDENTIAL_ID_BYTES) {
            throw CredentialException("unknown_credential: invalid credential id length")
        }
        if (digest.size != 32) {
            throw CredentialException("invalid_digest: digest must be 32 bytes")
        }

        val rpHash = credId.copyOfRange(0, EcUtil.RP_HASH_BYTES)
        if (!MessageDigest.isEqual(rpHash, EcUtil.rpHashPrefix(rpId))) {
            throw CredentialException("credential_rp_mismatch: credential is bound to a different RP")
        }

        val uuid = EcUtil.uuidFromBytes(
            credId.copyOfRange(EcUtil.RP_HASH_BYTES, EcUtil.CREDENTIAL_ID_BYTES),
        )
        val alias = EcUtil.alias(uuid)
        if (!keyStore.containsAlias(alias)) {
            throw CredentialException("unknown_credential: no hardware key for credential")
        }

        val privateKey = try {
            keyStore.getKey(alias, null) as? PrivateKey
                ?: throw CredentialException("unknown_credential: key is not a private key")
        } catch (exc: CredentialException) {
            throw exc
        } catch (exc: Exception) {
            throw CredentialException("keystore_error: ${exc.message}", exc)
        }

        val signature = try {
            Signature.getInstance("NONEwithECDSA").apply {
                initSign(privateKey)
                update(digest)
            }
        } catch (exc: KeyPermanentlyInvalidatedException) {
            deleteAlias(alias)
            throw CredentialException(
                "credential_invalidated: biometric enrollment or lock screen change invalidated the key",
                exc,
            )
        } catch (exc: UserNotAuthenticatedException) {
            throw CredentialException("user_not_authenticated: biometric authentication is required", exc)
        } catch (exc: Exception) {
            throw CredentialException("keystore_sign_init_failed: ${exc.message}", exc)
        }

        return PreparedSignature(signature = signature, alias = alias)
    }

    private fun generateWithStrongBoxFallback(alias: String): String {
        return try {
            generateKey(alias)
        } catch (exc: Exception) {
            if (!isStrongBoxFailure(exc)) {
                throw exc
            }
            Log.w(TAG, "StrongBox unavailable for $alias; retrying in TEE", exc)
            deleteAlias(alias)
            try {
                generateKeyInTee(alias)
                "TEE (StrongBox unavailable)"
            } catch (tee: Exception) {
                deleteAlias(alias)
                throw tee
            }
        }
    }

    private fun generateKey(alias: String): String {
        generateKeyInternal(alias, strongBox = true)
        return "StrongBox"
    }

    private fun generateKeyInTee(alias: String): String {
        generateKeyInternal(alias, strongBox = false)
        return "TEE"
    }

    private fun generateKeyInternal(alias: String, strongBox: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(false)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(
                0,
                KeyProperties.AUTH_BIOMETRIC_STRONG,
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (strongBox) {
            builder.setIsStrongBoxBacked(true)
        }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE,
        )
        generator.initialize(builder.build())
        generator.generateKeyPair()

        verifyHardwareBacked(alias)
    }

    private fun verifyHardwareBacked(alias: String) {
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: throw CredentialException("key_generation_failed: private key is missing")
        val keyInfo = try {
            KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
                .getKeySpec(privateKey, KeyInfo::class.java) as KeyInfo
        } catch (exc: Exception) {
            throw CredentialException("hardware_check_failed: ${exc.message}", exc)
        }
        if (!keyInfo.isInsideSecureHardware) {
            throw CredentialException("credential_not_hardware_backed: provider returned a software key")
        }
    }

    private fun isStrongBoxFailure(exc: Throwable): Boolean {
        var current: Throwable? = exc
        while (current != null) {
            if (current is StrongBoxUnavailableException) {
                return true
            }
            val message = current.message?.lowercase()
            if (message != null && "strongbox" in message) {
                return true
            }
            current = current.cause
        }
        return false
    }

    private fun deleteAlias(alias: String) {
        try {
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias)
            }
        } catch (exc: Exception) {
            Log.w(TAG, "failed to delete key $alias", exc)
        }
    }

    companion object {
        private const val TAG = "UKeyKeystore"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
