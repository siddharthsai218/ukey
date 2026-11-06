package org.ukey

import org.json.JSONException
import org.json.JSONObject
import org.ukey.crypto.CredentialException
import org.ukey.crypto.CredentialInfo
import org.ukey.crypto.Hex

class ProtocolException(message: String) : Exception(message)

data class SignerRequest(
    val id: Number,
    val action: String,
    val rpId: String,
    val clientHash: ByteArray?,
    val credId: ByteArray?,
    val digest: ByteArray?,
) {
    val taskId: Long
        get() = id.toLong()

    val actionLabel: String
        get() = when (action) {
            "make_credential" -> "Register"
            "get_assertion" -> "Assertion"
            "attest" -> "Attestation"
            else -> action
        }
}

object Protocol {
    private const val MAX_RP_ID_BYTES = 255
    private const val MAX_ERROR_LENGTH = 500

    fun parse(raw: String): SignerRequest {
        val json = try {
            JSONObject(raw)
        } catch (exc: JSONException) {
            throw ProtocolException("invalid_json: ${exc.message ?: "malformed JSON"}")
        }

        val id = json.opt("id")
        if (id !is Number || id is Double || id is Float) {
            throw ProtocolException("invalid_request: id must be an integer")
        }

        val action = json.opt("action")
        if (action !is String || action.isBlank()) {
            throw ProtocolException("invalid_request: action must be a non-empty string")
        }

        val rpId = parseRpId(json)
        val clientHash = json.opt("client_hash")?.let { parseHex(it, "client_hash", 32) }

        val credId = when (action) {
            "make_credential" -> json.opt("cred_id")?.let { parseHex(it, "cred_id", 32) }
            "get_assertion", "attest" ->
                parseHex(requireField(json, "cred_id"), "cred_id", 32)
            else -> null
        }
        val digest = when (action) {
            "get_assertion", "attest" ->
                parseHex(requireField(json, "digest"), "digest", 32)
            else -> json.opt("digest")?.let { parseHex(it, "digest", 32) }
        }

        if (action == "make_credential" && clientHash == null) {
            throw ProtocolException("invalid_request: client_hash is required")
        }

        return SignerRequest(
            id = id,
            action = action,
            rpId = rpId,
            clientHash = clientHash,
            credId = credId,
            digest = digest,
        )
    }

    fun credentialResponse(id: Number, info: CredentialInfo): String =
        JSONObject()
            .put("id", id)
            .put("pub_key_x", Hex.encode(info.x))
            .put("pub_key_y", Hex.encode(info.y))
            .put("cred_id", Hex.encode(info.credId))
            .toString()

    fun signatureResponse(id: Number, rawSignature: ByteArray): String {
        require(rawSignature.size == 64) { "raw signature must be 64 bytes" }
        return JSONObject()
            .put("id", id)
            .put("raw_sig", Hex.encode(rawSignature))
            .toString()
    }

    fun errorResponse(id: Any?, message: String): String {
        val clean = message
            .replace('\n', ' ')
            .replace('\r', ' ')
            .replace('\t', ' ')
            .take(MAX_ERROR_LENGTH)
            .ifBlank { "operation_failed" }
        return JSONObject()
            .put("id", id ?: JSONObject.NULL)
            .put("error", clean)
            .toString()
    }

    fun pairRequest(pin: String, deviceName: String): String =
        JSONObject()
            .put("action", "pair")
            .put("pin", pin.trim())
            .put("device_name", deviceName)
            .toString()

    fun authRequest(token: String, deviceName: String): String =
        JSONObject()
            .put("action", "auth")
            .put("token", token.trim())
            .put("device_name", deviceName)
            .toString()

    data class HandshakeResult(
        val success: Boolean,
        val token: String? = null,
        val error: String? = null,
    )

    fun parseHandshakeResponse(raw: String): HandshakeResult {
        val json = try {
            JSONObject(raw)
        } catch (_: JSONException) {
            return HandshakeResult(success = false, error = "Malformed response")
        }
        val status = json.optString("status")
        return if (status == "ok") {
            HandshakeResult(
                success = true,
                token = json.optString("token").takeIf { it.isNotBlank() },
            )
        } else {
            HandshakeResult(
                success = false,
                error = json.optString("error", "unauthorized"),
            )
        }
    }

    fun describeError(error: Throwable): String = when (error) {
        is ProtocolException -> error.message ?: "invalid_request"
        is CredentialException -> error.message ?: "credential_error"
        else -> {
            val message = error.message ?: "operation failed"
            "${error.javaClass.simpleName}: $message"
        }
    }

    fun extractId(raw: String): Number? {
        return try {
            val value = JSONObject(raw).opt("id")
            if (value is Number && value !is Double && value !is Float) value else null
        } catch (_: JSONException) {
            null
        }
    }

    private fun parseRpId(json: JSONObject): String {
        val value = json.opt("rp_id")
        if (value !is String || value.isBlank()) {
            throw ProtocolException("invalid_request: rp_id must be a non-empty string")
        }
        if (value.toByteArray(Charsets.UTF_8).size > MAX_RP_ID_BYTES) {
            throw ProtocolException("invalid_request: rp_id is longer than 255 bytes")
        }
        if (value.any { it.code < 0x20 || it.code == 0x7f }) {
            throw ProtocolException("invalid_request: rp_id contains control characters")
        }
        return value
    }

    private fun parseHex(value: Any?, field: String, expectedBytes: Int): ByteArray {
        if (value !is String) {
            throw ProtocolException("invalid_request: $field must be a hex string")
        }
        if (value.length != expectedBytes * 2) {
            throw ProtocolException(
                "invalid_request: $field must be ${expectedBytes * 2} hex characters",
            )
        }
        return try {
            Hex.decode(value)
        } catch (exc: IllegalArgumentException) {
            throw ProtocolException("invalid_request: $field is not valid hex")
        }
    }

    private fun requireField(json: JSONObject, field: String): Any {
        if (!json.has(field) || json.isNull(field)) {
            throw ProtocolException("invalid_request: $field is required")
        }
        return json.get(field)
    }
}
