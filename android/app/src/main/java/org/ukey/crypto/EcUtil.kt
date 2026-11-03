package org.ukey.crypto

import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.UUID

/** Small, testable helpers for EC coordinates and stateless credential IDs. */
object EcUtil {
    const val COORDINATE_BYTES = 32
    const val RP_HASH_BYTES = 16
    const val CREDENTIAL_ID_BYTES = RP_HASH_BYTES + 16

    fun coordinate32(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        return when {
            raw.size == COORDINATE_BYTES -> raw
            raw.size == COORDINATE_BYTES + 1 && raw[0] == 0.toByte() ->
                raw.copyOfRange(1, raw.size)
            raw.size < COORDINATE_BYTES ->
                ByteArray(COORDINATE_BYTES - raw.size) + raw
            else -> throw IllegalArgumentException("EC coordinate is wider than 32 bytes")
        }
    }

    fun rpHashPrefix(rpId: String): ByteArray =
        MessageDigest.getInstance("SHA-256")
            .digest(rpId.toByteArray(Charsets.UTF_8))
            .copyOfRange(0, RP_HASH_BYTES)

    fun uuidBytes(uuid: UUID): ByteArray =
        ByteBuffer.allocate(16)
            .putLong(uuid.mostSignificantBits)
            .putLong(uuid.leastSignificantBits)
            .array()

    fun uuidFromBytes(bytes: ByteArray): UUID {
        require(bytes.size == 16) { "a UUID must be 16 bytes" }
        val buffer = ByteBuffer.wrap(bytes)
        return UUID(buffer.long, buffer.long)
    }

    /**
     * Credential ID layout: SHA-256(rp_id)[0..15] || UUID[0..15].
     *
     * This keeps the credential ID stateless and 32 bytes long while binding
     * it to the RP. The alias is derived from the UUID portion, so no
     * credential database is needed on the phone.
     */
    fun credentialId(rpId: String, uuid: UUID): ByteArray =
        rpHashPrefix(rpId) + uuidBytes(uuid)

    fun alias(uuid: UUID): String = "ukey_cred_$uuid"
}
