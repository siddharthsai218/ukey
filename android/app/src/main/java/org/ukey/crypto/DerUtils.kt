package org.ukey.crypto

/**
 * Strict ASN.1 DER ECDSA signature decoder.
 *
 * AndroidKeyStore emits DER SEQUENCE(INTEGER r, INTEGER s). CTAP2/WebAuthn
 * require fixed-width 32-byte r and 32-byte s values, so this decoder rejects
 * malformed, negative, non-minimal, over-wide, or trailing data rather than
 * silently producing a signature the host would reject.
 */
object DerUtils {
    private const val TAG_INTEGER = 0x02
    private const val TAG_SEQUENCE = 0x30
    private const val COORDINATE_BYTES = 32

    @JvmStatic
    fun derToRaw(der: ByteArray): ByteArray {
        val parser = DerParser(der)
        parser.expect(TAG_SEQUENCE)
        val sequenceLength = parser.readLength()
        require(sequenceLength == parser.remaining) {
            "DER sequence length $sequenceLength does not match ${parser.remaining} remaining bytes"
        }

        val r = parser.readPositiveInteger("r")
        val s = parser.readPositiveInteger("s")
        require(parser.remaining == 0) { "trailing data after DER signature" }

        return normalize(r, "r") + normalize(s, "s")
    }

    private fun normalize(value: ByteArray, name: String): ByteArray {
        require(value.isNotEmpty()) { "ECDSA $name is empty" }
        var offset = 0
        if (value.size > COORDINATE_BYTES) {
            require(value.size == COORDINATE_BYTES + 1 && value[0] == 0.toByte()) {
                "ECDSA $name is wider than 32 bytes"
            }
            offset = 1
        }
        val significantLength = value.size - offset
        require(significantLength <= COORDINATE_BYTES) { "ECDSA $name is wider than 32 bytes" }
        require(value.any { it != 0.toByte() }) { "ECDSA $name is zero" }

        return ByteArray(COORDINATE_BYTES).also { output ->
            value.copyInto(
                destination = output,
                destinationOffset = COORDINATE_BYTES - significantLength,
                startIndex = offset,
                endIndex = value.size,
            )
        }
    }

    private class DerParser(private val bytes: ByteArray) {
        var position: Int = 0
            private set

        val remaining: Int
            get() = bytes.size - position

        fun expect(tag: Int) {
            require(remaining > 0) { "unexpected end of DER signature" }
            require((bytes[position].toInt() and 0xff) == tag) {
                "expected DER tag 0x${tag.toString(16)}, found 0x${(bytes[position].toInt() and 0xff).toString(16)}"
            }
            position++
        }

        fun readLength(): Int {
            require(remaining > 0) { "missing DER length" }
            val first = bytes[position++].toInt() and 0xff
            if (first < 0x80) {
                return first
            }

            val byteCount = first and 0x7f
            require(byteCount in 1..4) { "unsupported DER length form" }
            require(remaining >= byteCount) { "truncated DER length" }
            require((bytes[position].toInt() and 0xff) != 0) { "non-minimal DER length" }

            var length = 0
            repeat(byteCount) {
                length = (length shl 8) or (bytes[position++].toInt() and 0xff)
            }
            require(length >= 0x80) { "non-minimal long-form DER length" }
            return length
        }

        fun readPositiveInteger(name: String): ByteArray {
            expect(TAG_INTEGER)
            val length = readLength()
            require(length > 0) { "ECDSA $name has zero length" }
            require(remaining >= length) { "truncated ECDSA $name" }
            val value = bytes.copyOfRange(position, position + length)
            position += length

            require((value[0].toInt() and 0x80) == 0) { "ECDSA $name is negative" }
            if (length > 1 && value[0] == 0.toByte()) {
                require((value[1].toInt() and 0x80) != 0) {
                    "ECDSA $name has a non-minimal leading zero"
                }
            }
            return value
        }
    }
}
