package org.ukey.crypto

/** Lowercase hexadecimal helpers shared by the bridge and the credential codec. */
object Hex {
    private val DIGITS = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        var i = 0
        for (byte in bytes) {
            val value = byte.toInt() and 0xff
            out[i++] = DIGITS[value ushr 4]
            out[i++] = DIGITS[value and 0x0f]
        }
        return String(out)
    }

    fun decode(text: String): ByteArray {
        require(text.length % 2 == 0) { "hex string must have an even length" }
        val out = ByteArray(text.length / 2)
        for (i in out.indices) {
            val high = Character.digit(text[i * 2], 16)
            val low = Character.digit(text[i * 2 + 1], 16)
            require(high >= 0 && low >= 0) { "hex string contains a non-hex character" }
            out[i] = ((high shl 4) or low).toByte()
        }
        return out
    }
}
