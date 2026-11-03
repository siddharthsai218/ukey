package org.ukey.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger

class DerUtilsTest {

    @Test
    fun decodesTypicalDerSignature() {
        val der = hex(
            "3045" +
                "022100" + "aa".repeat(32) +
                "0220" + "55".repeat(32),
        )

        val raw = DerUtils.derToRaw(der)

        assertEquals(64, raw.size)
        assertArrayEquals(ByteArray(32) { 0xaa.toByte() }, raw.copyOfRange(0, 32))
        assertArrayEquals(ByteArray(32) { 0x55.toByte() }, raw.copyOfRange(32, 64))
    }

    @Test
    fun stripsLeadingZeroFromThirtyThreeByteIntegers() {
        val der = hex(
            "3046" +
                "022100" + "ff".repeat(32) +
                "022100" + "81".repeat(32),
        )

        val raw = DerUtils.derToRaw(der)

        assertEquals(64, raw.size)
        assertArrayEquals(ByteArray(32) { 0xff.toByte() }, raw.copyOfRange(0, 32))
        assertArrayEquals(ByteArray(32) { 0x81.toByte() }, raw.copyOfRange(32, 64))
    }

    @Test
    fun leftPadsShortIntegers() {
        val der = hex(
            "3025020101" +
                "0220" + "02".repeat(32),
        )

        val raw = DerUtils.derToRaw(der)

        assertEquals(64, raw.size)
        assertArrayEquals(
            ByteArray(32).also { it[31] = 1 },
            raw.copyOfRange(0, 32),
        )
        assertArrayEquals(ByteArray(32) { 2 }, raw.copyOfRange(32, 64))
    }

    @Test
    fun rejectsTrailingData() {
        val der = hex("30250201010220" + "02".repeat(32) + "00")
        assertThrows(IllegalArgumentException::class.java) { DerUtils.derToRaw(der) }
    }

    @Test
    fun rejectsNegativeInteger() {
        val der = hex("3025020181" + "0220" + "02".repeat(32))
        assertThrows(IllegalArgumentException::class.java) { DerUtils.derToRaw(der) }
    }

    @Test
    fun rejectsNonMinimalLeadingZero() {
        val der = hex("302602020001" + "0220" + "02".repeat(32))
        assertThrows(IllegalArgumentException::class.java) { DerUtils.derToRaw(der) }
    }

    @Test
    fun rejectsZeroInteger() {
        val der = hex("3025020100" + "0220" + "02".repeat(32))
        assertThrows(IllegalArgumentException::class.java) { DerUtils.derToRaw(der) }
    }

    @Test
    fun rejectsWrongSequenceTag() {
        val der = hex("31250201010220" + "02".repeat(32))
        assertThrows(IllegalArgumentException::class.java) { DerUtils.derToRaw(der) }
    }

    @Test
    fun derivesThirtyTwoByteCoordinates() {
        assertArrayEquals(
            ByteArray(32).also { it[31] = 7 },
            EcUtil.coordinate32(BigInteger.valueOf(7)),
        )
        assertArrayEquals(
            ByteArray(32) { 0xff.toByte() },
            EcUtil.coordinate32(BigInteger("ff".repeat(32), 16)),
        )
        assertArrayEquals(
            ByteArray(32) { 0xff.toByte() },
            EcUtil.coordinate32(BigInteger(byteArrayOf(0) + ByteArray(32) { 0xff.toByte() })),
        )
    }

    @Test
    fun credentialIdBindsRpAndRoundTripsUuid() {
        val uuid = java.util.UUID.fromString("123e4567-e89b-12d3-a456-426614174000")
        val credId = EcUtil.credentialId("example.com", uuid)

        assertEquals(32, credId.size)
        assertArrayEquals(EcUtil.rpHashPrefix("example.com"), credId.copyOfRange(0, 16))
        assertEquals(uuid, EcUtil.uuidFromBytes(credId.copyOfRange(16, 32)))
        assertEquals("ukey_cred_123e4567-e89b-12d3-a456-426614174000", EcUtil.alias(uuid))
    }

    private fun hex(value: String): ByteArray = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
