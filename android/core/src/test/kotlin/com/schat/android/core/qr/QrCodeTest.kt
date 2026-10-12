package com.schat.android.core.qr

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * QR encoding and decoding.
 *
 * The point of these tests is that a QR code that renders correctly but decodes to
 * something else fails in a way no screenshot can reveal: the other device would simply
 * reject the payload, or worse, accept a different one.
 */
class QrCodeTest {

    private val identity = "a951b5f835dd154622a5bf766a33c2ca475cef6d0688e7a54949a2f5592feef1"

    private val serverUri = "schat://connect?fp=eaa60c0122806c861bf30f599a624e46114ded9b" +
        "568916c146b4fd414ebed325&h=192.168.1.158&n=my-relay&p=8443&ss=1"

    @Test
    fun `an identity payload survives an encode-decode round trip`() {
        val payload = QrPayload.identity(identity)

        val decoded = QrCode.decode(QrCode.encode(payload))

        assertEquals(payload, decoded)
        assertEquals(QrPayload.Identity(identity), QrPayload.parse(decoded))
    }

    @Test
    fun `a connection URI survives an encode-decode round trip`() {
        // The longest payload the app produces, and the one where a truncated or corrupted
        // read would be easiest to miss.
        val decoded = QrCode.decode(QrCode.encode(serverUri))

        assertEquals(serverUri, decoded)
        assertEquals(QrPayload.ServerConfig(serverUri), QrPayload.parse(decoded))
    }

    @Test
    fun `the matrix is square and carries a quiet zone`() {
        val matrix = QrCode.encode(QrPayload.identity(identity), size = 512)

        assertEquals(512, matrix.size)
        assertTrue(matrix.all { it.size == 512 })

        // The outermost ring must be light, or a decoder has no border to find the code
        // against and the code simply never reads.
        assertTrue("top row is not a quiet zone", matrix.first().none { it })
        assertTrue("bottom row is not a quiet zone", matrix.last().none { it })
        assertTrue("left column is not a quiet zone", matrix.all { !it.first() })
        assertTrue("right column is not a quiet zone", matrix.all { !it.last() })
    }

    @Test
    fun `an empty frame decodes to nothing rather than throwing`() {
        val blank = Array(64) { BooleanArray(64) { false } }
        assertNull(QrCode.decode(blank))
        assertNull(QrCode.decode(emptyArray()))
        assertNull(QrCode.decode(arrayOf(BooleanArray(0))))
    }

    @Test
    fun `encoding nothing is refused`() {
        val failed = try {
            QrCode.encode("")
            false
        } catch (e: IllegalArgumentException) {
            true
        }
        assertTrue("encoding an empty payload should be refused", failed)
    }

    @Test
    fun `a camera luminance plane decodes`() {
        val matrix = QrCode.encode(QrPayload.identity(identity), size = 256)
        val height = matrix.size
        val width = matrix[0].size

        // Y=0 is black, Y=255 is white.
        val luminance = ByteArray(width * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                luminance[y * width + x] = if (matrix[y][x]) 0 else 255.toByte()
            }
        }

        val decoded = QrCode.decodeLuminance(luminance, width, height, width)
        assertEquals(QrPayload.identity(identity), decoded)
    }

    @Test
    fun `a luminance plane whose rows are padded still decodes`() {
        // The trap this guards: hardware aligns camera rows, so rowStride is usually
        // larger than width. Passing width as the stride shears the image by a few pixels
        // per row — it does not look broken, it just never decodes, which is
        // indistinguishable from "this phone cannot read QR codes".
        val matrix = QrCode.encode(QrPayload.identity(identity), size = 256)
        val height = matrix.size
        val width = matrix[0].size
        val rowStride = width + 16

        val luminance = ByteArray(rowStride * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                luminance[y * rowStride + x] = if (matrix[y][x]) 0 else 255.toByte()
            }
            // Padding bytes: real cameras leave whatever was in the buffer here.
            for (x in width until rowStride) {
                luminance[y * rowStride + x] = 0x40
            }
        }

        val decoded = QrCode.decodeLuminance(luminance, width, height, rowStride)
        assertNotNull("a padded luminance plane failed to decode", decoded)
        assertEquals(QrPayload.identity(identity), decoded)
    }

    @Test
    fun `a truncated buffer is refused instead of read past its end`() {
        assertNull(QrCode.decodeLuminance(ByteArray(10), 100, 100, 100))
        assertNull(QrCode.decodeLuminance(ByteArray(0), 0, 0, 0))
    }
}
