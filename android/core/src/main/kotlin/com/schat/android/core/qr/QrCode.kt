package com.schat.android.core.qr

import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel

/**
 * QR encoding and decoding.
 *
 * # Why this lives in :core rather than :app
 *
 * ZXing core is pure Java: no Android, no native code. Keeping it here means the encode
 * path, the decode-from-luminance path and the payload format are all exercised by the
 * JVM suite on every build. The only part that needs a device is the camera that produces
 * the luminance plane — and that part, unlike this, cannot be got wrong silently.
 *
 * # Error correction and why it is not maxed out
 *
 * The payloads are tiny (a 64-character identity is 89 bytes as a URI), so even the
 * default level leaves a comfortable margin. Level M is used deliberately: a denser QR at
 * level H would pack more modules into the same area, which on a phone screen at arm's
 * length is a worse trade than the extra redundancy.
 */
object QrCode {

    /** Quiet zone in modules, per ISO/IEC 18004. ZXing's writer applies it itself. */
    const val DEFAULT_SIZE = 640

    private val WRITER = QRCodeWriter()

    /**
     * Encodes [text] as a square module matrix.
     *
     * `true` means a dark module. The matrix is [size] x [size] and includes the quiet
     * zone, so it can be rendered directly with no further padding.
     */
    fun encode(text: String, size: Int = DEFAULT_SIZE): Array<BooleanArray> {
        require(text.isNotEmpty()) { "nothing to encode" }
        require(size > 0) { "size must be positive, got $size" }

        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            // A one-module margin would leave a decoder no white border to find the code
            // against; ZXing's writer takes the quiet zone in modules.
            EncodeHintType.MARGIN to 4,
            EncodeHintType.CHARACTER_SET to "UTF-8",
        )

        val matrix = WRITER.encode(text, BarcodeFormat.QR_CODE, size, size, hints)
        return Array(matrix.height) { y -> BooleanArray(matrix.width) { x -> matrix.get(x, y) } }
    }

    /**
     * Decodes a module matrix, as produced by [encode].
     *
     * This exists so the encode side has a test that does not need a camera: a QR code
     * that renders beautifully but decodes to something else is a failure no screenshot
     * would reveal.
     */
    fun decode(matrix: Array<BooleanArray>): String? {
        if (matrix.isEmpty() || matrix[0].isEmpty()) return null

        val height = matrix.size
        val width = matrix[0].size
        val pixels = IntArray(width * height)
        for (y in 0 until height) {
            val row = matrix[y]
            for (x in 0 until width) {
                pixels[y * width + x] = if (x < row.size && row[x]) DARK else LIGHT
            }
        }

        return decodeSource(RGBLuminanceSource(width, height, pixels))
    }

    /**
     * Decodes one camera frame.
     *
     * [data] is the Y (luminance) plane of a YUV_420_888 frame, and [rowStride] is its
     * actual row length, which is usually LARGER than [width] because of hardware
     * alignment. Passing [width] as the stride would shear the image by a few pixels per
     * row, which does not look broken — it simply never decodes, and looks exactly like
     * "the camera cannot read QR codes".
     *
     * No rotation is applied: the QR detector locates the three finder patterns and
     * solves the perspective transform, so it reads the code at any orientation.
     */
    fun decodeLuminance(data: ByteArray, width: Int, height: Int, rowStride: Int): String? {
        if (width <= 0 || height <= 0) return null
        if (data.size < rowStride * height) return null

        return decodeSource(
            PlanarYUVLuminanceSource(data, rowStride, height, 0, 0, width, height, false),
        )
    }

    /** Runs the reader over a luminance source, returning null instead of throwing. */
    private fun decodeSource(source: com.google.zxing.LuminanceSource): String? {
        val reader = MultiFormatReader()
        reader.setHints(
            mapOf(
                // Restricted to QR on purpose: without this a poster's barcode could be
                // accepted as a peer identity and the user would be told the other device
                // had published nothing.
                DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
                DecodeHintType.TRY_HARDER to true,
            ),
        )

        return try {
            reader.decodeWithState(BinaryBitmap(HybridBinarizer(source))).text
        } catch (e: Exception) {
            // NotFoundException is the ordinary "no code in this frame" result, which
            // happens on most frames. Treating it as an error would spam the log and
            // invite someone to "fix" it.
            null
        } finally {
            reader.reset()
        }
    }

    private const val DARK = 0xFF000000.toInt()
    private const val LIGHT = 0xFFFFFFFF.toInt()
}
