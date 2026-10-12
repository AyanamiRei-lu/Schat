package com.schat.android.ui.qr

import android.graphics.Bitmap
import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap

/**
 * Renders a QR module matrix.
 *
 * # Why the matrix is rendered directly rather than as a scaled bitmap
 *
 * A QR code is a grid of squares, and any resampling that is not nearest-neighbour turns
 * those squares into soft blobs. At the sizes involved here (a 640-pixel matrix shown in a
 * 260dp box) bilinear filtering is the difference between a code that scans instantly and
 * one that only scans if you hold the phone very still. [FilterQuality.None] is therefore
 * not a cosmetic choice.
 *
 * The matrix already contains the quiet zone, so no padding is added: an extra margin
 * would be harmless, but a missing one makes the code unscannable, and it is safer to have
 * exactly one place that decides.
 */
@Composable
fun QrImage(
    matrix: Array<BooleanArray>,
    contentDescription: String?,
    modifier: Modifier = Modifier,
) {
    val bitmap = remember(matrix) { matrix.toImageBitmap() }
    Image(
        bitmap = bitmap,
        contentDescription = contentDescription,
        modifier = modifier,
        filterQuality = FilterQuality.None,
    )
}

/** Converts a module matrix to an ARGB bitmap, one pixel per module. */
private fun Array<BooleanArray>.toImageBitmap(): ImageBitmap {
    val height = size
    val width = if (height == 0) 0 else this[0].size
    require(width > 0 && height > 0) { "a QR matrix must not be empty" }

    val pixels = IntArray(width * height)
    for (y in 0 until height) {
        val row = this[y]
        val offset = y * width
        for (x in 0 until width) {
            pixels[offset + x] = if (x < row.size && row[x]) DARK else LIGHT
        }
    }

    return Bitmap.createBitmap(pixels, width, height, Bitmap.Config.ARGB_8888).asImageBitmap()
}

private const val DARK = 0xFF000000.toInt()
private const val LIGHT = 0xFFFFFFFF.toInt()
