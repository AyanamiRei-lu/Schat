package com.schat.android.ui.qr

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.schat.android.core.qr.QrCode
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * A camera view that reads QR codes.
 *
 * # What this screen does with the camera, and what it does not
 *
 * It opens the back camera while it is on screen, decodes each preview frame in memory, and
 * drops it. No frame is written anywhere, and nothing leaves the device — the only value
 * that escapes this screen is the decoded string handed to [onResult]. That is why the
 * permission is requested here and nowhere else, at the moment it is needed, rather than
 * during onboarding: a user who never scans never grants it.
 *
 * # The two failure modes this is written around
 *
 * 1. **Row stride.** Camera frames are hardware-aligned, so a Y plane's rows are usually
 *    longer than the image is wide. Reading it as `width` bytes per row shears the picture
 *    by a few pixels per row, which looks fine and never decodes. The stride is passed
 *    through explicitly, and the buffer is padded to exactly `stride * height` because the
 *    final row is often delivered unpadded.
 *
 * 2. **Frames arriving faster than they are decoded.** The backpressure strategy keeps only
 *    the newest frame, and every frame is closed in a `finally`. A leaked ImageProxy
 *    exhausts the camera's buffer pool and analysis stops silently — after which the screen
 *    looks perfectly normal and simply never finds a code.
 *
 * # Untested on a device
 *
 * This file is compile-verified only. There is no camera in the build environment, so the
 * first real run is the first test. The *logic* it depends on — the payload format, the
 * encoder, and the luminance decoder including the stride case — is covered by :core's JVM
 * suite, which is exactly why it was put there.
 */
@Composable
fun QrScannerScreen(
    title: String,
    hint: String,
    onResult: (String) -> Unit,
    onCancel: () -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current

    var granted by remember {
        mutableStateOf(
            context.checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED,
        )
    }
    var requested by remember { mutableStateOf(false) }
    var cameraError by remember { mutableStateOf<String?>(null) }

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { allowed -> granted = allowed }

    // Asked once, on arrival. Re-prompting on every recomposition would be a denial loop.
    LaunchedEffect(Unit) {
        if (!granted && !requested) {
            requested = true
            launcher.launch(Manifest.permission.CAMERA)
        }
    }

    val previewView = remember {
        PreviewView(context).apply { scaleType = PreviewView.ScaleType.FILL_CENTER }
    }
    val executor = remember { Executors.newSingleThreadExecutor { r -> Thread(r, "schat-qr").apply { isDaemon = true } } }
    val mainHandler = remember { Handler(Looper.getMainLooper()) }
    /** Set once a code is read, so a burst of frames cannot deliver it several times. */
    val handled = remember { AtomicBoolean(false) }
    var provider by remember { mutableStateOf<ProcessCameraProvider?>(null) }

    DisposableEffect(Unit) {
        onDispose {
            provider?.unbindAll()
            executor.shutdownNow()
        }
    }

    LaunchedEffect(granted, previewView) {
        if (!granted) return@LaunchedEffect
        try {
            val resolved = context.cameraProvider()
            provider = resolved

            val preview = Preview.Builder().build()
            preview.setSurfaceProvider(previewView.surfaceProvider)

            val analysis = ImageAnalysis.Builder()
                .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()

            analysis.setAnalyzer(executor) { proxy -> analyze(proxy, handled, mainHandler, onResult) }

            resolved.unbindAll()
            resolved.bindToLifecycle(
                lifecycleOwner,
                CameraSelector.DEFAULT_BACK_CAMERA,
                preview,
                analysis,
            )
            cameraError = null
        } catch (e: Exception) {
            cameraError = e.message ?: e.javaClass.simpleName
        }
    }

    Column(modifier = Modifier.fillMaxSize().padding(16.dp)) {
        Text(
            text = title,
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = hint,
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 4.dp, bottom = 12.dp),
        )

        Box(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            contentAlignment = Alignment.Center,
        ) {
            when {
                !granted -> PermissionRequest(onRequest = { launcher.launch(Manifest.permission.CAMERA) })
                cameraError != null -> Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer,
                    ),
                ) {
                    Text(
                        text = "相机无法启动：$cameraError\n\n你仍然可以返回并手动输入。",
                        modifier = Modifier.padding(12.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
                else -> AndroidView(factory = { previewView }, modifier = Modifier.fillMaxSize())
            }
        }

        TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
            Text("返回（手动输入）")
        }
    }
}

/** Explains the permission without pressuring the user into granting it. */
@Composable
private fun PermissionRequest(onRequest: () -> Unit) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text(
            text = "扫码需要相机权限。",
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            text = "相机只在这个界面打开，画面只在内存里解码，不会被保存或上传。" +
                "不授权也没关系——返回后可以手动输入对方的身份公钥。",
            style = MaterialTheme.typography.bodySmall,
        )
        Button(onClick = onRequest) { Text("允许使用相机") }
    }
}

/**
 * Decodes one frame and reports a hit.
 *
 * The buffer is copied into an exactly `stride * height` array before decoding, because the
 * plane's own buffer is frequently one row short of that (the last row is not padded), and
 * a decoder that is handed a short buffer must either refuse it or read past its end.
 */
private fun analyze(
    proxy: ImageProxy,
    handled: AtomicBoolean,
    mainHandler: Handler,
    onResult: (String) -> Unit,
) {
    try {
        if (handled.get()) return

        val image = proxy.image ?: return
        if (image.planes.isEmpty()) return

        val plane = image.planes[0]
        val stride = plane.rowStride
        val buffer = plane.buffer

        val expected = stride * image.height
        if (expected <= 0) return

        val data = ByteArray(expected)
        buffer.get(data, 0, minOf(buffer.remaining(), expected))

        val text = QrCode.decodeLuminance(data, image.width, image.height, stride) ?: return
        if (handled.compareAndSet(false, true)) {
            mainHandler.post { onResult(text) }
        }
    } catch (e: Exception) {
        // A frame that cannot be decoded is the normal case, not an error worth surfacing.
    } finally {
        // Always. A leaked ImageProxy exhausts the camera's buffer pool and analysis stops
        // without any visible sign.
        proxy.close()
    }
}

/** Resolves the camera provider, which is delivered through a ListenableFuture. */
private suspend fun Context.cameraProvider(): ProcessCameraProvider =
    suspendCancellableCoroutine { continuation ->
        val future = ProcessCameraProvider.getInstance(this)
        future.addListener(
            {
                try {
                    continuation.resume(future.get())
                } catch (e: Exception) {
                    continuation.resumeWithException(e)
                }
            },
            androidx.core.content.ContextCompat.getMainExecutor(this),
        )
    }
