package com.schat.android.ui.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.schat.android.core.qr.QrCode
import com.schat.android.ui.qr.QrImage
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatShapes

/**
 * Shows a payload as a QR code.
 *
 * # What this does not do
 *
 * It does not authenticate anything. The device that scans it learns exactly the
 * characters shown here and nothing more — the same thing a hand-typed copy would
 * convey. The gain is that no character can be mistyped, which matters because a single
 * wrong hex digit produces the same "no bundle published for that identity" error as a
 * peer that has not published at all.
 *
 * Both callers say in [explain] what the scan does and does not establish, so that
 * neither scanning an identity nor scanning a connection code feels like a completed
 * trust decision.
 */
@Composable
fun SchatQrDialog(
    title: String,
    payload: String,
    explain: String,
    onDismiss: () -> Unit,
) {
    if (payload.isEmpty()) return

    val matrix = remember(payload) { QrCode.encode(payload) }
    val clipboard = LocalClipboardManager.current

    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = SchatShapes.Large, color = MaterialTheme.colorScheme.surface) {
            Column(
                modifier = Modifier
                    .verticalScroll(rememberScrollState())
                    .padding(Dimens.Xl),
                verticalArrangement = Arrangement.spacedBy(Dimens.Md),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                SectionLabel(title, modifier = Modifier.fillMaxWidth())

                // 二维码本身必须是纯白底、纯黑点：这是扫码能不能读出来的前提，
                // 所以它被放在一张白卡片上，而这张卡片不参与任何渐变。
                Surface(
                    shape = SchatShapes.Medium,
                    color = Color.White,
                    modifier = Modifier.padding(vertical = Dimens.Xs),
                ) {
                    QrImage(
                        matrix = matrix,
                        contentDescription = title,
                        modifier = Modifier
                            .padding(Dimens.Sm)
                            .size(250.dp),
                    )
                }

                MonoBlock(
                    text = groupInFours(payload),
                    container = MaterialTheme.colorScheme.surfaceContainerLow,
                )

                Text(
                    text = explain,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
                ) {
                    GhostButton(
                        text = "复制",
                        onClick = { clipboard.setText(AnnotatedString(payload)) },
                        modifier = Modifier.weight(1f),
                    )
                    GradientButton(
                        text = "关闭",
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

/** Groups a hex string in fours so it can be read aloud and compared. */
private fun groupInFours(value: String): String = value.chunked(4).joinToString(" ")
