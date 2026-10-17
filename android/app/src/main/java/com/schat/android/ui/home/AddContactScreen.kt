package com.schat.android.ui.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import com.schat.android.core.qr.QrPayload
import com.schat.android.ui.qr.QrScannerScreen
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.theme.SchatShapes
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.GradientButton
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel
import com.schat.android.ui.ui.isDarkNow

/**
 * 添加联系人：扫码，或手抄 64 位十六进制。
 *
 * 扫码在前，理由是手抄会错：抄错一位产生的报错和"对方从未发布预密钥"**逐字相同**，
 * 两种原因从现象上无法区分。
 */
@Composable
fun AddContactScreen(
    onStartSession: (String) -> Unit,
    onBack: () -> Unit,
) {
    var peer by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }
    val dark = isDarkNow()

    val looksValid = peer.trim().length == 64 &&
        peer.trim().lowercase().all { it in "0123456789abcdef" }

    if (scanning) {
        QrScannerScreen(
            title = "扫描身份二维码",
            hint = "对准对方「我的 → 我的二维码」里的那个码。",
            onResult = { text ->
                scanning = false
                when (val payload = QrPayload.parse(text)) {
                    is QrPayload.Identity -> {
                        peer = payload.identityHex
                        note = null
                    }
                    is QrPayload.ServerConfig -> note = "这是服务器连接码，不是身份码"
                    null -> note = "这个二维码里不是 SCHAT 的身份信息"
                }
            },
            onCancel = { scanning = false },
        )
        return
    }

    ScreenBackground {
        Column(modifier = Modifier.fillMaxSize()) {
            ScreenHeader(
                title = "添加联系人",
                onBack = onBack,
                backLabel = "返回",
            )

            ContentColumn(vertical = Dimens.Lg, gap = Dimens.Lg) {
                SectionLabel("对方身份")
                TextField(
                    value = peer,
                    onValueChange = {
                        peer = it
                        note = null
                    },
                    placeholder = { Text("64 位十六进制身份公钥") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = SchatShapes.Medium,
                    colors = TextFieldDefaults.colors(
                        focusedContainerColor = if (dark) SchatPalette.GrayBubbleDark else SchatPalette.GrayBubble,
                        unfocusedContainerColor = if (dark) SchatPalette.GrayBubbleDark else SchatPalette.GrayBubble,
                        focusedIndicatorColor = Color.Transparent,
                        unfocusedIndicatorColor = Color.Transparent,
                    ),
                )

                note?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }

                GradientButton(text = "扫码", onClick = { scanning = true })

                GradientButton(
                    text = "发出会话请求",
                    onClick = { onStartSession(peer.trim().lowercase()) },
                    enabled = looksValid,
                )

                Text(
                    text = "扫码只代替手抄，不证明对方是谁。建立会话后比对安全码。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
