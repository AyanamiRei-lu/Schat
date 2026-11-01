package com.schat.android.ui.home

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.schat.android.AppInfo
import com.schat.android.core.contacts.abbreviate
import com.schat.android.core.qr.QrPayload
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatShapes
import com.schat.android.ui.ui.GradientAvatar
import com.schat.android.ui.ui.SchatQrDialog
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel

/**
 * 「我的」页。
 *
 * 一张身份卡 + 三组条目。身份卡上不显示完整公钥——那串 64 位十六进制在这里除了让人
 * 以为自己看懂了以外没有用处，真正需要核对它的时候在「详情」和二维码里。
 */
@Composable
fun MineTab(
    myIdentity: String,
    nickname: String,
    onSetNickname: (String) -> Unit,
    serverDisplay: String,
    serverUri: String,
    onOpenRecovery: () -> Unit,
) {
    var showIdentityQr by remember { mutableStateOf(false) }
    var showServerQr by remember { mutableStateOf(false) }
    var showNickname by remember { mutableStateOf(false) }

    Column(modifier = Modifier.fillMaxSize()) {
        ScreenHeader(title = "我的")

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = Dimens.ScreenHorizontal, vertical = Dimens.Lg),
            verticalArrangement = Arrangement.spacedBy(Dimens.Lg),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
            ) {
                GradientAvatar(
                    label = nickname.ifBlank { "S" },
                    hue = hueOf(myIdentity),
                    size = 56.dp,
                )
                Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                    Text(
                        text = nickname.ifBlank { "SCHAT 身份" },
                        style = MaterialTheme.typography.titleMedium,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                    Text(
                        text = if (myIdentity.isEmpty()) "身份不可用" else abbreviate(myIdentity),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                    )
                }
            }

            SectionLabel("我的")

            MineGroup {
                MineRow(
                    label = "昵称",
                    value = nickname.ifBlank { "未设置" },
                    onClick = { showNickname = true },
                )
                MineDivider()
                MineRow(label = "我的二维码", onClick = { showIdentityQr = true })
                MineDivider()
                MineRow(label = "服务器连接码", onClick = { showServerQr = true })
                MineDivider()
                MineRow(label = "恢复码", onClick = onOpenRecovery)
            }

            SectionLabel("服务器")

            MineGroup {
                MineRow(label = "中继地址", value = serverDisplay, onClick = { showServerQr = true })
            }

            SectionLabel("关于")

            MineGroup {
                MineRow(label = "版本", value = "v${AppInfo.VERSION}", onClick = {})
                MineDivider()
                MineRow(label = "单聊协议", value = AppInfo.PROTOCOL, onClick = {})
                MineDivider()
                MineRow(label = "群聊协议", value = "MLS (RFC 9420)", onClick = {})
            }

            Spacer(modifier = Modifier.height(Dimens.Xs))
        }
    }

    if (showIdentityQr) {
        SchatQrDialog(
            title = "我的身份二维码",
            payload = QrPayload.identity(myIdentity),
            explain = "让对方扫这个码，省去手抄 64 位十六进制。扫到的只是公钥，不能证明谁是谁。",
            onDismiss = { showIdentityQr = false },
        )
    }

    if (showServerQr) {
        SchatQrDialog(
            title = "服务器连接码",
            payload = QrPayload.serverConfig(serverUri),
            explain = "让另一台设备在首次引导的「配置服务器」那一步扫它，就不必手动粘贴。",
            onDismiss = { showServerQr = false },
        )
    }

    if (showNickname) {
        NicknameDialog(
            current = nickname,
            onConfirm = {
                onSetNickname(it)
                showNickname = false
            },
            onDismiss = { showNickname = false },
        )
    }
}

/**
 * 设置昵称。
 *
 * 它是**自报名**：别人会看到，任何人都可以自称任何名字。所以文案里不写「你的名字」，
 * 而写「别人会看到这个名字」，并把唯一能确认身份的办法（安全码）同一句说清楚。
 */
@Composable
private fun NicknameDialog(
    current: String,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf(current) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("设置昵称") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("昵称") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    text = "别人会看到这个名字。任何人都可以自称任何名字，确认身份请比对安全码。",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    text = "留空则显示身份缩写。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(name) }) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

/** 一组条目：一张浅灰卡片，条目之间一条细线。 */
@Composable
private fun MineGroup(content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(SchatShapes.Medium)
            .background(MaterialTheme.colorScheme.surfaceContainerLow),
        content = content,
    )
}

@Composable
private fun MineDivider() {
    HorizontalDivider(
        thickness = 1.dp,
        color = MaterialTheme.colorScheme.outline,
        modifier = Modifier.padding(start = Dimens.Lg),
    )
}

/** 一行条目：标题 + 可选的值 + 一个指示箭头。 */
@Composable
private fun MineRow(label: String, value: String? = null, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = Dimens.Lg, vertical = 14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyLarge,
        )
        Spacer(modifier = Modifier.weight(1f))
        if (value != null) {
            Text(
                text = value,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        Text(
            text = "›",
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.padding(start = Dimens.Sm),
        )
    }
}

/** 稳定的身份色相：同一个人永远是同一个颜色。它是装饰，不是标识。 */
private fun hueOf(identityHex: String): Float =
    identityHex.take(2).toIntOrNull(16)?.times(360f)?.div(256f) ?: 200f
