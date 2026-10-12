package com.schat.android.ui.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.schat.android.chat.ChatMessage
import com.schat.android.chat.ChatState
import com.schat.android.chat.DeliveryState
import com.schat.android.core.contacts.Contact
import com.schat.android.core.qr.QrCode
import com.schat.android.core.qr.QrPayload
import com.schat.android.ui.qr.QrImage
import com.schat.android.ui.qr.QrScannerScreen
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The conversation screen.
 *
 * # Why the metadata warning is a permanent banner and not a dismissible dialog
 *
 * This build derives each mailbox from its owner's public identity, so anyone who knows
 * an identity can watch when that person receives traffic. The message contents stay
 * end-to-end encrypted — the mailbox is an address, not a key — but a user who is told
 * this once, in a dialog they tapped through during setup, will not remember it at the
 * moment it matters. The banner stays until the mechanism behind it is replaced, and it
 * is driven by the state flag rather than hardcoded, so removing it is tied to the fix.
 */
@Composable
fun ChatScreen(
    state: ChatState,
    myIdentity: String,
    serverUri: String,
    onStartSession: (String) -> Unit,
    onSend: (String) -> Unit,
    onOpenConversation: (String) -> Unit,
    onLeaveConversation: () -> Unit,
    onOpenGroups: () -> Unit,
    onCreateGroup: () -> Unit,
    onRenameContact: (String, String) -> Unit,
    onDeleteContact: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        if (state.mailboxIsDerivedFromIdentity) {
            MetadataWarning()
        }

        Header(
            state = state,
            myIdentity = myIdentity,
            serverUri = serverUri,
            onLeaveConversation = onLeaveConversation,
            onOpenGroups = onOpenGroups,
            onCreateGroup = onCreateGroup,
        )

        HorizontalDivider()

        if (state.peerIdentityHex.isEmpty()) {
            PeerPicker(
                contacts = state.contacts,
                onStartSession = onStartSession,
                onOpenConversation = onOpenConversation,
                onRenameContact = onRenameContact,
                onDeleteContact = onDeleteContact,
            )
        } else {
            MessageList(state = state, modifier = Modifier.weight(1f))
            Composer(onSend = onSend)
        }
    }
}

/**
 * The standing warning about this build's metadata protection.
 *
 * Worded to say exactly what leaks and what does not. "Metadata is not protected" alone
 * would be read as "messages can be read", which is false and would push users toward a
 * worse decision than the truth does.
 */
@Composable
internal fun MetadataWarning() {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp),
        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.errorContainer),
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Text(
                text = "⚠️ 本版本元数据保护未启用",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onErrorContainer,
            )
            Text(
                text = "信箱地址由你的身份公钥直接派生，因此知道你身份公钥的人可以观察到" +
                    "你何时在收发消息。消息内容仍然端到端加密，服务器与旁观者都读不到。" +
                    "这一项会在会话内令牌交换实现后被替换。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onErrorContainer,
                modifier = Modifier.padding(top = 4.dp),
            )
        }
    }
}

/** Identity, status line and the safety number. */
@Composable
private fun Header(
    state: ChatState,
    myIdentity: String,
    serverUri: String,
    onLeaveConversation: () -> Unit,
    onOpenGroups: () -> Unit,
    onCreateGroup: () -> Unit,
) {
    var showFullIdentity by remember { mutableStateOf(false) }
    var showQr by remember { mutableStateOf(false) }
    var showServerQr by remember { mutableStateOf(false) }

    Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp)) {
        Text(text = state.connection, style = MaterialTheme.typography.bodyMedium)

        if (state.error != null) {
            Text(
                text = state.error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }

        Text(
            text = "我的身份：" + if (showFullIdentity) group(myIdentity) else short(myIdentity),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = FontFamily.Monospace,
        )
        TextButton(onClick = { showFullIdentity = !showFullIdentity }) {
            Text(if (showFullIdentity) "隐藏我的完整身份" else "显示我的完整身份")
        }
        TextButton(onClick = onCreateGroup) {
            Text("新建群")
        }
        TextButton(onClick = onOpenGroups) {
            Text("群组")
        }
        TextButton(onClick = { showQr = true }) {
            Text("我的二维码")
        }
        TextButton(onClick = { showServerQr = true }, enabled = serverUri.isNotEmpty()) {
            Text("服务器连接码")
        }
        if (state.peerIdentityHex.isNotEmpty()) {
            // Without this the restored conversation would be a one-way door: the app
            // reopens the last peer on launch, so there has to be a way back to the picker.
            TextButton(onClick = onLeaveConversation) {
                Text("换一个联系人")
            }
        }

        if (showQr) {
            SchatQrDialog(
                title = "我的身份二维码",
                payload = QrPayload.identity(myIdentity),
                explain = "让对方扫这个码，就不必手抄 64 位十六进制了。" +
                    "注意：扫到的只是身份公钥，它不能证明对方是谁——建立会话后仍然必须比对安全码。",
                onDismiss = { showQr = false },
            )
        }

        if (showServerQr) {
            // The first device still has to paste the URI the relay printed, because
            // printing a QR on the relay itself would mean adding a QR library to a binary
            // that is mechanically checked to have no third-party dependencies. Every
            // device after the first can simply scan this.
            SchatQrDialog(
                title = "服务器连接码",
                payload = QrPayload.serverConfig(serverUri),
                explain = "让另一台设备在首次引导的「配置服务器」那一步扫这个码，它就不必手动粘贴。" +
                    "注意：这个码包含服务器地址与证书指纹，扫之前请确认对方要连的确实是同一台服务器。",
                onDismiss = { showServerQr = false },
            )
        }

        if (state.safetyNumber.isNotEmpty()) {
            Text(
                text = "安全码（请与对方当面或通过可信渠道逐组比对）：",
                style = MaterialTheme.typography.bodySmall,
            )
            Text(
                text = state.safetyNumber,
                style = MaterialTheme.typography.bodySmall,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

/** Asks for the peer's identity before any session exists. */
@Composable
private fun PeerPicker(
    contacts: List<Contact>,
    onStartSession: (String) -> Unit,
    onOpenConversation: (String) -> Unit,
    onRenameContact: (String, String) -> Unit,
    onDeleteContact: (String) -> Unit,
) {
    var peer by remember { mutableStateOf("") }
    var scanning by remember { mutableStateOf(false) }
    var note by remember { mutableStateOf<String?>(null) }
    val looksValid = peer.trim().length == 64 &&
        peer.trim().lowercase().all { it in "0123456789abcdef" }

    // The scanner takes over the whole screen while it is open: a camera preview behind a
    // half-visible form is worse than a clean handoff, and this way "where did my camera
    // go" is answerable by looking at the screen.
    if (scanning) {
        QrScannerScreen(
            title = "扫描对方的身份二维码",
            hint = "让对方在聊天界面点「我的二维码」，然后把这个框对准它。",
            onResult = { text ->
                scanning = false
                when (val payload = QrPayload.parse(text)) {
                    is QrPayload.Identity -> {
                        peer = payload.identityHex
                        note = null
                    }
                    is QrPayload.ServerConfig ->
                        note = "这是服务器连接码，不是身份码。请在首次引导的「配置服务器」里扫描它。"
                    null ->
                        note = "这个二维码里不是 SCHAT 的身份信息。"
                }
            },
            onCancel = { scanning = false },
        )
        return
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        // The contact list is local: nothing here is registered with the relay, and the
        // relay cannot enumerate who exists on it. Adding a friend is therefore just
        // "remember this identity", with no handshake with the server at all.
        if (contacts.isNotEmpty()) {
            Text(
                text = "会话",
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.Bold,
            )
            ContactRows(
                contacts = contacts,
                onOpen = onOpenConversation,
                onRename = onRenameContact,
                onDelete = onDeleteContact,
            )
            Text(
                text = "这份名单只保存在本机保险库里，不会上传，服务器也无法列举。",
                style = MaterialTheme.typography.bodySmall,
            )
            HorizontalDivider()
        }

        Text(
            text = "开始一段会话",
            style = MaterialTheme.typography.titleMedium,
            fontWeight = FontWeight.Bold,
        )
        Text(
            text = "扫对方的二维码，或手动输入对方的身份公钥（64 位十六进制）。",
            style = MaterialTheme.typography.bodySmall,
        )

        OutlinedTextField(
            value = peer,
            onValueChange = { peer = it },
            label = { Text("对端身份公钥") },
            singleLine = true,
            isError = peer.isNotEmpty() && !looksValid,
            modifier = Modifier.fillMaxWidth(),
        )

        // Scanning is offered first because typing is where the mistakes happen: one wrong
        // hex character produces exactly the same "no bundle published for that identity"
        // error as a peer that never published, so the typo is indistinguishable from the
        // symptom it mimics.
        Row(
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Button(onClick = { scanning = true }) { Text("扫码") }
            Text(
                text = "或手动输入上面的 64 位十六进制",
                style = MaterialTheme.typography.bodySmall,
            )
        }

        note?.let {
            Text(
                text = it,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
        }

        Button(
            onClick = { onStartSession(peer.trim()) },
            enabled = looksValid,
        ) {
            Text("获取预密钥并建立会话")
        }

        Text(
            text = "注意：建立会话只证明对方持有对应的私钥，不排除服务器替换了预密钥。" +
                "服务器在发布预密钥时不校验身份，所以建立会话后必须比对安全码。",
            style = MaterialTheme.typography.bodySmall,
        )
    }
}

/** The scrolling conversation. */
@Composable
internal fun MessageList(state: ChatState, modifier: Modifier = Modifier) {
    if (state.messages.isEmpty()) {
        Box(modifier = modifier.fillMaxWidth(), contentAlignment = Alignment.Center) {
            Text(
                text = "还没有消息。会话请求已发出，等对方上线即可。",
                style = MaterialTheme.typography.bodySmall,
            )
        }
        return
    }

    val listState = rememberLazyListState()
    // Jump rather than animate: with a long history, animating on every recomposition
    // fights the user's own scrolling.
    LaunchedEffect(state.messages.size) {
        listState.scrollToItem(state.messages.lastIndex)
    }

    LazyColumn(
        state = listState,
        modifier = modifier.fillMaxWidth(),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(8.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        items(state.messages, key = { it.id }) { message ->
            MessageBubble(message)
        }
    }
}

/** One message. */
@Composable
internal fun MessageBubble(message: ChatMessage) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (message.outgoing) Arrangement.End else Arrangement.Start,
    ) {
        Card(
            modifier = Modifier.fillMaxWidth(0.85f),
            colors = CardDefaults.cardColors(
                containerColor = if (message.outgoing) {
                    MaterialTheme.colorScheme.primaryContainer
                } else {
                    MaterialTheme.colorScheme.surfaceVariant
                },
            ),
        ) {
            Column(modifier = Modifier.padding(10.dp)) {
                Text(text = message.text, style = MaterialTheme.typography.bodyMedium)
                Text(
                    text = timeOf(message.atMillis) + statusSuffix(message),
                    style = MaterialTheme.typography.labelSmall,
                    color = if (message.state == DeliveryState.FAILED) {
                        MaterialTheme.colorScheme.error
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                )
            }
        }
    }
}

/** The composer. */
@Composable
internal fun Composer(onSend: (String) -> Unit) {
    var draft by remember { mutableStateOf("") }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(8.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            label = { Text("消息") },
            modifier = Modifier.weight(1f),
            maxLines = 4,
        )
        Button(
            onClick = {
                onSend(draft)
                draft = ""
            },
            enabled = draft.isNotBlank(),
        ) {
            Text("发送")
        }
    }
}

/**
 * Shows a payload as a QR code.
 *
 * # What this does not do
 *
 * It does not authenticate anything. The device that scans it learns exactly the characters
 * shown here and nothing more — the same thing a hand-typed copy would convey. The gain is
 * that no character can be mistyped, which matters because a single wrong hex digit
 * produces the same "no bundle published for that identity" error as a peer that has not
 * published at all.
 *
 * Both callers say in [explain] what the scan does and does not establish, so that neither
 * scanning an identity nor scanning a connection code feels like a completed trust
 * decision.
 */
@Composable
private fun SchatQrDialog(
    title: String,
    payload: String,
    explain: String,
    onDismiss: () -> Unit,
) {
    if (payload.isEmpty()) return

    val matrix = remember(payload) { QrCode.encode(payload) }
    val clipboard = LocalClipboardManager.current

    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = MaterialTheme.shapes.large, color = MaterialTheme.colorScheme.surface) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(10.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
            ) {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                )
                QrImage(
                    matrix = matrix,
                    contentDescription = title,
                    modifier = Modifier.size(260.dp),
                )
                Text(
                    text = group(payload),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                )
                Text(text = explain, style = MaterialTheme.typography.bodySmall)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { clipboard.setText(AnnotatedString(payload)) }) {
                        Text("复制")
                    }
                    TextButton(onClick = onDismiss) { Text("关闭") }
                }
            }
        }
    }
}

// ----------------------------------------------------------------------

/**
 * Describes where an outgoing message got to.
 *
 * "已送达服务器" rather than "已送达": the relay acknowledges receipt of the envelope,
 * and nothing more. It cannot acknowledge reading, because it cannot read. A tick that
 * implies the peer saw the message would be a claim this architecture cannot support.
 */
private fun statusSuffix(message: ChatMessage): String = when {
    !message.outgoing -> ""
    message.state == DeliveryState.SENDING -> " · 发送中"
    message.state == DeliveryState.SENT -> " · 已送达服务器"
    else -> " · 发送失败"
}

private fun timeOf(millis: Long): String =
    SimpleDateFormat("HH:mm", Locale.getDefault()).format(Date(millis))

/** Formats a hex identity in groups of four for reading aloud. */
private fun group(hex: String): String = hex.chunked(4).joinToString(" ")

/** Abbreviates a long hex string for display. */
private fun short(hex: String): String =
    if (hex.length <= 16) hex else hex.take(8) + "…" + hex.takeLast(8)
