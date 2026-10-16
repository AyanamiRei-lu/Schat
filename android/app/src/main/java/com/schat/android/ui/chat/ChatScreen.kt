package com.schat.android.ui.chat

import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
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
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.OnGradient
import com.schat.android.ui.theme.OnGradientDim
import com.schat.android.ui.theme.SchatGradients
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.theme.SchatShapes
import com.schat.android.ui.ui.BarAction
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.GhostButton
import com.schat.android.ui.ui.GradientButton
import com.schat.android.ui.ui.GradientCard
import com.schat.android.ui.ui.MonoBlock
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel
import com.schat.android.ui.ui.StatusPill
import com.schat.android.ui.ui.isDarkNow
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
    /**
     * 换屏动画的键：它变了就做一次淡入淡出。
     *
     * 取对端身份，所以"选联系人 → 会话"和"换一个联系人"都是一次转场，而**连接状态
     * 变化不会**——状态每分钟都在动，让它触发换屏动画会把界面变成闪烁的。
     */
    fadeKey: String = "",
) {
    // 扫码与"待建立会话的对端身份"都由这一层持有：扫码要整屏接管界面，
    // 而扫到的身份要能填进下面那个表单。
    var scanning by remember { mutableStateOf(false) }
    var peer by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }

    ScreenBackground {
        Column(modifier = Modifier.fillMaxSize()) {
            if (scanning) {
                // 扫码时整屏交给相机：半透明的相机预览后面压着表单比一次干净的切换更糟，
                // 而且这样"我的相机去哪了"看一眼屏幕就能回答。
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
                return@Column
            }

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

            if (state.peerIdentityHex.isEmpty()) {
                PeerPicker(
                    contacts = state.contacts,
                    peer = peer,
                    note = note,
                    onPeerChange = {
                        peer = it
                        note = null
                    },
                    onScan = { scanning = true },
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
    GradientCard(
        modifier = Modifier.padding(horizontal = Dimens.Lg, vertical = Dimens.Md),
        container = MaterialTheme.colorScheme.errorContainer,
        borderBrush = SchatGradients.alertBorder(),
        contentPadding = Dimens.Lg,
    ) {
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
        )
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
    val dark = isDarkNow()

    Column(modifier = Modifier.fillMaxWidth()) {
        // 渐变带只放"这是哪个会话、连上了没有、能做什么"。身份、安全码、二维码都在
        // 下面的正文里，用卡片承载——它们是要读和要核对的内容，不是导航。
        ScreenHeader(
            title = if (state.peerIdentityHex.isEmpty()) "SCHAT" else short(state.peerIdentityHex),
            subtitle = if (state.peerIdentityHex.isEmpty()) {
                "端到端加密 · 服务器只转发密文"
            } else {
                "安全码一致才说明对端真的是对方，请当面或经可信渠道比对。"
            },
            actions = {
                BarAction(text = "新建群", onClick = onCreateGroup)
                BarAction(text = "群组", onClick = onOpenGroups)
            },
            body = {
                StatusPill(
                    text = state.connection,
                    tone = if (state.error != null) SchatPalette.Red300 else SchatPalette.Sky400,
                )
            },
        )

        ContentColumn(vertical = Dimens.Lg, gap = Dimens.Md) {
            if (state.error != null) {
                GradientCard(
                    container = MaterialTheme.colorScheme.errorContainer,
                    borderBrush = SchatGradients.alertBorder(),
                    contentPadding = Dimens.Lg,
                ) {
                    Text(
                        text = state.error,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onErrorContainer,
                    )
                }
            }

            GradientCard(contentPadding = Dimens.Lg) {
                SectionLabel("我的身份")

                Text(
                    text = if (showFullIdentity) group(myIdentity) else short(myIdentity),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface,
                )

                Row(horizontalArrangement = Arrangement.spacedBy(Dimens.Sm)) {
                    TextButton(onClick = { showFullIdentity = !showFullIdentity }) {
                        Text(
                            text = if (showFullIdentity) "隐藏完整身份" else "显示完整身份",
                            style = MaterialTheme.typography.labelLarge,
                        )
                    }
                    if (state.peerIdentityHex.isNotEmpty()) {
                        // Without this the restored conversation would be a one-way door: the app
                        // reopens the last peer on launch, so there has to be a way back to the picker.
                        TextButton(onClick = onLeaveConversation) {
                            Text(text = "换一个联系人", style = MaterialTheme.typography.labelLarge)
                        }
                    }
                }

                // 二维码这两个动作属于"把我的身份或服务器信息交给另一台设备"，
                // 是一次性动作，所以和身份放在同一张卡片里。
                Row(horizontalArrangement = Arrangement.spacedBy(Dimens.Sm)) {
                    GhostButton(
                        text = "我的二维码",
                        onClick = { showQr = true },
                        modifier = Modifier.weight(1f),
                    )
                    GhostButton(
                        text = "服务器连接码",
                        onClick = { showServerQr = true },
                        enabled = serverUri.isNotEmpty(),
                        modifier = Modifier.weight(1f),
                    )
                }
            }

            if (state.safetyNumber.isNotEmpty()) {
                GradientCard(contentPadding = Dimens.Lg) {
                    SectionLabel("安全码", accent = SchatPalette.Sky400)
                    Text(
                        text = "请与对方当面或通过可信渠道逐组比对：",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    MonoBlock(text = state.safetyNumber)
                }
            }
        }
    }

    if (showQr) {
        SchatQrDialog(
            title = "我的身份二维码",
            payload = QrPayload.identity(myIdentity),
            explain = "让对方扫这个码，就不必手抄 64 位十六进制了。" +
                "注意：扫到的只是身份公钥，它不能证明对方是谁——建立会话后仍然必须比对安全码。",
            onDismiss = { showQr = false },
            dark = dark,
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
            dark = dark,
        )
    }
}

/**
 * Asks for the peer's identity before any session exists.
 *
 * 扫码状态由调用方持有（见 `ChatScreen`）：扫码时要整屏接管界面，那是一次"换屏"，
 * 而不是这个表单内部的一个开关——把它放在表单里会让相机预览被裁在表单下面。
 */
@Composable
private fun PeerPicker(
    contacts: List<Contact>,
    peer: String,
    note: String?,
    onPeerChange: (String) -> Unit,
    onScan: () -> Unit,
    onStartSession: (String) -> Unit,
    onOpenConversation: (String) -> Unit,
    onRenameContact: (String, String) -> Unit,
    onDeleteContact: (String) -> Unit,
) {
    val looksValid = peer.trim().length == 64 &&
        peer.trim().lowercase().all { it in "0123456789abcdef" }

    ContentColumn(gap = Dimens.BlockGap) {
        // The contact list is local: nothing here is registered with the relay, and the
        // relay cannot enumerate who exists on it. Adding a friend is therefore just
        // "remember this identity", with no handshake with the server at all.
        if (contacts.isNotEmpty()) {
            SectionLabel("会话（${contacts.size}）")
            ContactRows(
                contacts = contacts,
                onOpen = onOpenConversation,
                onRename = onRenameContact,
                onDelete = onDeleteContact,
            )
            Text(
                text = "这份名单只保存在本机保险库里，不会上传，服务器也无法列举。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        GradientCard(contentPadding = Dimens.Xl) {
            SectionLabel("开始一段会话")

            Text(
                text = "扫对方的二维码，或手动输入对方的身份公钥（64 位十六进制）。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            OutlinedTextField(
                value = peer,
                onValueChange = onPeerChange,
                label = { Text("对端身份公钥") },
                singleLine = true,
                isError = peer.isNotEmpty() && !looksValid,
                modifier = Modifier.fillMaxWidth(),
            )

            note?.let {
                Text(
                    text = it,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }

            // Scanning is offered first because typing is where the mistakes happen: one wrong
            // hex character produces exactly the same "no bundle published for that identity"
            // error as a peer that never published, so the typo is indistinguishable from the
            // symptom it mimics.
            GradientButton(
                text = "扫码读取身份",
                onClick = onScan,
            )

            if (peer.isNotBlank()) {
                Text(
                    text = "已填入身份公钥。也可以继续手动修改上面的输入框。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            GradientButton(
                text = "获取预密钥并建立会话",
                onClick = { onStartSession(peer.trim()) },
                enabled = looksValid,
            )

            Text(
                text = "注意：建立会话只证明对方持有对应的私钥，不排除服务器替换了预密钥。" +
                    "服务器在发布预密钥时不校验身份，所以建立会话后必须比对安全码。",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
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
                color = MaterialTheme.colorScheme.onSurfaceVariant,
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
        contentPadding = androidx.compose.foundation.layout.PaddingValues(
            horizontal = Dimens.Lg,
            vertical = Dimens.Md,
        ),
        verticalArrangement = Arrangement.spacedBy(Dimens.Sm),
    ) {
        items(state.messages, key = { it.id }) { message ->
            MessageBubble(message)
        }
    }
}

/**
 * One message.
 *
 * 新消息有一次入场动画：淡入 + 从下方 12dp 滑到位。它在**首次组合后**才触发，
 * 所以重进会话时整屏历史不会一起滑进来——那看起来像加载，不像消息到达。
 * 动画只动透明度与位移，不动尺寸，因此它不会引起整屏重排。
 */
@Composable
internal fun MessageBubble(message: ChatMessage) {
    var entered by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { entered = true }

    val slide by animateDpAsState(
        targetValue = if (entered) 0.dp else Dimens.Md,
        animationSpec = tween(240),
        label = "schat-bubble-slide",
    )
    val alpha by animateFloatAsState(
        targetValue = if (entered) 1f else 0f,
        animationSpec = tween(240),
        label = "schat-bubble-alpha",
    )
    val dark = isDarkNow()

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = slide),
        horizontalArrangement = if (message.outgoing) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth(0.85f)
                .shadow(2.dp, MaterialTheme.shapes.medium, clip = false)
                .clip(MaterialTheme.shapes.medium)
                .background(
                    if (message.outgoing) {
                        if (dark) SchatGradients.outgoingDark(alpha) else SchatGradients.outgoing(alpha)
                    } else {
                        Brush.linearGradient(
                            listOf(
                                MaterialTheme.colorScheme.surface.copy(alpha = alpha),
                                MaterialTheme.colorScheme.surfaceContainerLow.copy(alpha = alpha),
                            ),
                        )
                    },
                )
                .border(
                    BorderStroke(
                        1.dp,
                        if (message.outgoing) {
                            Color.Transparent
                        } else {
                            MaterialTheme.colorScheme.outlineVariant.copy(alpha = alpha)
                        },
                    ),
                    MaterialTheme.shapes.medium,
                )
                .padding(horizontal = Dimens.Md, vertical = Dimens.Md),
            verticalArrangement = Arrangement.spacedBy(Dimens.Xs),
        ) {
            Text(
                text = message.text,
                style = MaterialTheme.typography.bodyMedium,
                color = if (message.outgoing) OnGradient else MaterialTheme.colorScheme.onSurface,
            )
            Text(
                text = timeOf(message.atMillis) + statusSuffix(message),
                style = MaterialTheme.typography.labelSmall,
                color = when {
                    message.state == DeliveryState.FAILED -> MaterialTheme.colorScheme.error
                    message.outgoing -> OnGradientDim
                    else -> MaterialTheme.colorScheme.onSurfaceVariant
                },
            )
        }
    }
}

/** The composer. */
@Composable
internal fun Composer(onSend: (String) -> Unit) {
    var draft by remember { mutableStateOf("") }
    val dark = isDarkNow()

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = Dimens.Md, vertical = Dimens.Md),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
    ) {
        OutlinedTextField(
            value = draft,
            onValueChange = { draft = it },
            label = { Text("消息") },
            placeholder = { Text("输入内容，端到端加密后发送") },
            modifier = Modifier.weight(1f),
            maxLines = 4,
        )

        val interaction = remember { MutableInteractionSource() }
        // 接收者写法，而不是 collectIsPressedAsState(interaction)：后者在这个文件里
        // 被编译器判为接收者类型不匹配（同一个调用在 ui/ui/Components.kt 里没有报错）。
        // 两处保持同一种写法，就不会再出现这种"只在一个文件里报错"的情况。
        val pressed by interaction.collectIsPressedAsState()
        val lift by animateDpAsState(
            targetValue = if (pressed) 1.dp else 5.dp,
            animationSpec = spring(),
            label = "schat-send-lift",
        )
        val enabled = draft.isNotBlank()

        Box(
            modifier = Modifier
                .size(54.dp)
                .shadow(lift, SchatShapes.Pill, clip = false)
                .clip(SchatShapes.Pill)
                .background(
                    when {
                        !enabled && dark -> SchatGradients.disabledDark()
                        !enabled -> SchatGradients.disabled()
                        dark -> SchatGradients.brandDark()
                        else -> SchatGradients.brand()
                    },
                )
                .clickable(
                    interactionSource = interaction,
                    indication = null,
                    enabled = enabled,
                ) {
                    onSend(draft)
                    draft = ""
                },
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = "↑",
                style = MaterialTheme.typography.titleLarge,
                color = OnGradient,
                fontWeight = FontWeight.Bold,
            )
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
    dark: Boolean = isDarkNow(),
) {
    if (payload.isEmpty()) return

    val matrix = remember(payload) { QrCode.encode(payload) }
    val clipboard = LocalClipboardManager.current

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surface,
            modifier = Modifier.border(
                BorderStroke(
                    1.dp,
                    if (dark) {
                        SchatGradients.cardBorderDark(MaterialTheme.colorScheme.outlineVariant)
                    } else {
                        SchatGradients.cardBorder(MaterialTheme.colorScheme.outlineVariant)
                    },
                ),
                MaterialTheme.shapes.large,
            ),
        ) {
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
                    shape = MaterialTheme.shapes.medium,
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

                MonoBlock(text = group(payload), container = MaterialTheme.colorScheme.surfaceContainerLow)

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
