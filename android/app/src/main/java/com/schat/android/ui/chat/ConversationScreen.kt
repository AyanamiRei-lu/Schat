package com.schat.android.ui.chat

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import com.schat.android.chat.ChatMessage
import com.schat.android.chat.ChatState
import com.schat.android.chat.DeliveryState
import com.schat.android.core.contacts.abbreviate
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.OnGradient
import com.schat.android.ui.theme.OnGradientDim
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.theme.SchatShapes
import com.schat.android.ui.ui.BarAction
import com.schat.android.ui.ui.GhostButton
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
 * 单聊窗口。
 *
 * 它是全屏的、没有底边栏：底边栏是「在哪一页」的指示，进到一段会话里之后，
 * 用户只关心这段对话，返回就是回列表。
 *
 * # 为什么安全码不直接显示在正文里
 *
 * 那串 60 位数字只在"要当面比对"的时候才有用，平时它只是占掉两行。所以它被移到「详情」
 * 里，标题栏留一个入口——需要核对的人点得开，不需要的人不受打扰。
 */
@Composable
fun ConversationScreen(
    state: ChatState,
    onSend: (String) -> Unit,
    onBack: () -> Unit,
) {
    var showDetail by remember { mutableStateOf(false) }
    val peer = state.peerIdentityHex
    val contactName = state.contacts
        .firstOrNull { it.identityHex.equals(peer, ignoreCase = true) }
        ?.displayName
        ?: abbreviate(peer)

    ScreenBackground {
        Column(modifier = Modifier.fillMaxSize()) {
            ScreenHeader(
                title = contactName,
                onBack = onBack,
                backLabel = "返回",
                actions = { BarAction(text = "详情", onClick = { showDetail = true }) },
                body = { StatusPill(text = state.connection) },
            )

            if (state.mailboxIsDerivedFromIdentity) {
                MetadataWarning()
            }

            state.error?.let { message ->
                Text(
                    text = message,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.errorContainer)
                        .padding(horizontal = Dimens.Lg, vertical = Dimens.Sm),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onErrorContainer,
                )
            }

            MessageList(state = state, modifier = Modifier.weight(1f))
            Composer(onSend = onSend)
        }
    }

    if (showDetail) {
        ConversationDetailDialog(
            peer = peer,
            safetyNumber = state.safetyNumber,
            onDismiss = { showDetail = false },
        )
    }
}

/**
 * 会话详情：对端身份与安全码。
 *
 * 措辞只说一件事——安全码一致才说明对端真的是对方，而且要比对得当面或经可信渠道。
 * 二维码扫到的只是公钥，它证明不了持有者是谁。
 */
@Composable
private fun ConversationDetailDialog(
    peer: String,
    safetyNumber: String,
    onDismiss: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Surface(shape = SchatShapes.Large, color = MaterialTheme.colorScheme.surface) {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()).padding(Dimens.Xl),
                verticalArrangement = Arrangement.spacedBy(Dimens.Md),
            ) {
                SectionLabel("对端身份")
                MonoBlock(text = groupInFours(peer))

                if (safetyNumber.isNotEmpty()) {
                    SectionLabel("安全码")
                    MonoBlock(text = safetyNumber)
                }

                Text(
                    text = "安全码一致，才说明对端真的是对方。请当面或经可信渠道逐组比对。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                GhostButton(
                    text = "关闭",
                    onClick = onDismiss,
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        }
    }
}

/**
 * The standing warning about this build's metadata protection.
 *
 * # 它是常驻的，所以要小
 *
 * 它是一句**常驻**提示，不是一次必须被处理的错误。常驻的东西越大，越会被人当成背景
 * 噪声，那正好与它存在的理由相反。所以它是一条窄带：3dp 红竖线 + 一行 bodySmall。
 * 措辞一个字没删——信息量不靠字号。
 *
 * Worded to say exactly what leaks and what does not. "Metadata is not protected" alone
 * would be read as "messages can be read", which is false and would push users toward a
 * worse decision than the truth does.
 */
@Composable
internal fun MetadataWarning() {
    val dark = isDarkNow()

    Column(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(if (dark) SchatPalette.AlertFillDark else SchatPalette.AlertFillLight)
                .padding(horizontal = Dimens.Lg, vertical = Dimens.Sm),
            horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
        ) {
            // 一条竖线，而不是整块红底：它标出"从这里开始是警告"，但不会把整行变成红色。
            Box(
                modifier = Modifier
                    .padding(top = 1.dp)
                    .width(3.dp)
                    .heightIn(min = 30.dp)
                    .clip(SchatShapes.Pill)
                    .background(SchatPalette.Red500),
            )
            Text(
                text = "元数据保护未启用：信箱地址由身份公钥派生，知道你公钥的人能观察到" +
                    "你何时收发消息。消息内容仍是端到端加密的，服务器与旁观者读不到。" +
                    "会话内令牌交换实现后会替换掉这一机制。",
                style = MaterialTheme.typography.bodySmall,
                color = if (dark) SchatPalette.ParchmentDim else SchatPalette.Gray600,
            )
        }
        HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)
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
        contentPadding = PaddingValues(horizontal = Dimens.Lg, vertical = Dimens.Md),
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
 * 气泡是实心的：自己发的蓝底白字，收到的浅灰底深字，和 QQ 完全一致。
 * 新消息有一次淡入，在**首次组合后**才触发，所以重进会话时整屏历史不会一起闪一下。
 */
@Composable
internal fun MessageBubble(message: ChatMessage) {
    var entered by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { entered = true }

    val appear by animateFloatAsState(
        targetValue = if (entered) 1f else 0f,
        animationSpec = tween(160),
        label = "schat-bubble-appear",
    )
    val dark = isDarkNow()

    val fill = when {
        message.outgoing -> SchatPalette.Blue500
        dark -> SchatPalette.GrayBubbleDark
        else -> SchatPalette.GrayBubble
    }

    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = if (message.outgoing) Arrangement.End else Arrangement.Start,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth(0.82f)
                .clip(SchatShapes.Medium)
                .background(fill.copy(alpha = appear))
                .padding(horizontal = Dimens.Md, vertical = Dimens.Sm),
            verticalArrangement = Arrangement.spacedBy(2.dp),
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
                    message.state == DeliveryState.FAILED -> SchatPalette.Red500
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
    val enabled = draft.isNotBlank()

    Column(modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface)) {
        // 一条细分割线，把输入区和消息区分开。QQ 与 X 都是这样，不需要阴影。
        HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Dimens.Md, vertical = Dimens.Sm),
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
        ) {
            TextField(
                value = draft,
                onValueChange = { draft = it },
                placeholder = { Text("输入消息") },
                modifier = Modifier.weight(1f),
                maxLines = 4,
                shape = SchatShapes.Medium,
                colors = TextFieldDefaults.colors(
                    focusedContainerColor = if (dark) SchatPalette.GrayBubbleDark else SchatPalette.GrayBubble,
                    unfocusedContainerColor = if (dark) SchatPalette.GrayBubbleDark else SchatPalette.GrayBubble,
                    focusedIndicatorColor = Color.Transparent,
                    unfocusedIndicatorColor = Color.Transparent,
                    disabledIndicatorColor = Color.Transparent,
                ),
            )

            val interaction = remember { MutableInteractionSource() }
            val pressed by interaction.collectIsPressedAsState()
            val fill = when {
                !enabled && dark -> SchatPalette.BlackFill
                !enabled -> SchatPalette.GrayBubble
                pressed -> SchatPalette.Blue600
                dark -> SchatPalette.Blue400
                else -> SchatPalette.Blue500
            }

            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(fill)
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
                    style = MaterialTheme.typography.titleMedium,
                    color = if (enabled) OnGradient else MaterialTheme.colorScheme.onSurfaceVariant,
                )
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

/** Formats a long hex string in groups of four for reading aloud. */
private fun groupInFours(value: String): String = value.chunked(4).joinToString(" ")
