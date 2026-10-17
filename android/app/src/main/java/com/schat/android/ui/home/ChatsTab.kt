package com.schat.android.ui.home

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.schat.android.chat.ChatState
import com.schat.android.ui.chat.ContactRows
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.ui.BarAction
import com.schat.android.ui.ui.GhostButton
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.StatusPill

/**
 * 「聊天」页：会话列表。
 *
 * 顶栏只有两件事：这是聊天页，以及现在连没连上。群的两个动作放在右上角——它们不是
 * 常态操作，但需要的时候一眼能找到。
 */
@Composable
fun ChatsTab(
    state: ChatState,
    onOpenConversation: (String) -> Unit,
    onNewGroup: () -> Unit,
    onOpenGroups: () -> Unit,
    onAddContact: () -> Unit,
    onRenameContact: (String, String) -> Unit,
    onDeleteContact: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        ScreenHeader(
            title = "聊天",
            actions = {
                BarAction(text = "新建群", onClick = onNewGroup)
                BarAction(text = "群组", onClick = onOpenGroups)
            },
            body = { StatusPill(text = state.connection, tone = connectionTone(state)) },
        )

        state.error?.let { message ->
            Text(
                text = message,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Dimens.Lg, vertical = Dimens.Sm),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
            HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)
        }

        if (state.contacts.isEmpty()) {
            EmptyState(
                text = "还没有会话",
                action = "去通讯录添加联系人",
                onAction = onAddContact,
            )
            return@Column
        }

        Column(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f)
                .verticalScroll(rememberScrollState())
                .padding(vertical = Dimens.Sm),
            verticalArrangement = Arrangement.spacedBy(Dimens.Xs),
        ) {
            ContactRows(
                contacts = state.contacts,
                onOpen = onOpenConversation,
                onRename = onRenameContact,
                onDelete = onDeleteContact,
            )
            Spacer(modifier = Modifier.height(Dimens.Sm))
        }
    }
}

/** 一屏空的时候说什么：一句事实 + 一个能走下去的动作。 */
@Composable
internal fun EmptyState(text: String, action: String, onAction: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(Dimens.Xxl),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )
        Spacer(modifier = Modifier.height(Dimens.Lg))
        GhostButton(text = action, onClick = onAction)
    }
}

/**
 * 连接状态的颜色。
 *
 * 绿=还在正常工作，灰=正在做某件事（连接中、发布中），红=出错了。
 * 一个点的颜色就是这一行的全部信息量。
 */
@Composable
internal fun connectionTone(state: ChatState): Color = when {
    state.error != null -> SchatPalette.Red500
    state.connection.contains("断开") ||
        state.connection.contains("失败") ||
        state.connection.contains("不可用") -> SchatPalette.Red500
    state.connection.contains("…") -> SchatPalette.Gray500
    else -> SchatPalette.GreenOK
}
