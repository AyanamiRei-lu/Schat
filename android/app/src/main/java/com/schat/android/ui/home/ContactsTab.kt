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
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.schat.android.core.contacts.Contact
import com.schat.android.ui.chat.ContactRows
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.ui.BarAction
import com.schat.android.ui.ui.ScreenHeader

/**
 * 「通讯录」页：好友列表。
 *
 * 它和「聊天」页用同一份名单，但只显示名字——QQ 的通讯录也是这个做法：会话页回答
 * "最近谁找过我"，通讯录回答"我认识谁"。多显示预览和未读数只会让两个页看起来一样。
 */
@Composable
fun ContactsTab(
    contacts: List<Contact>,
    onOpen: (String) -> Unit,
    onAdd: () -> Unit,
    onRename: (String, String) -> Unit,
    onDelete: (String) -> Unit,
) {
    Column(modifier = Modifier.fillMaxSize()) {
        ScreenHeader(
            title = "通讯录",
            subtitle = if (contacts.isEmpty()) null else "${contacts.size} 位联系人",
            actions = { BarAction(text = "＋", onClick = onAdd) },
        )

        if (contacts.isEmpty()) {
            EmptyState(
                text = "还没有联系人",
                action = "扫码或输入身份添加",
                onAction = onAdd,
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
                contacts = contacts,
                onOpen = onOpen,
                onRename = onRename,
                onDelete = onDelete,
                compact = true,
            )
            Spacer(modifier = Modifier.height(Dimens.Sm))
        }
    }
}
