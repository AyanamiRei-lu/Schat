package com.schat.android.ui.home

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.schat.android.chat.ChatState
import com.schat.android.ui.ui.HomeBottomBar
import com.schat.android.ui.ui.HomeTab
import com.schat.android.ui.ui.ScreenBackground

/**
 * 主界面：底边栏 + 三个页。
 *
 * 内容区在上、底边栏在下，用 `Column` 而不是"内容铺满 + 底栏浮在上面"：后者一定会让
 * 最后一个列表项被挡住，然后每个页面都要各自补一段底部留白——补漏一处就少看一行。
 */
@Composable
fun HomeScreen(
    tab: HomeTab,
    onTab: (HomeTab) -> Unit,
    state: ChatState,
    myIdentity: String,
    serverUri: String,
    serverDisplay: String,
    onOpenConversation: (String) -> Unit,
    onAddContact: () -> Unit,
    onNewGroup: () -> Unit,
    onOpenGroups: () -> Unit,
    onRenameContact: (String, String) -> Unit,
    onDeleteContact: (String) -> Unit,
    onOpenRecovery: () -> Unit,
) {
    val unread = state.contacts.sumOf { it.unread }

    ScreenBackground {
        Column(modifier = Modifier.fillMaxSize()) {
            Box(modifier = Modifier.weight(1f)) {
                when (tab) {
                    HomeTab.Chats -> ChatsTab(
                        state = state,
                        onOpenConversation = onOpenConversation,
                        onNewGroup = onNewGroup,
                        onOpenGroups = onOpenGroups,
                        onAddContact = onAddContact,
                        onRenameContact = onRenameContact,
                        onDeleteContact = onDeleteContact,
                    )

                    HomeTab.Contacts -> ContactsTab(
                        contacts = state.contacts,
                        onOpen = onOpenConversation,
                        onAdd = onAddContact,
                        onRename = onRenameContact,
                        onDelete = onDeleteContact,
                    )

                    HomeTab.Mine -> MineTab(
                        myIdentity = myIdentity,
                        serverDisplay = serverDisplay,
                        serverUri = serverUri,
                        onOpenRecovery = onOpenRecovery,
                    )
                }
            }

            HomeBottomBar(current = tab, unread = unread, onSelect = onTab)
        }
    }
}
