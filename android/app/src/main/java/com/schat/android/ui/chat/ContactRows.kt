package com.schat.android.ui.chat

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
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
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.schat.android.core.contacts.Contact
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.ui.GradientAvatar
import com.schat.android.ui.ui.UnreadPill
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The conversation list.
 *
 * # What each row is allowed to imply
 *
 * A row shows a name, the last thing said, when, and how many messages are waiting. It
 * deliberately shows nothing that would suggest verification: a nickname is what *this*
 * user typed, and an avatar is a colour derived from the key — neither says anything about
 * who is on the other end. That is still the safety number's job, and the conversation
 * screen is where it lives.
 */
@Composable
fun ContactRows(
    contacts: List<Contact>,
    onOpen: (String) -> Unit,
    onRename: (String, String) -> Unit,
    onDelete: (String) -> Unit,
    /**
     * 只显示名字。
     *
     * 「聊天」页回答"最近谁找过我"，所以要有预览、时间和未读；「通讯录」页回答"我认识谁"，
     * 那些信息只会让两个页看起来一样。
     */
    compact: Boolean = false,
) {
    var renaming by remember { mutableStateOf<Contact?>(null) }
    var deleting by remember { mutableStateOf<Contact?>(null) }

    Column(modifier = Modifier.fillMaxWidth()) {
        contacts.forEach { contact ->
            ContactRow(
                contact = contact,
                compact = compact,
                onOpen = { onOpen(contact.identityHex) },
                onRename = { renaming = contact },
                onDelete = { deleting = contact },
            )
        }
    }

    renaming?.let { contact ->
        RenameContactDialog(
            contact = contact,
            onConfirm = { name ->
                onRename(contact.identityHex, name)
                renaming = null
            },
            onDismiss = { renaming = null },
        )
    }

    deleting?.let { contact ->
        DeleteContactDialog(
            contact = contact,
            onConfirm = {
                onDelete(contact.identityHex)
                deleting = null
            },
            onDismiss = { deleting = null },
        )
    }
}

/** One conversation. */
@Composable
private fun ContactRow(
    contact: Contact,
    compact: Boolean,
    onOpen: () -> Unit,
    onRename: () -> Unit,
    onDelete: () -> Unit,
) {
    var menuOpen by remember { mutableStateOf(false) }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(18.dp))
            .clickable(onClick = onOpen)
            .padding(horizontal = Dimens.Md, vertical = Dimens.Md),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
    ) {
        GradientAvatar(
            label = contact.displayName,
            hue = hueOf(contact.identityHex),
            size = if (compact) 40.dp else 44.dp,
        )

        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = contact.displayName,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                if (!compact) {
                    Text(
                        text = timeLabel(contact.lastMessageAtMillis),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            if (!compact) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = previewLine(contact),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f),
                    )
                    if (contact.unread > 0) UnreadPill(contact.unread)
                }
            } else if (!contact.isNamed) {
                // 通讯录里只补一行身份缩写：没有备注名时，光看"ac12abcd…"分不清是谁，
                // 而这一行至少能让用户去核对。
                Text(
                    text = contact.identityHex.take(16) + "…",
                    style = MaterialTheme.typography.labelSmall,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }

        Box {
            TextButton(onClick = { menuOpen = true }) { Text("⋮") }
            DropdownMenu(expanded = menuOpen, onDismissRequest = { menuOpen = false }) {
                DropdownMenuItem(
                    text = { Text("重命名") },
                    onClick = {
                        menuOpen = false
                        onRename()
                    },
                )
                DropdownMenuItem(
                    text = { Text("删除联系人与聊天记录") },
                    onClick = {
                        menuOpen = false
                        onDelete()
                    },
                )
            }
        }
    }
}

/**
 * 一个稳定的身份色相。
 *
 * 颜色由身份公钥派生，所以同一个人在本机永远是同一个颜色，重启和换设备都不变——
 * 但它是**装饰**，不是标识：两个联系人可能撞色，而且它不代表任何信任关系。
 * 真正的比对靠安全码，不靠这个颜色。
 */
private fun hueOf(identityHex: String): Float =
    identityHex.take(2).toIntOrNull(16)?.times(360f)?.div(256f) ?: 200f

/** The last message, or a note that there is not one yet. */
private fun previewLine(contact: Contact): String = when {
    contact.lastMessageAtMillis == 0L -> "还没有消息"
    contact.lastMessagePreview.isBlank() -> "（空消息）"
    contact.lastMessageWasOutgoing -> "我：${contact.lastMessagePreview}"
    else -> contact.lastMessagePreview
}

/** A short, local timestamp: the time today, the date otherwise. */
private fun timeLabel(millis: Long): String {
    if (millis <= 0L) return ""

    val age = System.currentTimeMillis() - millis
    val pattern = if (age in 0..86_400_000L) "HH:mm" else "MM-dd"
    return SimpleDateFormat(pattern, Locale.getDefault()).format(Date(millis))
}

/** Renames a contact. */
@Composable
private fun RenameContactDialog(
    contact: Contact,
    onConfirm: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf(contact.nickname) }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("给这个联系人起个名字") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("备注名") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                Text(
                    text = "名字只保存在这台设备上：不会发给对方，也不会发给服务器。" +
                        "对方无法给你改名，你也不能替对方取名。",
                    style = MaterialTheme.typography.bodySmall,
                )
                Text(
                    text = "留空则显示身份公钥的缩写。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(name) }) { Text("保存") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}

/** Confirms deleting a contact and everything stored under it. */
@Composable
private fun DeleteContactDialog(
    contact: Contact,
    onConfirm: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("删除 ${contact.displayName}？") },
        text = {
            Text(
                text = "这会同时删除本机保存的这段对话历史**以及会话密钥**，无法撤销。\n\n" +
                    "对方设备上的记录不受影响，但你们之后需要重新建立会话。" +
                    "如果只是想清掉未读角标，不需要删除。",
            )
        },
        confirmButton = { TextButton(onClick = onConfirm) { Text("删除") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("取消") } },
    )
}
