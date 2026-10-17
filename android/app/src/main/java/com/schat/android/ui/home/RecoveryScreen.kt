package com.schat.android.ui.home

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.unit.dp
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.theme.SchatShapes
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.GhostButton
import com.schat.android.ui.ui.GradientButton
import com.schat.android.ui.ui.MonoBlock
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel
import com.schat.android.ui.ui.isDarkNow

/**
 * 恢复码：查看、复制、导出备份、从备份恢复。
 *
 * # 这里真正能做什么
 *
 * 恢复码是**备份这把锁的钥匙**，不是身份本身的种子：身份密钥只在本机保险库里，24 个词
 * 单独还原不出它。所以换机流程是两件东西一起用——
 *
 * 1. 旧机「复制备份」，得到一段可放在任何地方的密文；
 * 2. 新机把这段密文粘进下面的框，再输入 24 个词，解回身份。
 *
 * 备份离开这 24 个词就是一堆密文，所以它可以放在聊天记录、备忘录、网盘里。
 */
@Composable
fun RecoveryScreen(
    recoveryCode: String,
    onCreateBackup: () -> String?,
    onRestore: (envelope: String, words: List<String>) -> Unit,
    restoreBusy: Boolean,
    restoreError: String?,
    onBack: () -> Unit,
) {
    val clipboard = LocalClipboardManager.current
    val dark = isDarkNow()

    var envelope by remember { mutableStateOf("") }
    var wordsText by remember { mutableStateOf("") }
    var note by remember { mutableStateOf<String?>(null) }
    var confirming by remember { mutableStateOf(false) }

    val words = remember(wordsText) {
        wordsText.split(Regex("\\s+")).map { it.trim() }.filter { it.isNotEmpty() }
    }

    val fieldColors = TextFieldDefaults.colors(
        focusedContainerColor = if (dark) SchatPalette.GrayBubbleDark else SchatPalette.GrayBubble,
        unfocusedContainerColor = if (dark) SchatPalette.GrayBubbleDark else SchatPalette.GrayBubble,
        focusedIndicatorColor = Color.Transparent,
        unfocusedIndicatorColor = Color.Transparent,
    )

    ScreenBackground {
        Column(modifier = Modifier.fillMaxSize()) {
            ScreenHeader(
                title = "恢复码",
                onBack = onBack,
                backLabel = "返回",
            )

            ContentColumn(vertical = Dimens.Lg, gap = Dimens.Lg) {
                SectionLabel("我的恢复码")
                if (recoveryCode.isBlank()) {
                    Text(
                        text = "本机资料里没有恢复码。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                } else {
                    MonoBlock(text = recoveryCode)
                    Text(
                        text = "抄在纸上，不要截图。它和备份一起才能换机恢复。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    GhostButton(
                        text = "复制恢复码",
                        onClick = { clipboard.setText(AnnotatedString(recoveryCode)) },
                        modifier = Modifier.fillMaxWidth(),
                    )
                }

                HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)

                SectionLabel("备份")
                Text(
                    text = "备份由恢复码加密，离开这 24 个词就是一堆密文，可以放在任何地方。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                GradientButton(
                    text = "复制备份",
                    onClick = {
                        val sealed = runCatching { onCreateBackup() }.getOrNull()
                        if (sealed.isNullOrBlank()) {
                            note = "备份生成失败"
                        } else {
                            clipboard.setText(AnnotatedString(sealed))
                            note = "备份已复制（${sealed.length} 字符）"
                        }
                    },
                    enabled = recoveryCode.isNotBlank(),
                )

                HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)

                SectionLabel("从备份恢复")
                Text(
                    text = "粘上备份文本，再输入 24 个词。恢复会用备份里的身份替换本机身份。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )

                TextField(
                    value = envelope,
                    onValueChange = {
                        envelope = it
                        note = null
                    },
                    placeholder = { Text("备份文本（SCHAT-BACKUP-1…）") },
                    minLines = 3,
                    maxLines = 6,
                    modifier = Modifier.fillMaxWidth(),
                    shape = SchatShapes.Medium,
                    colors = fieldColors,
                )

                TextField(
                    value = wordsText,
                    onValueChange = {
                        wordsText = it
                        note = null
                    },
                    placeholder = { Text("24 个单词，空格分隔") },
                    minLines = 2,
                    maxLines = 4,
                    modifier = Modifier.fillMaxWidth(),
                    shape = SchatShapes.Medium,
                    colors = fieldColors,
                )

                note?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }

                restoreError?.let {
                    Text(
                        text = it,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }

                GradientButton(
                    text = if (restoreBusy) "正在恢复…" else "从备份恢复",
                    onClick = { confirming = true },
                    enabled = !restoreBusy && envelope.isNotBlank() && words.size == 24,
                )

                Text(
                    text = "恢复到本机会清除本机现有的会话与聊天记录。备份里的身份在别的设备上依然有效。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }

    if (confirming) {
        AlertDialog(
            onDismissRequest = { confirming = false },
            title = { Text("用备份替换本机身份？") },
            text = {
                Text(
                    "本机现有的身份、联系人与聊天记录将被备份里的身份替换，且无法撤销。",
                    style = MaterialTheme.typography.bodySmall,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirming = false
                        onRestore(envelope, words)
                    },
                ) { Text("替换") }
            },
            dismissButton = {
                TextButton(onClick = { confirming = false }) { Text("取消") }
            },
        )
    }
}
