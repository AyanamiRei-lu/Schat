package com.schat.android.ui.chat

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * 选一个人加进群。
 *
 * [identityHex] 是候选人的身份，也是加人时唯一需要的东西——**名字只用于显示**。群里的成员
 * 身份由签名密钥决定，与本机的备注名无关：换了备注名不会换人，两个同名的联系人也不会被
 * 搞混。
 */
data class GroupAddCandidate(
    /** 候选人的身份公钥，十六进制。 */
    val identityHex: String,

    /** 显示名：备注名，或没有备注时的身份缩写。 */
    val displayName: String,
)

/**
 * 从联系人里挑一个加入群。
 *
 * # 为什么是独立的一屏，而不是一个弹窗
 *
 * 与群列表同样的做法：界面层次由一处状态决定（选人 → 群列表 → 群 → 单聊），返回就是把这个
 * 状态清掉。弹窗会引入另一套返回语义，而这一层已经有一个能用的了。
 *
 * # 为什么已经在群里的人不出现在这里
 *
 * 过滤在调用方完成。列出一个已经加入的人，会让用户点一个必然失败的动作——而"点不动的人"
 * 比"不出现的人"更让人困惑。
 */
@Composable
fun GroupAddMemberScreen(
    candidates: List<GroupAddCandidate>,
    onPick: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxSize()) {
        // 与所有会话界面一致：这条警告常驻且不可关闭。
        MetadataWarning()

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) { Text("返回") }
            Text(text = "加人进群", modifier = Modifier.weight(1f))
        }

        if (candidates.isEmpty()) {
            // 两种空都落在这里：还没有任何联系人，或联系人都已经在群里。
            Text(
                text = "没有可以加入的联系人。\n" +
                    "群里的成员已经都在这里了；要加新人，先在会话界面与对方建立会话。",
                modifier = Modifier.padding(24.dp),
            )
            return@Column
        }

        candidates.forEach { candidate ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { onPick(candidate.identityHex) }
                    .padding(horizontal = 16.dp, vertical = 12.dp),
            ) {
                Text(text = candidate.displayName)
            }
        }
    }
}
