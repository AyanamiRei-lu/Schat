package com.schat.android.ui.chat

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.GradientCard
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel

/**
 * 群列表里的一行。
 *
 * [memberCount] 与 [epoch] 来自 Go 侧对快照的解读，不是界面自己数出来的：界面不解析
 * 群状态（那是协议核心的职责），它只显示核心报出来的事实。
 */
data class GroupListItem(
    /** 群标识，十六进制。 */
    val groupIdHex: String,

    /** 群里的成员数。 */
    val memberCount: Long,

    /** 当前 epoch。 */
    val epoch: Long,
)

/**
 * 本机保存的群。
 *
 * # 为什么需要这个界面
 *
 * 在它存在之前，会话界面的「群组」按钮只会打开**第一个**已保存的群，而群会话界面没有返回
 * 的路——两件事合起来让用户一旦进入群界面就只能杀掉进程。列表把"哪个群"和"怎么回去"变成
 * 了两个可以点的东西。
 *
 * # 为什么名字是标识前缀
 *
 * 群名（用户起的名字）是下一步；在这一步，显示标识的前 8 位至少**不会说谎**：它确实是这个群，
 * 而且两个不同的群看起来一定不同。显示一个编造的名字会比显示标识更糟。
 */
@Composable
fun GroupListScreen(
    groups: List<GroupListItem>,
    onOpen: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    ScreenBackground {
        Column(modifier = modifier.fillMaxSize()) {
            // 与群会话界面一致：这条警告常驻且不可关闭。
            MetadataWarning()

            ScreenHeader(
                title = "群组",
                subtitle = "本机保存了 ${groups.size} 个群；群名与成员由协议核心回答。",
                onBack = onBack,
                backLabel = "返回",
            )

            ContentColumn(vertical = Dimens.Lg, gap = Dimens.Md) {
                if (groups.isEmpty()) {
                    GradientCard {
                        SectionLabel("还没有群")
                        Text(
                            text = "在会话界面点「新建群」可以建一个。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    return@ContentColumn
                }

                // 群的数量是个位数，用 Column 逐行列出，不引入惰性列表。
                groups.forEach { group ->
                    GradientCard(onClick = { onOpen(group.groupIdHex) }) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            Text(
                                text = group.groupIdHex.take(8) + "…",
                                style = MaterialTheme.typography.bodyLarge,
                                fontFamily = FontFamily.Monospace,
                                fontWeight = FontWeight.SemiBold,
                            )
                            val readable = group.memberCount >= 0
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
                            ) {
                                Text(
                                    // 成员数与 epoch 都是核心报出来的事实，界面只负责显示。
                                    // 负数表示核心读不懂这份快照——那种情况下说"状态不可用"，而不是显示一个
                                    // 看起来像真的"0 人"。
                                    text = if (readable) {
                                        "${group.memberCount} 人 · epoch ${group.epoch}"
                                    } else {
                                        "状态不可用"
                                    },
                                    style = MaterialTheme.typography.labelSmall,
                                    color = if (readable) {
                                        MaterialTheme.colorScheme.onSurfaceVariant
                                    } else {
                                        MaterialTheme.colorScheme.error
                                    },
                                )
                                if (readable) {
                                    Text(
                                        text = "›",
                                        style = MaterialTheme.typography.titleMedium,
                                        color = SchatPalette.Blue500,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
