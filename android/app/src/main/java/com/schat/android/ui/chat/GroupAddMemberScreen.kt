package com.schat.android.ui.chat

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.OnGradient
import com.schat.android.ui.theme.SchatPalette
import com.schat.android.ui.ui.ContentColumn
import com.schat.android.ui.ui.GradientCard
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel

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
    ScreenBackground {
        Column(modifier = modifier.fillMaxSize()) {
            // 与所有会话界面一致：这条警告常驻且不可关闭。
            MetadataWarning()

            ScreenHeader(
                title = "加人进群",
                onBack = onBack,
                backLabel = "返回",
            )

            ContentColumn(vertical = Dimens.Lg, gap = Dimens.Md) {
                if (candidates.isEmpty()) {
                    // 两种空都落在这里：还没有任何联系人，或联系人都已经在群里。
                    GradientCard {
                        SectionLabel("没有可以加入的联系人")
                        Text(
                            text = "群里的成员已经都在这里了；要加新人，先在会话界面与对方建立会话。",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    return@ContentColumn
                }

                candidates.forEach { candidate ->
                    GradientCard(
                        onClick = { onPick(candidate.identityHex) },
                        contentPadding = Dimens.Lg,
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(Dimens.Md),
                        ) {
                            // 渐变小方块里放候选人的身份前缀首字母：它不表示身份，
                            // 只让人在一列里能快速区分行。
                            Box(
                                modifier = Modifier
                                    .size(34.dp)
                                    .clip(RoundedCornerShape(percent = 32))
                                    .background(MaterialTheme.colorScheme.primary),
                                contentAlignment = Alignment.Center,
                            ) {
                                Text(
                                    text = candidate.displayName.take(1).uppercase(),
                                    style = MaterialTheme.typography.labelLarge,
                                    color = OnGradient,
                                    fontWeight = FontWeight.Bold,
                                )
                            }

                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = candidate.displayName,
                                    style = MaterialTheme.typography.titleSmall,
                                    fontWeight = FontWeight.SemiBold,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis,
                                )
                                Text(
                                    text = candidate.identityHex.take(16) + "…",
                                    style = MaterialTheme.typography.labelSmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }

                            Text(
                                text = "加入 ›",
                                style = MaterialTheme.typography.labelLarge,
                                color = SchatPalette.Blue500,
                            )
                        }
                    }
                }
            }
        }
    }
}
