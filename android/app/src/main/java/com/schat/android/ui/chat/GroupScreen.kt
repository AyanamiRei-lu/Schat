package com.schat.android.ui.chat

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.schat.android.chat.ChatMessage
import com.schat.android.chat.ChatState
import com.schat.android.chat.DeliveryState
import com.schat.android.core.groups.GroupMessage
import com.schat.android.ui.theme.Dimens
import com.schat.android.ui.theme.SchatShapes
import com.schat.android.ui.ui.BarAction
import com.schat.android.ui.ui.ScreenBackground
import com.schat.android.ui.ui.ScreenHeader
import com.schat.android.ui.ui.SectionLabel

/**
 * 群会话界面。
 *
 * # 复用而不是重写
 *
 * [MetadataWarning]、[MessageList]、[Composer] 都来自单聊界面。复用它们的理由不是省代码：
 *
 * - **元数据警告必须在每一个会话里出现**，群聊同样暴露元数据——服务端能看到谁在何时向哪个
 *   信箱投递。只要有一处会话漏掉它，用户对隐私的判断就是错的；
 * - 时间格式、投递状态、长文本的处理必须与单聊一致，因为用户看到的是同一款应用。
 *
 * # 显示什么，不显示什么
 *
 * 这里显示的是**本机保存的**消息（已解密的明文）。群状态的快照**不经过这里**，
 * 也不该经过：它含该 epoch 的密钥，只应待在加密存储与协议层之间。
 *
 * 叶子下标刻意不显示给用户：它对用户没有意义，而"谁发的"应当由成员列表与备注名回答。
 */
@Composable
fun GroupScreen(
    groupName: String,
    messages: List<GroupMessage>,
    onSend: (String) -> Unit,
    /**
     * 把当前联系人加进这个群。
     *
     * 它触发的是两步：一条群提交（让已有的成员看到群变了），以及一封 Welcome（发给被加的人，
     * 因为它还不是成员、推不出群信箱）。两封都由控制器发出，界面只负责发起。
     */
    onAddMember: () -> Unit,

    /**
     * 回到会话界面。
     *
     * 在它存在之前，群会话界面是一条死胡同：openGroup 只被赋值、从不被清空，用户进来之后
     * 只能杀掉进程。返回不是装饰，它是这个界面能被使用的条件。
     */
    onBack: () -> Unit,

    /**
     * 群里现在的成员，已经解析成可以显示的名字（备注名，或认不出时的身份前缀）。
     *
     * 界面不解析群状态——谁在群里由协议核心回答，这里只负责显示。名字的顺序按叶子
     * 下标，所以刷新不会让它重排。
     */
    members: List<String>,
    modifier: Modifier = Modifier,
) {
    ScreenBackground {
        Column(modifier = modifier.fillMaxSize()) {
            // 常驻，不可关闭。
            MetadataWarning()

            ScreenHeader(
                title = groupName,
                subtitle = "共 ${members.size} 人",
                onBack = onBack,
                backLabel = "返回",
                actions = {
                    BarAction(text = "加人", onClick = onAddMember)
                },
            )

            // 群里是谁。
            //
            // 完整名单在这里逐行展开，而不是塞进标题里：一个十人的群，标题里只能容下
            // 三个名字，剩下的要靠"等七人"去猜。名单来自协议核心，界面不解析群状态。
            MemberStrip(members = members)

            MessageList(
                state = ChatState(messages = messages.mapIndexed { index, message -> message.toChatMessage(index) }),
                modifier = Modifier.weight(1f),
            )

            Composer(onSend = onSend)
        }
    }
}

/**
 * 成员名单：一行胶囊。
 *
 * 名单在标题下面展开，而不是塞进标题里——一个十人的群，标题里只能容下三个名字，
 * 剩下的要靠"等七人"去猜。人数多了就截断，并用「+N」说明还有多少；完整名单随时
 * 可以由协议核心重新问一次（见调用方）。
 */
@Composable
private fun MemberStrip(members: List<String>) {
    if (members.isEmpty()) return

    Column(
        modifier = Modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .padding(horizontal = Dimens.Lg, vertical = Dimens.Sm),
        verticalArrangement = Arrangement.spacedBy(Dimens.Xs),
    ) {
        SectionLabel("成员 ${members.size}")
        Row(
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(Dimens.Sm),
        ) {
            members.take(MEMBER_CHIP_LIMIT).forEach { name ->
                Text(
                    text = name,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .clip(SchatShapes.Pill)
                        .background(MaterialTheme.colorScheme.surfaceContainerLow)
                        .padding(horizontal = Dimens.Sm, vertical = 2.dp)
                        .widthIn(max = 96.dp),
                )
            }
            if (members.size > MEMBER_CHIP_LIMIT) {
                Text(
                    text = "+${members.size - MEMBER_CHIP_LIMIT}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        HorizontalDivider(thickness = 1.dp, color = MaterialTheme.colorScheme.outline)
    }
}

/**
 * 一次最多显示几个成员胶囊。
 *
 * 上限不是"排版好看"，而是不让一个五十人的群把消息区挤到屏幕外面：
 * 多出来的人数由「+N」说明，而完整名单随时可以由协议核心重新问一次。
 */
private const val MEMBER_CHIP_LIMIT = 6

/**
 * 把一条群消息映射成会话界面认识的消息。
 *
 * `state` 一律是 [DeliveryState.SENT]，因为存在本机历史里的消息只有两种来源：
 * 本机已发出的（中继已接受），或收到的。**"已送达对方"无法声称**——
 * 中继从不确认投递，它只转发。
 */
private fun GroupMessage.toChatMessage(index: Int): ChatMessage = ChatMessage(
    id = index.toLong(),
    outgoing = mine,
    text = text,
    atMillis = atMillis,
    state = DeliveryState.SENT,
)
