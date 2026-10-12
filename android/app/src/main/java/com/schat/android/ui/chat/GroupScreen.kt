package com.schat.android.ui.chat

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.ui.Alignment
import androidx.compose.material3.TextButton
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.unit.dp
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import com.schat.android.chat.ChatMessage
import com.schat.android.chat.ChatState
import com.schat.android.chat.DeliveryState
import com.schat.android.core.groups.GroupMessage

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
    Column(modifier = modifier.fillMaxSize()) {
        // 常驻，不可关闭。
        MetadataWarning()

        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            TextButton(onClick = onBack) {
                Text("返回")
            }
            Text(text = groupName, modifier = Modifier.weight(1f))
            TextButton(onClick = onAddMember) {
                Text("加人")
            }
        }

        // 群里是谁。
        //
        // 群名不是用户起的，而是由成员拼出来的（见调用方）：对用户来说"我、张三"比
        // "群 1"或一串标识更有信息量，而它不会说谎——名单就是群状态里的名单。
        Text(
            text = members.joinToString("、"),
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 4.dp),
        )

        MessageList(
            state = ChatState(messages = messages.mapIndexed { index, message -> message.toChatMessage(index) }),
            modifier = Modifier.weight(1f),
        )

        Composer(onSend = onSend)
    }
}

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
