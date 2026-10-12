package com.schat.android.chat

import mobile.Mobile

/**
 * 群组功能的 Kotlin 门面。
 *
 * ## 这一层只做搬运
 *
 * 建群、加人、入群、收发全部在 Go 侧完成，并且**各自都有端到端测试**：
 * 建群 → 加人 → 用 Welcome 入群 → 双方 epoch 一致，以及消息往返还原、外人读不到。
 * 这里不重新实现任何逻辑——**任何在这里"顺手补一下"的判断都会成为第二处事实来源**，
 * 而这一路上已经有八次教训（见 docs/MLS-M4-HANDOFF.md 第 9 节）。
 *
 * ## 没有做、也不该在这里做的事
 *
 * - **不解析群状态**：状态是一个含 epoch 密钥的 JSON 快照，必须**原样**存进加密保险库。
 *   要显示信息用 [summary]，它只返回可展示的字段。
 * - **不保存棘轮代数**：代数由调用方随群状态一起保存，[seal] 传入并返回它
 *   （§9.2 要求同一代不得重用，而这个值不在快照里）。
 * - **不做填充**：填充在 Go 侧完成，因为最小长度由套件的哈希与 AEAD 长度决定。
 */
object GroupController {

    /** 建群。返回群状态快照，必须存进保险库。 */
    fun createGroup(identityJson: String, groupIdHex: String): String =
        Mobile.groupCreate(identityJson, groupIdHex)

    /**
     * 生成一对 KeyPackage。
     *
     * [Published.packageHex] 发布到预密钥目录，**任何人都能读**；
     * [Published.initKeyPrivateHex] 必须存进保险库——**它是日后解开 Welcome 的唯一凭据**，
     * 丢了就永远入不了群，而症状会表现为"对方发的 Welcome 有问题"。
     */
    /**
     * What [keyPackage] produced, and all three values must be KEPT.
     *
     * initKeyPrivateHex opens the Welcome. leafKeyPrivateHex is the key of the leaf the
     * KeyPackage publishes, and the joiner needs it to decrypt the path secret addressed to it —
     * without it a member can join and then follow nothing. A record that has the first two and
     * not the third is a member that will silently fall behind.
     */
    data class Published(
        val packageHex: String,
        val initKeyPrivateHex: String,
        val leafKeyPrivateHex: String,
    )

    fun keyPackage(identityJson: String): Published {
        val result = Mobile.groupKeyPackage(identityJson)
        return Published(result.keyPackageHex, result.initKeyPrivateHex, result.leafKeyPrivateHex)
    }

    data class AddResult(val stateJson: String, val commitHex: String, val welcomeHex: String)

    /**
     * 把某人加进群。
     *
     * 返回三样东西，**缺一不可**：
     * - [AddResult.stateJson]：自己的新状态，存进保险库；
     * - [AddResult.commitHex]：广播给**已在群里**的成员，否则他们不会知道这次变更；
     * - [AddResult.welcomeHex]：单独发给新成员，它只能靠这个入群。
     */
    fun addMember(stateJson: String, identityJson: String, keyPackageHex: String): AddResult {
        val result = Mobile.groupAddMember(stateJson, identityJson, keyPackageHex)
        return AddResult(result.stateJSON, result.commitHex, result.welcomeHex)
    }

    /** 用收到的 Welcome 入群。initKeyPrivateHex 来自 [keyPackage]。 */
    /**
     * Joins a group from a Welcome.
     *
     * The leaf key is not optional bookkeeping: the joiner decrypts the path secret addressed to
     * it with that key. The INDEX is no longer a parameter — AcceptWelcome derives it from that
     * key, because a caller cannot know it and a wrong one makes the member decrypt a secret
     * meant for somebody else. Both the key and the index come from [keyPackage]; the key must be
     * kept, the index is then found.
     */
    fun processWelcome(
        welcomeHex: String,
        initKeyPrivateHex: String,
        leafKeyPrivateHex: String,
    ): String =
        Mobile.groupProcessWelcome(welcomeHex, initKeyPrivateHex, leafKeyPrivateHex)

    data class Sealed(val messageHex: String, val nextGeneration: Long)

    // gomobile maps Go int AND int64 to Kotlin Long (Go ints are 64-bit); only int32 becomes Int.
    // Every integer this façade exchanges with the binding is therefore Long.

    /**
     * 加密一条群消息。
     *
     * [generation] 必须是随状态保存的那个值（Long，与生成的绑定一致）；返回值里的 [Sealed.nextGeneration] 是下一次要传的。
     * 传错不会报错——只会让接收方全部解不开。
     */
    fun seal(stateJson: String, identityJson: String, plaintextHex: String, generation: Long): Sealed {
        val result = Mobile.groupSeal(stateJson, identityJson, plaintextHex, generation)
        return Sealed(result.messageHex, result.nextGeneration)
    }

    data class Opened(val plaintextHex: String, val senderLeaf: Long, val generation: Long)

    /**
     * 群里的一位成员。
     *
     * [leaf] 是它在**这个 epoch** 的树里的位置——成员变化会改变别人的叶子下标，所以它不是
     * 一个人的稳定标识，[identityHex] 才是。
     */
    data class GroupMemberItem(val leaf: Long, val identityHex: String)

    /** 解密一条群消息。失败意味着：不是这个 epoch 的、不是这个群的，或被人改过。 */
    fun open(stateJson: String, messageHex: String): Opened {
        val result = Mobile.groupOpen(stateJson, messageHex)
        return Opened(result.plaintextHex, result.senderLeaf, result.generation)
    }

    /** 供界面显示的摘要。**不含任何密钥。** */
    fun summary(stateJson: String): mobile.GroupSummary = Mobile.groupStateSummary(stateJson)

    /**
     * 群里当前的成员。
     *
     * 界面**不解析群状态**——那是协议核心的职责——所以"谁在群里"必须由核心回答，这里只把它的
     * JSON 变成界面认识的东西。
     *
     * 身份是十六进制字符串，与本机联系人的身份可以直接比对：认得出的成员用备注名，认不出的
     * 显示身份前缀。**不显示"未知"**——一个陌生的身份是一个事实，而"未知"不是。
     */
    fun members(stateJson: String): List<GroupMemberItem> {
        val array = org.json.JSONArray(Mobile.groupMembersJSON(stateJson))
        return (0 until array.length()).map { index ->
            val item = array.getJSONObject(index)
            GroupMemberItem(
                leaf = item.getLong("leaf"),
                identityHex = item.getString("identity"),
            )
        }
    }

    /**
     * 只读一条群消息的公开头部：它属于哪个群、哪个 epoch。
     *
     * **不做任何解密，也不认证任何东西。** 群 ID 与 epoch 在密文之外，因为接收方必须先知道
     * 该用哪份群状态才谈得上解密——没有任何方案能"先解密，再看该用哪把钥匙"。
     * 头部被篡改时，解密会失败（它绑定在内容密文的 AAD 里），而读取头部仍会成功：
     * 这个区分让客户端能分清"不是我的群"与"被人改过"。
     */
    fun header(messageHex: String): mobile.GroupMessageHeaderResult = Mobile.groupMessageHeader(messageHex)

    /** 把群消息装进中继信封（内容类型 0x03）。 */
    fun wrap(tokenHex: String, message: ByteArray): ByteArray = Mobile.wrapGroup(tokenHex, message)

    /** 从中继信封取出群消息；不是 0x03 会抛出异常，而不是把载荷交出去。 */
    fun unwrap(wire: ByteArray): ByteArray = Mobile.unwrapGroup(wire)

    /**
     * The leaf THIS identity occupies in the group.
     *
     * Needed before a commit can be applied, and it must be the value the tree reports rather
     * than one the caller assumes: every binding function that processes a commit takes it, and
     * every one of them is wrong if it is wrong.
     */
    fun myLeaf(stateJson: String, identityJson: String): Long =
        Mobile.groupMyLeaf(stateJson, identityJson)

    /**
     * Applies a commit another member made, returning the new state.
     *
     * A commit is not a message: it replaces the epoch. It travels to the group's mailboxes,
     * because only members can apply it and the members are exactly those who can derive them.
     */
    fun processCommit(stateJson: String, commitHex: String, myLeaf: Long): String =
        Mobile.groupProcessCommit(stateJson, commitHex, myLeaf)

    /** Puts a commit into a relay envelope for one of the group's mailboxes. */
    fun wrapCommit(tokenHex: String, commit: ByteArray): ByteArray =
        Mobile.wrapGroupCommit(tokenHex, commit)

    /** Reads a commit out of a relay envelope. */
    fun unwrapCommit(wire: ByteArray): ByteArray = Mobile.unwrapGroupCommit(wire)

    /**
     * The delivery tokens of this group's mailboxes.
     *
     * A commit arrives with only a token and no group id, so a client that receives one has to
     * work out which group it belongs to — and this is how: the tokens are derived from the
     * group's current epoch, so the group whose tokens contain the envelope's token is the group
     * the envelope is for. Trying each stored group is acceptable because a device has a handful
     * of groups, not thousands.
     */
    fun mailboxTokens(stateJson: String, tokenEpoch: Long, count: Long): List<String> =
        Mobile.groupMailboxTokens(stateJson, tokenEpoch, count)
            .split(',')
            .filter { it.isNotEmpty() }

    /** The group's routing key: what the mailboxes are derived from. */
    fun routeKey(stateJson: String): String = Mobile.groupRouteKey(stateJson)
}
