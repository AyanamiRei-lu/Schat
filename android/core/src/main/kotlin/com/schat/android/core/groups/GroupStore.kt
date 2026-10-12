package com.schat.android.core.groups

import com.schat.android.data.store.EncryptedStore

/**
 * 一个群在本机保存的全部内容。
 *
 * [stateJson] 是 Go 协议核心产出的不透明快照——**它含该 epoch 的密钥**，
 * 因此只能待在加密存储里。这里不解它、不改它、不打印它：
 * 这一层的职责是保存，不是理解。
 */
data class GroupRecord(
    /** 群标识，十六进制。 */
    val groupIdHex: String,

    /** 群状态快照，**含 epoch 密钥**。 */
    val stateJson: String,

    /**
     * 下一条消息要用的棘轮代数。
     *
     * 它不在快照里，而必须与快照一起保存：代数传错不会报错，只会让**接收方全部解不开**。
     */
    val generation: Long,

    /**
     * 成员备注名，按叶子下标。
     *
     * 只是本机显示用的名字；群里的身份由签名密钥决定，与这里的名字无关。
     */
    val memberNames: Map<Long, String> = emptyMap(),
)

/**
 * 群里的一条消息。
 *
 * 正文以**明文**存在这里，因为存储本身是加密的：把它再加密一层只会多一份要维护的密钥，
 * 而对保护没有增加——能读到这个存储的人已经有打开这个群的全部钥匙了。
 */
data class GroupMessage(
    /** 发送者的叶子下标。 */
    val fromLeaf: Long,

    /** 是否为本机发出。 */
    val mine: Boolean,

    /** 发送者用的棘轮代数（本机发出时为本机代数）。 */
    val generation: Long,

    /** 落库时间，毫秒。只用于排序与显示。 */
    val atMillis: Long,

    /** 正文。 */
    val text: String,
)

/**
 * 把群保存在加密存储里。
 *
 * # 为什么用索引键而不是枚举
 *
 * 存储层只有 contains / get / put / remove，没有"列出所有键"。所以群标识单独放在
 * [KEY_INDEX] 里，用换行分隔。**这正是成员备注名必须转义的原因**——同一个存储里，
 * 一个能注入分隔符的名字就会变成第二条记录。
 *
 * # 为什么旧版本被拒绝而不是迁移
 *
 * 快照的版本在 Go 侧的 JSON 里（`snapshotVersion`），不在这一层。版本不符时
 * `GroupController` 会拒绝它——**猜一个群密钥的布局不是可以悄悄做的事**，
 * 这与单聊会话快照的既有规则一致。
 */
/**
 * 每个群保留的消息条数上限。**必须有上限**：存储没有总量限制，而一个群可以无限地收消息。
 *
 * 放在文件级而不是伴生对象里，是为了让它可被测试引用——上限的行为是需要被断言的东西，
 * 而不是一个只写在实现里的数字。
 */
const val GROUP_MESSAGE_LIMIT = 500

class GroupStore(private val store: EncryptedStore) {

    /** 保存一个群，覆盖已有的同名记录。 */
    fun save(record: GroupRecord) {
        require(record.groupIdHex.isNotBlank()) { "群标识不能为空" }
        require(record.generation >= 0) { "棘轮代数不能为负" }

        store.putString(stateKey(record.groupIdHex), record.stateJson)
        store.putString(generationKey(record.groupIdHex), record.generation.toString())
        store.putString(namesKey(record.groupIdHex), encodeNames(record.memberNames))

        addToIndex(record.groupIdHex)
    }

    /**
     * 读回一个群。
     *
     * 缺少状态或代数时返回 null，而不是半个对象：[stateJson] 缺失意味着这个群已经不可用，
     * 而代数为零或默认值会让**下一条消息重用一代密钥**——这是 AEAD 唯一无法承受的失败。
     */
    fun load(groupIdHex: String): GroupRecord? {
        val state = store.getString(stateKey(groupIdHex)) ?: return null
        val generation = store.getString(generationKey(groupIdHex))?.toLongOrNull() ?: return null

        return GroupRecord(
            groupIdHex = groupIdHex,
            stateJson = state,
            generation = generation,
            memberNames = decodeNames(store.getString(namesKey(groupIdHex))),
        )
    }

    /** 本机保存的全部群标识。 */
    fun list(): List<String> =
        (store.getString(KEY_INDEX) ?: "")
            .split('\n')
            .filter { it.isNotBlank() }

    /**
     * 删除一个群。
     *
     * 状态、代数、备注名**一并删除**。[stateJson] 是打开该群全部历史的钥匙，
     * 留下它就是留下一个"已删除"的群——这与联系人删除遵循同一条规则。
     */
    fun clear(groupIdHex: String) {
        store.remove(stateKey(groupIdHex))
        store.remove(generationKey(groupIdHex))
        store.remove(namesKey(groupIdHex))
        // 消息也必须删：留着一个"已删除的群"的聊天记录，等于删除没有发生。
        store.remove(messagesKey(groupIdHex))

        val remaining = list().filter { it != groupIdHex }
        if (remaining.isEmpty()) store.remove(KEY_INDEX) else store.putString(KEY_INDEX, remaining.joinToString("\n"))
    }

    /**
     * 追加一条消息。
     *
     * 历史上限是每个群 [MAX_MESSAGES] 条，超出的从最旧的一端丢弃。**上限是必需的**：
     * 存储没有总量限制，而一个群可以无限地收消息。
     */
    fun appendMessage(groupIdHex: String, message: GroupMessage) {
        val kept = (loadMessages(groupIdHex) + message).takeLast(GROUP_MESSAGE_LIMIT)
        store.putString(messagesKey(groupIdHex), encodeMessages(kept))
    }

    /** 读回一个群的消息，从最旧到最新。 */
    fun loadMessages(groupIdHex: String): List<GroupMessage> =
        decodeMessages(store.getString(messagesKey(groupIdHex)))

    /**
     * 保存本机发布出去的那份 KeyPackage 及其 init 私钥。
     *
     * 两者必须一起存，缺一不可：KeyPackage 是公开的，而 init 私钥是日后解开 Welcome 的
     * 唯一凭据。分开存就会出现"群在、入群凭据不在"的半个状态——这与 ClientProfileStore
     * 里"半个 profile 比没有更糟"是同一条理由。
     *
     * 它是【身份级】而不是群级：一份 KeyPackage 可以被多个群用来加入，所以它不属于任何一个群。
     */
    fun saveMyKeyPackage(keyPackageHex: String, initKeyPrivateHex: String, leafKeyPrivateHex: String) {
        require(
            keyPackageHex.isNotEmpty() &&
                initKeyPrivateHex.isNotEmpty() &&
                leafKeyPrivateHex.isNotEmpty(),
        ) {
            "KeyPackage、init 私钥与叶子私钥都必须非空"
        }
        store.putString(KEY_MY_KEYPACKAGE, keyPackageHex)
        store.putString(KEY_MY_INIT_KEY, initKeyPrivateHex)
        store.putString(KEY_MY_LEAF_KEY, leafKeyPrivateHex)
    }

    /** 读回本机发布的 KeyPackage 与它的 init 私钥；缺任一项返回 null，而不是半个结果。 */
    fun loadMyKeyPackage(): Triple<String, String, String>? {
        val keyPackage = store.getString(KEY_MY_KEYPACKAGE) ?: return null
        val initKey = store.getString(KEY_MY_INIT_KEY) ?: return null
        // A record written before the leaf key was kept has no third value. Returning null
        // makes the caller publish a new KeyPackage, which is the only correct outcome: the
        // stored one describes a leaf whose private half is gone, so joining with it would
        // leave the member unable to follow any commit.
        val leafKey = store.getString(KEY_MY_LEAF_KEY) ?: return null
        if (keyPackage.isEmpty() || initKey.isEmpty() || leafKey.isEmpty()) return null
        return Triple(keyPackage, initKey, leafKey)
    }

    private fun addToIndex(groupIdHex: String) {
        if (list().contains(groupIdHex)) return
        store.putString(KEY_INDEX, (list() + groupIdHex).joinToString("\n"))
    }

    private companion object {
        const val KEY_INDEX = "groups.index"

        // 本机发布出去的 KeyPackage 与它的 init 私钥：身份级，不属于任何一个群。
        const val KEY_MY_KEYPACKAGE = "groups.myKeyPackage"
        const val KEY_MY_INIT_KEY = "groups.myInitKey"

        // 叶子密钥的私钥：入群者用它解开寻址给自己的路径秘密，下标决定它尝试哪一个密文。
        const val KEY_MY_LEAF_KEY = "groups.myLeafKey"

        // 叶子密钥的私钥：入群者用它解开寻址给自己的路径秘密。它与 KeyPackage 一起保存，
        // 因为 KeyPackage 描述的就是那片叶子 —— 少了它，成员能入群却跟不上任何一条提交。

        /** 每个群保留的消息条数上限。 */
        const val MAX_MESSAGES = 500

        fun messagesKey(id: String) = "group.$id.messages"

        fun stateKey(id: String) = "group.$id.state"
        fun generationKey(id: String) = "group.$id.generation"
        fun namesKey(id: String) = "group.$id.names"

        /**
         * 备注名的编码：每行 `叶子下标:名字`。
         *
         * 名字里的换行、回车与冒号会被转义成 `\n`、`\r`、`\:`。
         * **这不是美化，是防止注入**：不转义的话，一个叫 "x\n5:某人" 的备注名
         * 会在读回时变出一条属于叶子 5 的伪造记录。
         */
        fun encodeNames(names: Map<Long, String>): String =
            names.entries
                .sortedBy { it.key }
                .joinToString("\n") { (leaf, name) -> "$leaf:${escape(name)}" }

        fun decodeNames(raw: String?): Map<Long, String> {
            if (raw.isNullOrEmpty()) return emptyMap()

            val out = mutableMapOf<Long, String>()
            for (line in raw.split('\n')) {
                if (line.isEmpty()) continue
                val separator = line.indexOf(':')
                // 结构不完整的行被丢弃，而不是猜测它的含义：一条读不懂的记录不该变成一条
                // 看似有效的成员。
                if (separator <= 0) continue
                val leaf = line.substring(0, separator).toLongOrNull() ?: continue
                out[leaf] = unescape(line.substring(separator + 1))
            }
            return out
        }

        /**
         * 消息的编码：每行 `叶子|mine|代数|时间|转义后的正文`。
         *
         * 正文里同样要转义 `|`、`\\`、换行与回车——理由与备注名一样：
         * 一个能注入分隔符的正文会变出一条伪造的消息记录。
         */
        fun encodeMessages(messages: List<GroupMessage>): String =
            messages.joinToString("\n") { m ->
                listOf(m.fromLeaf.toString(), if (m.mine) "1" else "0", m.generation.toString(),
                    m.atMillis.toString(), escape(m.text)).joinToString("|")
            }

        fun decodeMessages(raw: String?): List<GroupMessage> {
            if (raw.isNullOrEmpty()) return emptyList()

            val out = mutableListOf<GroupMessage>()
            for (line in raw.split('\n')) {
                if (line.isEmpty()) continue
                // 恰好 5 段：转义保证正文里不会再出现分隔符，所以段数不对的行是坏的，
                // 丢弃它而不是猜它的含义。
                val parts = line.split('|')
                if (parts.size != 5) continue
                val leaf = parts[0].toLongOrNull() ?: continue
                val mine = parts[1] == "1"
                val generation = parts[2].toLongOrNull() ?: continue
                val at = parts[3].toLongOrNull() ?: continue
                out.add(GroupMessage(leaf, mine, generation, at, unescape(parts[4])))
            }
            return out
        }

        fun escape(name: String): String = buildString(name.length) {
            for (ch in name) {
                when (ch) {
                    '\\' -> append("\\\\")
                    '\n' -> append("\\n")
                    '\r' -> append("\\r")
                    ':' -> append("\\:")
                    // 注意：这里必须转义成不含 '|' 的形式。写成 "\\|" 是错的——解码按字符
                    // 切分，转义后的分隔符照样会被切开，于是整条消息被丢弃。
                    '|' -> append("\\p")
                    // 注意：这里必须转义成不含 '|' 的形式。写成 "\\|" 是错的——解码按字符
                    // 切分，转义后的分隔符照样会被切开，于是整条消息被丢弃。
                    '|' -> append("\\p")
                    else -> append(ch)
                }
            }
        }

        fun unescape(value: String): String = buildString(value.length) {
            var i = 0
            while (i < value.length) {
                val ch = value[i]
                if (ch == '\\' && i + 1 < value.length) {
                    when (value[i + 1]) {
                        '\\' -> { append('\\'); i += 2 }
                        'n' -> { append('\n'); i += 2 }
                        'r' -> { append('\r'); i += 2 }
                        ':' -> { append(':'); i += 2 }
                        'p' -> { append('|'); i += 2 }
                        'p' -> { append('|'); i += 2 }
                        else -> { append(ch); i++ }
                    }
                } else {
                    append(ch); i++
                }
            }
        }
    }
}
