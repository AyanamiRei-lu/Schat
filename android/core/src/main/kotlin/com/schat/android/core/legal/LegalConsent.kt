package com.schat.android.core.legal

import com.schat.android.data.store.KeyValueStore

/**
 * 一份协议文档。
 *
 * # 版本号从文本本身解析，不是硬编码的
 *
 * 这个项目里已经吃过一次亏：两个地方各写一份同一个数字，然后它们悄悄不一致。
 * 所以这里**只有一个版本来源**——协议文本里的 `**版本：1.0**` 那一行。解析不出来
 * 就返回 null，调用方必须拒绝继续，而不是默默放过：那会变成"用户同意了一个版本号
 * 未知的协议"。
 */
data class LegalDocument(
    /** 稳定标识。它会被写进存储，所以一旦发布就不能改（改了就当成一份新文档）。 */
    val id: String,

    /** 在 assets 下的文件名。 */
    val fileName: String,

    /** 从文本第一行 `# 标题` 解析出来的标题。 */
    val title: String,

    /** 从文本解析出来的版本。 */
    val version: String,
)

/**
 * 四份协议文档的清单。
 *
 * 它们是 `docs/legal/` 与 `android/app/src/main/assets/legal/` 里**同一批文件**的两份副本。
 * 两份内容必须逐字节相同，否则 App 里显示的和用户能在仓库里查到的就不是同一份文本——
 * 而协议的价值恰恰在于"你随时能查到我说过什么"。CI 里有一条检查比对这两份副本。
 */
object LegalDocuments {

    /** assets 下的目录名，也是 docs 下的目录名。 */
    const val DIR = "legal"

    // 稳定标识。写进存储，不可更改。
    const val USER_AGREEMENT = "user-agreement"
    const val PRIVACY_POLICY = "privacy-policy"
    const val CHILDREN_PRIVACY = "children-privacy"
    const val SERVER_OPERATOR_GUIDE = "server-operator-guide"

    /** id -> 文件名。顺序即界面里的显示顺序。 */
    val FILE_NAMES: Map<String, String> = linkedMapOf(
        USER_AGREEMENT to "USER-AGREEMENT.md",
        PRIVACY_POLICY to "PRIVACY-POLICY.md",
        CHILDREN_PRIVACY to "CHILDREN-PRIVACY.md",
        SERVER_OPERATOR_GUIDE to "SERVER-OPERATOR-GUIDE.md",
    )

    /**
     * 需要普通用户**确认**的文档。
     *
     * 《服务器运营须知》不在其中：它约束的是**运营服务器的人**，不是每一个用 App 的人。
     * 它仍然列在阅读界面里——用户可以随时读——但不参与"同意"这个动作。
     */
    val REQUIRING_CONSENT: List<String> = listOf(USER_AGREEMENT, PRIVACY_POLICY, CHILDREN_PRIVACY)

    /**
     * 从协议文本里解析出标题与版本。
     *
     * 两个模式都锚在行首，而且只取**第一个**匹配：文档开头就是为了给人看而写的
     * 标题与版本，后面的正文里再出现就不该影响解析。
     *
     * 任一解析不出来就返回 null。调用方的正确反应是**不让用户继续**——不是用默认值
     * 兜住，那等于同意了一份版本未知的协议。
     */
    fun parse(id: String, text: String): LegalDocument? {
        val fileName = FILE_NAMES[id] ?: return null

        val title = TITLE.find(text)?.groupValues?.get(1)?.trim()
        if (title.isNullOrEmpty()) return null

        val version = VERSION.find(text)?.groupValues?.get(1)?.trim()
        if (version.isNullOrEmpty()) return null

        return LegalDocument(id = id, fileName = fileName, title = title, version = version)
    }

    /** 全部四份文档，按 [FILE_NAMES] 的顺序。 */
    fun parseAll(texts: Map<String, String>): List<LegalDocument> =
        FILE_NAMES.keys.mapNotNull { id -> texts[id]?.let { parse(id, it) } }

    private val TITLE = Regex("""(?m)^#\s+(.+?)\s*$""")

    private val VERSION = Regex("""\*\*版本：\s*([0-9A-Za-z._-]+)\s*\*\*""")
}

/**
 * 用户确认过的东西。
 *
 * [acceptedVersions] 是"文档 id -> 当时确认的版本"。记版本而不只是记一个布尔值，
 * 是为了让协议更新后能**只提醒那些同意过旧版本的人**，而不是把所有人再问一遍，
 * 也不是谁都不问。
 */
data class LegalConsent(
    val acceptedVersions: Map<String, String>,

    /** 确认发生的时刻，毫秒。仅用于显示，不参与判断。 */
    val acceptedAtMillis: Long,
)

/**
 * 把确认记录保存在加密存储里。
 *
 * # 为什么它是独立的一份，而不是 ClientProfileData 的一个字段
 *
 * 确认发生在引导流程的**第二步**（生成身份之前），而 `ClientProfileData` 是在流程
 * **结束时**一次性写入的。如果同意记录跟着 profile 走，那么一个走到第三步就退出的人
 * 会丢掉他的同意记录，下次启动又要从条款页开始——而更糟的是，如果那时有人把
 * profile 的写入时机改动一下，同意记录就可能**永远写不进去**，条款页变成一道过不去的门。
 *
 * 独立存储 + 一确认就落盘，让这条记录的生命周期只取决于它自己。
 */
class LegalConsentStore(private val store: KeyValueStore) {

    /** 写入一份新的确认记录，覆盖旧的。 */
    fun save(consent: LegalConsent) {
        store.putString(KEY_AT, consent.acceptedAtMillis.toString())
        // 先清掉旧的版本记录，再写新的：否则一份被移除的文档会永远留在记录里
        LegalDocuments.FILE_NAMES.keys.forEach { store.remove(versionKey(it)) }
        consent.acceptedVersions.forEach { (id, version) ->
            if (id in LegalDocuments.FILE_NAMES && version.isNotEmpty()) {
                store.putString(versionKey(id), version)
            }
        }
    }

    /** 读回确认记录；没有任何记录时返回 null。 */
    fun load(): LegalConsent? {
        val at = store.getString(KEY_AT)?.toLongOrNull() ?: return null
        val versions = LinkedHashMap<String, String>()
        LegalDocuments.FILE_NAMES.keys.forEach { id ->
            store.getString(versionKey(id))?.let { versions[id] = it }
        }
        if (versions.isEmpty()) return null
        return LegalConsent(acceptedVersions = versions, acceptedAtMillis = at)
    }

    /** 清除确认记录（例如用户重置了本地数据）。 */
    fun clear() {
        store.remove(KEY_AT)
        LegalDocuments.FILE_NAMES.keys.forEach { store.remove(versionKey(it)) }
    }

    /**
     * 判断当前这批文档是否都已被确认。
     *
     * [documents] 是**当前**的文档（版本从文本解析而来）。只有当每一份"需要确认"的
     * 文档都在记录里、且版本与当前一致时，才算满足。
     *
     * 一份文档的版本从 1.0 变成 1.1，这里立刻变 false —— 引导流程会把用户带回条款页。
     * 这正是"记住版本号"的用处：条款更新后，用户看到的是**更新过的**那一份，
     * 而不是一个他一直以为有效的旧同意。
     */
    fun isSatisfied(documents: List<LegalDocument>): Boolean {
        val consent = load() ?: return false
        val byId = documents.associateBy { it.id }

        return LegalDocuments.REQUIRING_CONSENT.all { id ->
            val current = byId[id] ?: return@all false
            consent.acceptedVersions[id] == current.version
        }
    }

    /**
     * 列出需要重新确认的文档 id。
     *
     * 界面用它来告诉用户"哪一份变了"，而不是笼统地说"协议更新了"——用户有权知道
     * 自己被告知的是哪一份、哪一版。
     */
    fun pendingDocuments(documents: List<LegalDocument>): List<String> {
        val consent = load()
        val byId = documents.associateBy { it.id }
        return LegalDocuments.REQUIRING_CONSENT.filter { id ->
            val current = byId[id] ?: return@filter true
            consent?.acceptedVersions?.get(id) != current.version
        }
    }

    private fun versionKey(id: String) = "$KEY_VERSION_PREFIX$id"

    private companion object {
        const val KEY_AT = "legal.consent.at"
        const val KEY_VERSION_PREFIX = "legal.consent.version."
    }
}
