package com.schat.android.core.legal

import com.schat.android.data.store.EncryptedStore
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * 同意记录的行为。
 *
 * # 这里的样本文本是真实文本的头部，逐字复制
 *
 * 这一点很要紧。用**真实**文本去测解析，才能证明解析器在真实输入上工作；用一段
 * 手写的、格式"差不多"的样本文本，证明的只是解析器能解析它自己想象出来的输入。
 * 这个项目为此付出过代价：曾经有 8 处测试给被测代码喂了现实中不存在的输入，
 * 297 项全绿而功能完全不可用。
 *
 * 文本一旦改动（比如版本从 1.0 变成 1.1），这些样本自然也要跟着改——而 CI 里
 * 有一条检查保证 assets 与 docs/legal 两份副本逐字节相同。
 */
class LegalConsentTest {

    @get:Rule
    val temp = TemporaryFolder()

    private val key = ByteArray(32) { it.toByte() }

    private fun newStore(): LegalConsentStore {
        val encrypted = EncryptedStore(File(temp.root, "vault.dat"), key)
        return LegalConsentStore(encrypted)
    }

    // ---- 真实文本的头部，与 docs/legal 里逐字相同 ------------------------------------

    private val userAgreement = """
        # Schat 用户协议

        **版本：1.0**  
        **本协议自公布之日起生效。**

        **项目仓库：** https://github.com/AyanamiRei-lu/Schat
    """.trimIndent()

    private val privacyPolicy = """
        # Schat 隐私政策

        **版本：1.0**
        **本政策自公布之日起生效。**
        **项目仓库：** https://github.com/AyanamiRei-lu/Schat
    """.trimIndent()

    private val childrenPrivacy = """
        # Schat 儿童个人信息保护规则

        **版本：1.0**
        **本规则自公布之日起生效。**
        **项目仓库：** https://github.com/AyanamiRei-lu/Schat
    """.trimIndent()

    private val operatorGuide = """
        # Schat 服务器运营须知

        **版本：1.0**
        **本须知自公布之日起生效。**
        **项目仓库：** https://github.com/AyanamiRei-lu/Schat
    """.trimIndent()

    private fun texts(version: String = "1.0"): Map<String, String> = mapOf(
        LegalDocuments.USER_AGREEMENT to userAgreement.replace("**版本：1.0**", "**版本：$version**"),
        LegalDocuments.PRIVACY_POLICY to privacyPolicy.replace("**版本：1.0**", "**版本：$version**"),
        LegalDocuments.CHILDREN_PRIVACY to childrenPrivacy.replace("**版本：1.0**", "**版本：$version**"),
        LegalDocuments.SERVER_OPERATOR_GUIDE to operatorGuide,
    )

    private fun documents(version: String = "1.0") = LegalDocuments.parseAll(texts(version))

    // ---- 解析 ----------------------------------------------------------------------

    @Test
    fun `parses the title and version out of the real text`() {
        val doc = LegalDocuments.parse(LegalDocuments.USER_AGREEMENT, userAgreement)
        assertEquals("Schat 用户协议", doc?.title)
        assertEquals("1.0", doc?.version)
    }

    @Test
    fun `parses all four documents`() {
        val all = documents()
        assertEquals(4, all.size)
        assertEquals(
            listOf("Schat 用户协议", "Schat 隐私政策", "Schat 儿童个人信息保护规则", "Schat 服务器运营须知"),
            all.map { it.title },
        )
    }

    @Test
    fun `a document without a version parses as null rather than as some default`() {
        // 这是整件事里最要紧的一条：解析不出版本就必须拒绝，而不是拿一个默认值兜住。
        // 用默认值兜住等于让用户"同意了一份版本未知的协议"。
        val noVersion = userAgreement.replace("**版本：1.0**", "")
        assertNull(LegalDocuments.parse(LegalDocuments.USER_AGREEMENT, noVersion))
    }

    @Test
    fun `a document without a title parses as null`() {
        assertNull(LegalDocuments.parse(LegalDocuments.USER_AGREEMENT, "**版本：1.0**"))
    }

    @Test
    fun `an unknown id parses as null`() {
        assertNull(LegalDocuments.parse("no-such-document", userAgreement))
    }

    // ---- 同意记录 ------------------------------------------------------------------

    @Test
    fun `nothing is satisfied before anything is accepted`() {
        val store = newStore()
        assertNull(store.load())
        assertFalse(store.isSatisfied(documents()))
        assertEquals(LegalDocuments.REQUIRING_CONSENT, store.pendingDocuments(documents()))
    }

    @Test
    fun `accepting the current versions satisfies the gate`() {
        val store = newStore()
        val docs = documents()
        store.save(
            LegalConsent(
                acceptedVersions = docs.filter { it.id in LegalDocuments.REQUIRING_CONSENT }
                    .associate { it.id to it.version },
                acceptedAtMillis = 1_700_000_000_000,
            )
        )
        assertTrue(store.isSatisfied(docs))
        assertTrue(store.pendingDocuments(docs).isEmpty())
    }

    @Test
    fun `the operator guide is listed but does not have to be accepted`() {
        val store = newStore()
        val docs = documents()
        // 只确认那三份需要确认的，刻意**不**包含运营须知
        store.save(
            LegalConsent(
                acceptedVersions = mapOf(
                    LegalDocuments.USER_AGREEMENT to "1.0",
                    LegalDocuments.PRIVACY_POLICY to "1.0",
                    LegalDocuments.CHILDREN_PRIVACY to "1.0",
                ),
                acceptedAtMillis = 1,
            )
        )
        assertTrue("运营须知约束的是运营者，不是每一个用 App 的人", store.isSatisfied(docs))
    }

    @Test
    fun `a version bump brings the user back to the terms`() {
        val store = newStore()
        store.save(
            LegalConsent(
                acceptedVersions = mapOf(
                    LegalDocuments.USER_AGREEMENT to "1.0",
                    LegalDocuments.PRIVACY_POLICY to "1.0",
                    LegalDocuments.CHILDREN_PRIVACY to "1.0",
                ),
                acceptedAtMillis = 1,
            )
        )
        assertTrue(store.isSatisfied(documents("1.0")))

        // 协议升到 1.1：同意的是 1.0，所以不满足，而且能说出是哪几份变了
        val bumped = documents("1.1")
        assertFalse("同意过 1.0 不该被当成同意 1.1", store.isSatisfied(bumped))
        assertEquals(
            listOf(
                LegalDocuments.USER_AGREEMENT,
                LegalDocuments.PRIVACY_POLICY,
                LegalDocuments.CHILDREN_PRIVACY,
            ),
            store.pendingDocuments(bumped),
        )
    }

    @Test
    fun `only the document that changed is reported as pending`() {
        val store = newStore()
        val docs = documents()
        val bumped = texts().toMutableMap()
        bumped[LegalDocuments.PRIVACY_POLICY] =
            bumped.getValue(LegalDocuments.PRIVACY_POLICY).replace("**版本：1.0**", "**版本：1.1**")

        store.save(
            LegalConsent(
                acceptedVersions = mapOf(
                    LegalDocuments.USER_AGREEMENT to "1.0",
                    LegalDocuments.PRIVACY_POLICY to "1.0",
                    LegalDocuments.CHILDREN_PRIVACY to "1.0",
                ),
                acceptedAtMillis = 1,
            )
        )

        assertEquals(
            listOf(LegalDocuments.PRIVACY_POLICY),
            store.pendingDocuments(LegalDocuments.parseAll(bumped)),
        )
        // 而原封不动的那一批仍然是满足的
        assertTrue(store.isSatisfied(docs))
    }

    @Test
    fun `the record survives a new store over the same file`() {
        val docs = documents()
        newStore().save(
            LegalConsent(
                acceptedVersions = docs.associate { it.id to it.version },
                acceptedAtMillis = 42,
            )
        )
        // 换一个实例读同一个文件：这是"重启应用"的模型
        val reopened = newStore()
        assertTrue(reopened.isSatisfied(docs))
        assertEquals(42L, reopened.load()?.acceptedAtMillis)
    }

    @Test
    fun `clearing forgets everything`() {
        val store = newStore()
        val docs = documents()
        store.save(
            LegalConsent(acceptedVersions = docs.associate { it.id to it.version }, acceptedAtMillis = 7)
        )
        assertTrue(store.isSatisfied(docs))

        store.clear()
        assertNull(store.load())
        assertFalse(store.isSatisfied(docs))
    }

    @Test
    fun `saving again replaces the previous record rather than merging with it`() {
        val store = newStore()
        store.save(
            LegalConsent(
                acceptedVersions = mapOf(LegalDocuments.USER_AGREEMENT to "0.9"),
                acceptedAtMillis = 1,
            )
        )
        store.save(
            LegalConsent(
                acceptedVersions = mapOf(LegalDocuments.USER_AGREEMENT to "1.0"),
                acceptedAtMillis = 2,
            )
        )
        val loaded = store.load()
        assertEquals("1.0", loaded?.acceptedVersions?.get(LegalDocuments.USER_AGREEMENT))
        assertEquals(2L, loaded?.acceptedAtMillis)
        // 被替换掉的那份不该残留
        assertNull(loaded?.acceptedVersions?.get(LegalDocuments.PRIVACY_POLICY))
    }
}
