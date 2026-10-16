package com.schat.android.data.store

import java.io.File
import java.util.Base64

/**
 * 一个最小的键值面。
 *
 * # 为什么需要它
 *
 * 有两类记录，它们的**保密性不同、可写入的时机也不同**：
 *
 * | 记录 | 是秘密吗 | 什么时候能写 |
 * |---|---|---|
 * | 身份、预密钥、恢复码 | **是** | 口令设好之后（密钥由口令派生） |
 * | 协议确认记录（版本 + 时间戳） | **不是** | **口令还没设的时候** |
 *
 * 后者发生在引导流程的第一步——用户刚打开应用，保险库还不存在。要求它先有密钥，
 * 就会变成"用户为了同意协议，必须先设一个口令"，这在流程上是本末倒置的。
 *
 * 所以这一层只规定"怎么存"，不规定"存得保不保密"。[EncryptedStore] 用 AES-256-GCM，
 * [PlainFileStore] 明文——两个实现满足同一个面，调用方按数据的性质挑一个。
 *
 * # 方法签名为什么长这样
 *
 * 它**照着 [EncryptedStore] 已有的方法写**，一个字都不改。这样 `EncryptedStore`
 * 实现它不需要任何包装，而已有的调用点与测试完全不受影响。
 */
interface KeyValueStore {

    /** 读一个字符串值，不存在时返回 null。 */
    fun getString(name: String): String?

    /** 写入一个字符串值，覆盖旧的。 */
    fun putString(name: String, value: String)

    /** 删除一个键。返回是否真的删掉了什么。 */
    fun remove(name: String): Boolean
}

/**
 * 一个明文的键值存储，用于**不需要保密**的记录。
 *
 * # 明文在这里不是妥协
 *
 * 会说"那就加密啊"——但加密需要密钥，而在引导的第一步，密钥还不存在：它由用户
 * 尚未设置的口令派生。把协议确认记录放进加密存储，等于让"同意协议"依赖"已经设好
 * 口令"，顺序就反了。
 *
 * 而这些数据本身也不是秘密：它说的是"这个人在这个时刻同意过 1.0 版"，而那两件事
 * 都写在协议文本里、任何人都能查到。真正需要保护的是消息与密钥，它们在别处。
 *
 * # 格式
 *
 * ```
 * SCHAT-PLAIN-1
 * <base64 键>\t<base64 值>
 * ...
 * ```
 *
 * 手写的行格式而不是 JSON：`org.json` 在 Android 上有、在普通 JVM 上没有（会抛异常），
 * 而这个类要在 JVM 上做单元测试。键用 base64 编码，所以键里出现制表符或换行也不会
 * 把文件弄坏。
 *
 * 写入用"写临时文件再改名"，与 [EncryptedStore] 同样的理由：崩溃不会留下半个文件。
 */
class PlainFileStore(private val file: File) : KeyValueStore {

    private val records = LinkedHashMap<String, String>()

    init {
        if (file.exists()) load()
    }

    override fun getString(name: String): String? = records[name]

    override fun putString(name: String, value: String) {
        require(name.isNotEmpty()) { "record name must not be empty" }
        records[name] = value
        persist()
    }

    override fun remove(name: String): Boolean {
        if (records.remove(name) == null) return false
        persist()
        return true
    }

    /** 是否存过某个键。 */
    fun contains(name: String): Boolean = records.containsKey(name)

    /** 全部键名。 */
    fun names(): Set<String> = records.keys.toSet()

    /** 删除整个文件。 */
    fun clear() {
        records.clear()
        if (file.exists()) file.delete()
    }

    private fun load() {
        val lines = try {
            file.readLines()
        } catch (e: Exception) {
            // 读不到就当空的。一个读不出来的存储不该让应用起不来——而调用方会发现
            // 记录不在（isSatisfied 返回 false），于是把用户带回条款页，那是对的行为。
            return
        }
        if (lines.isEmpty() || lines[0].trim() != MAGIC) return

        for (line in lines.drop(1)) {
            if (line.isBlank()) continue
            val tab = line.indexOf('\t')
            if (tab <= 0) continue
            val name = try {
                String(Base64.getDecoder().decode(line.substring(0, tab)), Charsets.UTF_8)
            } catch (e: Exception) {
                continue
            }
            records[name] = String(
                Base64.getDecoder().decode(line.substring(tab + 1)),
                Charsets.UTF_8,
            )
        }
    }

    private fun persist() {
        val builder = StringBuilder()
        builder.append(MAGIC).append('\n')
        for ((name, value) in records) {
            val encodedName = Base64.getEncoder().encodeToString(name.toByteArray(Charsets.UTF_8))
            val encodedValue = Base64.getEncoder().encodeToString(value.toByteArray(Charsets.UTF_8))
            builder.append(encodedName).append('\t').append(encodedValue).append('\n')
        }

        val temp = File(file.parentFile, file.name + ".tmp")
        temp.parentFile?.mkdirs()
        temp.writeText(builder.toString())

        if (!temp.renameTo(file)) {
            // Windows 不允许 rename 覆盖已存在的文件，退回到删除再改名。
            file.delete()
            if (!temp.renameTo(file)) {
                temp.copyTo(file, overwrite = true)
                temp.delete()
            }
        }
    }

    private companion object {
        const val MAGIC = "SCHAT-PLAIN-1"
    }
}
