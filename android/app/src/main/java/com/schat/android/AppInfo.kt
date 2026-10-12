package com.schat.android

/**
 * Static facts about this build, shown on the status screen.
 *
 * This object exists so that the UI states plainly what the application can and
 * cannot currently do. Shipping a build that looks finished but does nothing is
 * the single most misleading thing a security application can do, so the list of
 * unimplemented pieces is part of the product surface until those pieces land.
 */
object AppInfo {

    /** Product name. */
    const val NAME = "SCHAT"

    /** Client version. Kept in step with android/app/build.gradle.kts. */
    const val VERSION = "0.1.0-alpha"

    /** Pairwise protocol revision, from protocol/version.go. */
    const val PROTOCOL = "SCS-1/v1"

    /** Group protocol, per the owner's decision to use MLS without compromise. */
    const val GROUP_PROTOCOL = "MLS (RFC 9420)"

    /** Minimum supported platform. */
    const val MIN_ANDROID = "Android 8.0 (API 26)"

    /**
     * What actually works today.
     *
     * Everything here is verified by `go build`, `go vet` and `go test` on the
     * Go side, and by a Gradle build on this side. Nothing is claimed that has
     * not been executed.
     */
    val implemented: List<String> = listOf(
        "SCS-1 域分隔标签体系（12 个标签，唯一性有测试保证）",
        "HKDF-SHA256 密钥派生（通过 RFC 5869 官方测试向量）",
        "AEAD 配置矩阵：ChaCha20-Poly1305 / XChaCha20 / AES-256-GCM",
        "四重 DH 会话建立（SCS-HSK）：LEXSORT + transcript 绑定 + 一次性预密钥",
        "双棘轮（SCS-DR）：对称链、DH 棘轮、乱序消息、重放与篡改防护",
        "未认证帧的回滚防护（伪造棘轮公钥无法摧毁会话）",
        "分块密钥梯 + 哈希树（支持随机访问与断点续传）",
        "Argon2id 三档参数 + 设备密钥双因子保险库派生",
        "投递令牌（每 24 小时轮换的元数据保护）",
        "记忆零化工具（密钥用后立即擦除）",
        "长度填充（隐藏消息真实长度）",
        "中继服务端：WebSocket 网关（RFC 6455）、令牌路由、内存队列、TLS 与指纹固定",
        "预密钥目录：发布/获取/撤回；获取时**原子消费**一个一次性预密钥（并发抢领不重复发放）",
        "协议核心已编译为 .aar 并链入本 App（Go 实现，与测试套件同一份代码）",
        "客户端核心：连接 URI 解析、AES-256-GCM 本地加密存储、保险库派生",
        "客户端网络层：证书指纹固定、中继长连接与心跳、预密钥目录调用",
        "信封内容分层（0x01 加密帧 / 0x02 握手），握手 Init 可在中继信封内传递",
        "会话控制器：建立/接受会话、文本收发、预密钥整池发布、棘轮快照与历史持久化",
        "聊天界面：消息列表、输入框、状态行、身份显示、60 位安全码比对",
        "真实服务器集成测试（两层）：协议层验证预密钥往返，客户端网络层验证 TLS 固定与 WebSocket",
        "二维码快联：展示身份码与服务器连接码、扫码填入（ZXing + CameraX，均为开源依赖，未用闭源的 ML Kit）",
        "好友列表（仅存本机）：备注名、最后消息与未读计数、按活跃时间排序、重命名与删除",
        "消息与联系人保存在本机加密库中，杀掉进程重开后仍在（含棘轮状态）",
        "首次运行引导：生成身份、设置口令、抄写恢复码、配置服务器",
        "保险库接线：双因子创建/解锁、错口令校验、本机资料持久化",
        "自动化测试共 466 项（协议 176 + 服务端 116 + 客户端核心 174），其中 5 项需真实服务器、默认 SKIP",
    )

    /**
     * What does not work yet, and therefore what the user must not rely on.
     *
     * The roadmap step is named for each item so that this list can be checked
     * against SCHAT.md section 13.2.
     */
    val pending: List<String> = listOf(
        "步骤 3c：配置二维码渲染（目前需手动输入连接 URI）",
        "步骤 5 收尾：单聊代码已全部实现并通过编译与单元测试，但**尚未在两台真机上走通**——这是目前唯一缺失的证据",
        "会话控制器无自动化测试：:core 之所以是纯 JVM 模块，正是为了把协议 AAR 挡在测试类路径之外，代价是 :app 里的控制器只能靠评审与真机验证（其回归后果是握手可重放）",
        "release 构建（R8 裁剪与压缩）未测量：下面显示的体积是 debug 包",
        "⚠️ 相机扫码路径**未在真机上验证过**：构建环境没有摄像头，只能保证编译通过；" +
            "它依赖的编解码与负载解析逻辑有 18 项 JVM 测试覆盖，但相机本身属于「只能真机验证」的一类",
        "本 App 申请 `INTERNET` 与 `CAMERA` 两个权限。相机仅在扫码界面启用，画面在内存中解码后丢弃，" +
            "不保存、不拍照、不上传；拒绝该权限后仍可手动输入",
        "步骤 6a：MLS (RFC 9420) 核心实现与官方测试向量验证",
        "步骤 6b：群聊功能接入",
        "步骤 7：图片 / 视频 / 语音 / 文件的分块加密传输与 P2P 直连",
        "步骤 9：服务器部署与连接教程",
        "Keystore 层尚无自动化测试覆盖（依赖平台行为，需真机验证）",
        "⚠️ 元数据保护暂缺：投递令牌的服务端实现已完成，但客户端尚未实现会话内令牌交换" +
            "（首次通信前没有会话可用来交换令牌）。当前由公开身份派生信箱地址并据此寻址，" +
            "即任何知道你身份公钥的人都能观察到你何时在收发消息。消息内容仍受端到端加密保护。",
    )
}
