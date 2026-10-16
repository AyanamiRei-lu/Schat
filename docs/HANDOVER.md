# SCHAT 交接文档

> **写给下一位接手这个项目的 AI（或人）。**
>
> 这份文档的目标只有一个：**让你在半小时内知道这个项目现在处在什么地方，以及哪一句话不能信。**
>
> 它不重复设计细节——那些在 `SCHAT.md`（115 KB）和 `docs/` 里。它记录的是**现状、验证状态、和一路上真实踩过的坑**。
>
> 写这份文档时，其中的每一条"已通过"都来自**实际运行**；每一条"未验证"都明确标出。**没有一条是凭记忆写的。**

---

## 0. 如果只读一段

**SCHAT** 是一个**完全开源、可自建服务器**的安卓端到端加密聊天软件。中继服务器只转发密文信封——它不落盘、不建库、不解密。

- **仓库**：https://github.com/AyanamiRei-lu/Schat
- **许可**：GNU **AGPL-3.0-or-later**（对外提供网络服务的修改版必须同样开源）
- **版本**：`0.1.0-alpha`
- **规模**：281 个文件 / 3.2 MB（纯源码；构建产物均被忽略）

**现在真的能用的**：一对一加密聊天、好友列表、本地加密存储、二维码互扫、**群聊**（建群 / 加人 / 群消息 / 成员名单）。

**现在还没有的**：富媒体（图片 / 视频 / 语音 / 文件）、群成员「移除」的界面入口、服务端管理界面。

**下一步最该做的三件事**（详见第 11 节）：
1. **真机双机验证群聊**——协议层有端到端测试，客户端也编译通过，但"两台手机互相加人"从未实际跑过；
2. **富媒体（步骤 7）**——这是唯一一块大功能缺口；
3. **让 `:core` 的 CI job 变绿**（它现在标着 `continue-on-error`，见第 10.4 节）。

---

## 1. 项目是什么

一个安卓端到端加密聊天软件，设计原则有四条，**每一条都是可机械校验的**，不是口号：

| 原则 | 怎么保证 |
|---|---|
| **服务器零留存** | `mode=live` 是默认；预密钥目录与离线队列都在内存里。代码结构保证，不是配置保证 |
| **服务器零第三方依赖** | `go list -m all` 只有自身模块。CI 里有一条检查，`tools/verify.ps1` 里也有一条 |
| **服务器不含解密代码** | 它**刻意不导入协议核心**。`go list -deps ./...` 里不含 `protocol`。CI 与 `verify.ps1` 双重检查 |
| **不需要域名与 CA** | 服务端用自签名证书，**客户端固定证书指纹**。所以不用买域名、不用 Let's Encrypt、不用反向代理 |

**关于"原创加密算法"**：`SCS-1` 是**在标准原语之上的原创组合层**（X25519 / Ed25519 / HKDF-SHA256 / ChaCha20-Poly1305 / AES-256-GCM / Argon2id）——**没有自创任何密码学原语**。这一点在 `PROTOCOL-SPEC.md` 与 `SECURITY.md` 里都写明了。

---

## 2. 已经实现并且**验证过**的

| 能力 | 验证方式 | 结果 |
|---|---|---|
| SCS-1 协议核心：会话建立、双棘轮、乱序/重放/篡改/反射防护 | `cd protocol && go test ./...` | **305 项通过 + 49 项子测试，1 项 SKIP** |
| MLS 表示层编解码器 | 官方 RFC 9420 黄金向量 | 逐字节通过；非最短编码被拒 |
| MLS 密码学基础层 | 官方 `crypto-basics.json` | **12 项**逐字节通过（套件 0x0001 与 0x0003） |
| MLS 密钥调度 | 官方 `key-schedule.json` | **140 项**、10 个 epoch 逐字节通过 |
| MLS 树数学 | 官方 `tree-math.json` | **8144 项**下标关系通过 |
| MLS 秘密树 / 发送者数据 / 祖先节点 | 官方向量 | 656 / 12 / 349,525 组通过 |
| **MLS 群聊的端到端路径** | 见第 2.1 节 | **四个场景**全部通过 |
| 中继服务器 | `cd server && go test ./...` | **116 项通过 + 32 项子测试** |
| 服务端：零第三方依赖 | `GOWORK=off go list -m all` | 只有自身模块 |
| 服务端：不导入协议核心 | `GOWORK=off go list -deps ./...` | 依赖树里没有 `protocol` |
| 客户端核心（纯 JVM） | `cd android && ./gradlew :core:test` | **194 项通过，4 项 SKIP** |
| 客户端编译 | `./gradlew :app:assembleDebug` | 产出 **37.4 MB** debug APK |
| CI | GitHub Actions | 三个 job；Go 两个为绿 |

> **界面层（2026 年的一次 UI 改版）**：配色收敛到白/蓝/黑三族、加了渐变与动画、
> 所有界面改为共用 `ui/ui/Components.kt` 的零件。验证方式是
> `./gradlew :app:assembleDebug` 与 `:app:compileDebugKotlin --rerun-tasks`（全量重编）
> 均通过、APK 仍为 37.4 MB。**它没有被任何自动化测试覆盖，也没有在真机上跑过**——
> 界面在这个项目里一直是"只能靠真机验证"的那一类（见第 3.2 节）。

### 2.1 群聊的四个"跟随"场景（这是 M4 的核心）

MLS 里最容易出错、也最难发现的，是"某个成员在群变化之后还能不能继续待下去"。这四个场景**各有一条端到端测试**，都在 `protocol/mobile/` 下：

| 场景 | 测试文件 | 它证明的事 |
|---|---|---|
| **建群者**跟进别人的提交 | `selfupdate_test.go` | 建群者保留了自己的叶子私钥，且它跨 epoch 被**合并**而非覆盖 |
| **发送方自更新后**跟进别人的提交 | `selfupdate_test.go` | 成员替换自己的叶子后，用的是**新**私钥 |
| **接收方**应用一条提交 | `follow_test.go`、`groupcommit_test.go` | 能从路径**派生**出 commit secret |
| **经 Welcome 入群者**跟进提交 | `groupcommit_test.go` | 入群者的转录哈希正确，且它**自己推导**出叶子下标 |

**为什么强调这四个**：在这个项目的开发过程中，**每一个都单独缺失过**，而**每一个的症状都是"确认标签不匹配"**——一个指向密钥调度、与真正原因毫无关系的错误。详见第 10.5 节。

---

## 3. **未实现**与**未验证**——这两件事必须分清

### 3.1 未实现（代码里真的没有）

| 功能 | 位置 | 说明 |
|---|---|---|
| **富媒体**：图片 / 视频 / 语音 / 文件 | 步骤 7 | 唯一一块大功能缺口。`server/internal/signaling/signaling.go` 里是 `ErrNotImplemented`；`health` 端点的 `unimplemented` 列表里也写着 |
| **群成员「移除」的界面入口** | 协议层**有**（`protocol/mls/group/removal_test.go`），客户端**没有按钮** | 加人已经能用了，移除只差一个界面入口 |
| **服务端二维码渲染** | — | **设计上不做**：画二维码要引入第三方库，会破坏"零依赖" |
| **`/metrics` 在 8443 上** | — | 指标端点在**另一个端口**（默认 `127.0.0.1:9090`），`/metrics` 在 8443 上返回 404。这是有意的 |
| **部分 MLS proposal 类型** | `protocol/mls/messages/proposal.go:143` | 用 `ErrNotImplementedYet` **明确拒绝**而不是猜着编码。这是设计，不是缺陷 |

### 3.2 未验证（代码有，但从没在真实条件下跑过）

| 事项 | 现状 | 风险 |
|---|---|---|
| **群聊的双机真机验证** | 协议层有端到端测试，客户端编译通过，**但两台手机互相加人从未实际跑过** | **最高**——这是客户端唯一一块"逻辑测过、界面没过"的地方 |
| **相机扫码** | `ui/qr/QrScannerScreen.kt` 存在且编译通过 | `AppInfo.kt` **自己承认**："相机扫码路径**未在真机上验证过**：构建环境没有摄像头，只能保证编译通过" |
| **MLS `UpdatePath` / `Welcome` 的互操作性** | 有自洽性测试与端到端测试，**但没有官方逐字节向量** | 与**其它 MLS 实现**互通未经第三方验证。`SECURITY.md` 里写明了 |
| **release 构建的体积** | 只测过 debug（37.4 MB） | R8 开启后的体积未知；`README.md` 明说"在测出来之前不声称 release 体积" |

> **写这一节的理由**：这个项目里最容易犯的错误，是把"编译通过"当成"能用"，把"自洽性测试通过"当成"互操作正确"。上面每一条都标了它到底证明了什么。

---

## 4. 仓库结构

```
schat/
├── SCHAT.md            主设计文档（115 KB）：架构、SCS-1 规格、资源预算、用户须知
├── README.md           给访客看的：特性、能力表、构建步骤
├── SECURITY.md         威胁模型、漏洞报告流程、**运维方能看到什么**
├── CONTRIBUTING.md     如何参与——里面写的是这个项目真实的经验教训
├── LICENSE             AGPL-3.0 全文
├── go.work             Go workspace（只有 protocol 与 server）
│
├── protocol/           SCS-1 协议核心（Go，客户端侧；**服务端刻意不依赖它**）
│   ├── *.go            SCS-1 单聊协议本身
│   ├── mls/            IETF MLS (RFC 9420) 实现
│   └── mobile/         gomobile 绑定层（产出一份 AAR 给安卓）
│
├── server/             中继服务器（Go，单二进制，零第三方依赖）
│   ├── cmd/            可执行入口
│   ├── internal/       各内部包（见第 6 节）
│   ├── Dockerfile
│   └── schat-server.service   systemd 单元（加固到只读根文件系统）
│
├── android/
│   ├── core/           **纯 JVM 模块**，无 Android 依赖（见第 7.1 节）
│   └── app/            Android 绑定与 Compose 界面（见第 7.2 节）
│
├── docs/               15 份文档（见第 9 节）
├── tools/              构建与验证脚本
└── assets/icon/        图标源文件
```

**注意两个空目录** ✗：`android/data/` 与 `android/feature/` 里**一个源文件都没有**——是重构留下的残留。可以删，但删之前确认没有构建脚本引用它们。

---

## 5. `protocol/` —— 协议核心（Go）

### 5.1 包

| 包 | 职责（取自它自己的包注释） |
|---|---|
| `protocol` | 实现 SCS-1，SChat Secure Protocol 本身 |
| `protocol/mls/crypto` | MLS 密码套件与带标签的密码学操作 |
| `protocol/mls/tls` | MLS 的表示语言（TLS 语法） |
| `protocol/mls/tree` | RFC 9420 附录 C 的数组式棘轮树；节点编解码 |
| `protocol/mls/messages` | 提案、提交与分帧层 |
| `protocol/mls/schedule` | MLS 密钥调度（RFC 9420 §8） |
| `protocol/mls/secrettree` | MLS 秘密树与发送者棘轮 |
| `protocol/mls/group` | **把各层绑成一个 epoch**：树、密钥调度、转录、提案 |
| `protocol/mls` | ⚠️ 包注释写着 "**will implement**"——**这是过时的**，MLS 已经实现 |
| `protocol/mobile` | gomobile 绑定层：给安卓用的导出函数面 |

### 5.2 `protocol/mls/group/` 里最值得先读的文件

| 文件 | 作用 |
|---|---|
| `epoch.go` | `Epoch` 结构；`ProcessCommit`（接收方如何应用一条提交） |
| `commit.go` | `CreateCommit`（发送方如何造一条提交）与 `commit_secret` 的来源 |
| `join.go` | `AcceptWelcome`——**入群者的叶子下标在这里被推导出来** |
| `create.go` / `proposals.go` | 提案的收集与应用（`applyProposalEffects` 是**共享**实现） |
| `application.go` | `SealApplication` / `OpenApplication`（群消息的加解密） |
| `welcome.go` | `BuildWelcome`（邀请信封的构造） |
| `snapshot.go` | 状态的序列化——**`PrivateNodes` 必须跟着快照走**，否则重启后跟不上群 |
| `privatenodes.go` | `derivePrivateNodes`：入群者从路径秘密推导私有节点 |

### 5.3 `protocol/mobile/` —— gomobile 边界

这一层是**给 Kotlin 用的**，每个导出函数都对应客户端的一个动作：

| 文件 | 导出面 |
|---|---|
| `mobile.go` | 身份、预密钥、`PublishBundleJSONWithKeyPackage` |
| `group.go` | `GroupCreate` / `GroupKeyPackage` / `GroupStateSummary` |
| `groupadd.go` | `GroupAddMember`（发送方加人） |
| `groupwelcome.go` | `GroupProcessWelcome`（**入群，三参数，不需要下标**） |
| `groupcommit.go` | `GroupProcessCommit`（接收方应用提交） |
| `groupmessage.go` | `GroupSeal` / `GroupOpen`（群消息） |
| `groupcommitwire.go` | `0x05` 信封：`WrapGroupCommit` / `UnwrapGroupCommit` / `GroupMyLeaf` |
| `groupwelcomewire.go` | `0x04` 信封 |
| `groupwire.go` | `0x03` 信封 |
| `grouproute.go` / `groupmailbox.go` | 群信箱令牌的派生 |

> ⚠️ **最重要的一条交接信息**：**只要你在 `protocol/mobile/` 里新增了一个导出函数，就必须重建 AAR**，否则 Kotlin 侧会报 `Unresolved reference`——那个错误看起来像"我写错了代码"，实际是"绑定层没有这个符号"。
>
> 重建命令：`powershell -ExecutionPolicy Bypass -File tools/build-protocol.ps1`
> 耗时：**约 270–300 秒**（有缓存时）；首次或清理后可能 **900 秒**。

### 5.4 跑测试

```bash
cd protocol
go build ./... && go test ./...
go test -race ./...        # CI 里也跑这个
```

⚠️ **必须在 `protocol/` 目录内跑**。从仓库根目录跑 `go build ./...` 会被 Go 拒绝（`directory prefix . does not contain modules listed in go.work`）。

---

## 6. `server/` —— 中继服务器（Go）

### 6.1 包

| 包 | 职责 |
|---|---|
| `internal/config` | 加载与校验服务器设置（JSON，不是 YAML——YAML 会引入第三方依赖） |
| `internal/gateway` | 终结客户端连接、搬动不透明信封 |
| `internal/router` | 把投递令牌映射到活动连接 |
| `internal/queue` | 有界的、只在内存里、永不落盘的邮箱（`buffer` 模式） |
| `internal/directory` | 发布与提供公开预密钥包（**只存公钥材料**） |
| `internal/ws` | 一个最小的服务端 WebSocket 实现（**自己写的**，为了零依赖） |
| `internal/tlsutil` | TLS 配置；**自签名证书的生成与持久化** |
| `internal/metrics` | 聚合计数器 |
| `internal/signaling` | WebRTC 信令（**未实现**，`ErrNotImplemented`） |
| `internal/version` | 构建标识（`Version` / `Commit` / `Protocol`） |
| `internal/wstest` | 测试用的最小 WebSocket 客户端 |

### 6.2 两条结构性主张（CI 里各有一条检查）

```bash
cd server
GOWORK=off go list -m all | tail -n +2        # 必须是空的：零第三方依赖
GOWORK=off go list -deps ./... | grep Schat/protocol   # 必须无输出：不含解密代码
```

**第二条不是风格问题**：服务器能看到全部密文与元数据，它唯一能给出的隐私保证是"读不懂"。一旦它导入了协议核心，那个保证就只剩一句承诺。

### 6.3 部署

三种方式都写在 `docs/SERVER-SETUP.md` 里（那份文档我逐条实测过，见第 10.6 节）：

- **单二进制 + systemd**（推荐）：交叉编译 `GOOS=linux GOARCH=amd64`，`scp` 上去
- **Docker**：`server/Dockerfile`，最终镜像里只有一个静态二进制
- **反向代理终结 TLS**：Caddy 零配置；⚠️ 但此时 `--public-host` **不生效**（见第 10.6 节）

**已经部署了一台**：阿里云 ECS `ecs.e-c1m2.large`（2 核 4 GiB，Ubuntu 22.04，公网 IP `47.114.40.65`），systemd 方式，实测内存 **2.7 MB**。

### 6.4 跑测试

```bash
cd server
go build ./... && go test ./...
```

---

## 7. `android/` —— 客户端（Kotlin + Jetpack Compose）

### 7.1 `:core` —— 纯 JVM 模块（无 Android 依赖）

**这个模块存在的理由是具体的**（`android/core/build.gradle.kts` 里写着）：最初的代码住在 `:app` 里，和 gomobile 的 AAR 待在一起，结果单元测试**根本跑不起来**——Gradle 的测试执行器加载整个运行期 classpath，gomobile 生成的 `go.Seq` 类在静态初始化时破坏那个 classpath，JVM 带着一个由 PATH 片段拼出来的 `ClassNotFoundException` 死掉。

**教训不是"绕开 AAR"，而是：不依赖 Android 的逻辑，不该被编译进一个依赖 Android 的模块。** 一个只在插着设备时才跑的 40 项测试，实际上就是跑不起来的测试。

它**只依赖 Kotlin 标准库**。

| 文件 | 职责（取自它自己的文档注释） |
|---|---|
| `ServerConfig.kt` | 解析后的 `schat://connect?...` 服务器描述符 |
| `contacts/Contact.kt` | 本机记住的一个联系人；`displayName` = 备注名，无备注时用身份缩写 |
| `contacts/ContactList.kt` | 联系人列表上的操作 |
| `crypto/Vault.kt` | 从 SCS-1 协议核心派生密钥材料 |
| `crypto/VaultSession.kt` | **不保密**的那部分保管库参数 |
| `groups/GroupStore.kt` | 一个群在本机保存的全部内容（状态、棘轮代数、成员备注名、消息） |
| `net/RelayClient.kt` | 中继协议的客户端一半 |
| `net/DirectoryClient.kt` | 经中继发布与获取预密钥包 |
| `net/PinnedTrust.kt` | 针对自签名中继的**证书固定** |
| `onboarding/Onboarding.kt` | 首次引导的状态机 |
| `profile/ClientProfileStore.kt` | 一个可用客户端需要的一切，打包成不透明的字符串束 |
| `qr/QrCode.kt` | 二维码的编码与解码 |
| `qr/QrPayload.kt` | 一个 SCHAT 二维码能承载什么 |
| `data/store/EncryptedStore.kt` | 文件支撑的键值存储，值用 **AES-256-GCM** 加密 |

**测试**：`android/core/src/test/` 下 11 个测试文件，共 194 项。

### 7.2 `:app` —— Android 绑定与界面

| 文件 | 职责 |
|---|---|
| `SchatApplication.kt` | 应用入口 |
| `MainActivity.kt` | 唯一的 Activity |
| `AppInfo.kt` | 这个构建的静态事实，显示在状态页；**它诚实地列出了未验证的功能** |
| `app/AppWiring.kt` | **把所有东西接起来**的地方：引导流程、单聊界面、群界面的分支（`GroupRoute`/`ChatRoute`） |
| `chat/ChatController.kt` | 会话控制器：收发、投递状态、内容类型分发（`0x01`–`0x05`） |
| `chat/GroupController.kt` | 群组功能的 Kotlin 门面（`mobile.Mobile` 的包装） |
| `core/crypto/AndroidDeviceKeyProvider.kt` | 保管库硬件绑定的 Android 实现 |
| `core/crypto/GoKeyDeriver.kt` | 生产用的 `KeyDeriver`，由 Go 里的 SCS-1 协议核心支撑 |
| `ui/onboarding/OnboardingScreen.kt` | 首次运行流程（口令、恢复码、**配置服务器**） |
| `ui/chat/ChatScreen.kt` | 单聊界面；「群组」与「新建群」按钮在这里 |
| `ui/chat/ContactRows.kt` | 会话列表 |
| `ui/chat/GroupScreen.kt` | 群会话界面（顶栏：返回｜群名｜加人；下方是成员名单） |
| `ui/chat/GroupListScreen.kt` | 群列表 |
| `ui/chat/GroupAddMemberScreen.kt` | 选一个人加进群 |
| `ui/qr/QrImage.kt` | 渲染二维码模块矩阵 |
| `ui/qr/QrScannerScreen.kt` | 相机扫码（**未在真机验证**） |
| `ui/theme/Theme.kt` | 主题：白/蓝/黑三族的 Material3 配色、字阶、形状 |
| `ui/theme/DesignTokens.kt` | 颜色、间距、圆角三个令牌对象；**界面里的裸 `.dp` 和 `Color(0x…)` 应当只有这一处** |
| `ui/theme/Gradients.kt` | 全部渐变（页面底、顶栏、按钮、气泡、卡片描边）与"呼吸"动画值 |
| `ui/ui/Components.kt` | 界面零件：`ScreenBackground`／`ScreenHeader`／`GradientCard`／`GradientButton`／`GhostButton`／`BarAction`／`StatusPill`／`UnreadPill`／`GradientAvatar`／`ProgressBar`／`CheckOption`／`MonoBlock`／`FadeSwap` |

**关于界面层本身**（这一段是给下一位改界面的人的）：

- **所有颜色只来自 `DesignTokens.kt`**，且只用白、蓝、黑三族；红色是语义色（错误、失败、
  元数据警告），不作为装饰。没有主题引擎，也没有动态取色——能重新给界面上色的通道，
  同时也是能用来伪装界面的通道。
- **动画只动颜色、位移与绘制坐标**，不动布局尺寸（唯二的例外是 `ProgressBar` 的填充宽度
  和 `GradientButton` 的按钮高度）。布局尺寸的动画会带来整屏重排，那看起来是卡，不是流畅。
  时长：转场 200ms、气泡入场 240ms、按压反馈 140–180ms、背景呼吸 12–14 秒。
- **换屏动画的键必须是"真的换了一屏"**：`SchatRoot` 用 `Stage`，`ChatScreen` 用对端身份。
  用连接状态当键会让界面随每一次状态更新闪烁。
- **改过界面代码后必须 `--rerun-tasks`**（见第 10.3 节），并且 `MaterialTheme.shapes` 的类型
  是 Material3 自己的 `Shapes`——往它上面加属性是不行的，需要胶囊形时显式用
  `SchatShapes.Pill`。

### 7.3 构建与测试

```bash
cd android

# 客户端核心（纯 JVM，不需要 Android SDK）——194 项
./gradlew :core:test

# 编译客户端
./gradlew :app:compileDebugKotlin

# 出包
./gradlew :app:assembleDebug
```

⚠️ **改过界面代码后，用 `--rerun-tasks` 验证**：
```bash
./gradlew :app:compileDebugKotlin --rerun-tasks
```
理由见第 10.3 节：增量编译会给出**假绿**。

### 7.4 信封内容类型（客户端与服务器的契约）

| 类型 | 内容 | 投向 |
|---|---|---|
| `0x01` | SCS-1 单聊帧 | 对端信箱 |
| `0x02` | SCS-1 握手 | 对端信箱 |
| `0x03` | MLS 群消息 | **群信箱**（由 epoch 派生） |
| `0x04` | MLS Welcome | **新成员个人的**信箱（它还没进群，推不出群信箱） |
| `0x05` | MLS 提交（commit） | **群信箱** |

**服务器从不检查内容类型**——它只按投递令牌转发。这一点由 `server/internal/gateway/` 的测试和"不导入协议核心"这条检查共同保证。

---

## 8. `tools/` 与构建

| 脚本 | 作用 |
|---|---|
| `tools/build-protocol.ps1` | **用 gomobile 构建 `schat-protocol.aar`**（三个 ABI：arm64-v8a / armeabi-v7a / x86_64）。**新增 `protocol/mobile` 导出后必须重跑** |
| `tools/verify.ps1` | 一键自检：构建 + 全套测试 + 服务端两条结构性主张 |
| `tools/fetch-mls-vectors.ps1` | 抓取官方 MLS 测试向量到 `protocol/mls/vectors/`（**该目录被忽略，不可再分发**——上游仓库没有附许可） |
| `tools/make-icon.ps1`、`prepare-icon-master.ps1` | 图标生成 |
| `tools/measure-relay-load.ps1` | 测量中继的每连接内存成本 |

**已知的构建事实**（实测）：

- AAR 体积 **10.18 MB**，构建耗时 **270–300 秒**（有缓存）/ 约 **900 秒**（首次）
- debug APK **37.4 MB**（含三个 ABI 的原生库）
- **`lib/x86/libgojni.so` 缺失**——只有 **32 位 x86 模拟器**会崩，arm / arm64 / x86_64 都正常

---

## 9. 文档地图

| 文档 | 内容 |
|---|---|
| `SCHAT.md` | **主设计文档**（115 KB）：架构、SCS-1 协议规格、资源预算、用户须知 |
| `README.md` | 给访客看的：特性、能力表、构建步骤 |
| `SECURITY.md` | 威胁模型、漏洞报告流程、**运维方能看到什么** |
| `CONTRIBUTING.md` | 如何参与；包含这个项目真实的经验教训 |
| `docs/PROTOCOL-SPEC.md` | SCS-1 协议实现规格（供第三方复现与审计） |
| `docs/RELAY-API.md` | **客户端↔服务端线协议**：`/ws` 消息格式、二进制信封、预密钥目录接口 |
| `docs/MLS-PLAN.md` | MLS 实现计划：里程碑、逐字节验收标准、风险 |
| `docs/MLS-M3B-HANDOFF.md` | M3B 阶段的交接记录 |
| `docs/MLS-M4-HANDOFF.md` | **M4（群聊接收方）的交接记录**——与本文档互补，建议一起读 |
| `docs/THREAT-MODEL.md` | 威胁模型与安全边界 |
| `docs/SERVER-SETUP.md` | **服务器部署与客户端连接教程**（逐条实测过） |
| `docs/LAN-TESTING.md` | 局域网测试指南 |
| `docs/DEVICE-TEST.md` | 真机测试清单 |
| `docs/BUILDING.md` | 各组件构建指南与一键自检 |
| `docs/FAQ.md` | 常见问题 |

---

## 10. 已知的坑（这一路上真实踩过的）

> 这一节是这份文档里**最有价值**的部分。每一条都造成过实际的返工。

### 10.1 **注释不可全信** ✗

这个项目的注释写得很多（解释"为什么"），但有**几处已经过时**，而且**没有任何东西在检查它们**：

| 位置 | 它说什么 | 实际 |
|---|---|---|
| `protocol/mls/`（包注释） | "**will implement** the IETF MLS protocol" | **已经实现了** |
| `protocol/mls/messages/create.go:48` | "the KeyPackage layer, **which is not implemented yet**" | KeyPackage 已实现 |
| `protocol/mls/messages/create_test.go:23` | "which this project **has not implemented**" | 同上 |
| `server/internal/version/version.go`（已修） | "These are overridden at build time with `-X`" | 曾经是 `const`，`-X` **完全无效且不报错** |
| `go.work`（已修） | "server/go.mod carries a replace directive" | `server/go.mod` **没有** replace |

**教训**：**一个没有人核对的主张，和一句谎话的作用是一样的。** 接手时如果某条注释与代码冲突，**信代码，并顺手修掉注释**。

### 10.2 **`-ldflags -X` 只能设置变量，对 `const` 静默无效** ✗

`server/internal/version/version.go` 里原本是 `const (Version = ...)`，而 `Dockerfile` 里写着 `-X ...Version=${VERSION}` —— **`-X` 对 `const` 什么也不做，且不报任何错**。所以"Docker 镜像里注入了版本号"这句话曾经是假的。已改成 `var`，并用运行结果证明（注入 `9.9.9-PROOF` 后 `--version` 打印出来了）。

### 10.3 **增量编译会给出假绿** ✗

给 `GroupScreen` 加了一个必填参数、而调用点没跟着改，`./gradlew :app:compileDebugKotlin` **仍然报告成功** ✗——因为那个调用点所在的文件**没有被重新编译**。

**规则：宣称"能编译"之前，用 `--rerun-tasks` 强制全量重编一次。**

### 10.4 **测试如果给了代码一个现实中不存在的输入，它证明的只是"代码在虚假输入下自洽"** ✗

这是这个项目里**代价最大**的一课。

有 **8 处测试**曾经把**发送方的 commit secret 直接传给接收方**——那是现实中不可能发生的输入（接收方只能自己从路径派生）。结果：

- **297 项测试全绿**，而"经邀请入群的成员能否跟进后续群变更"**完全不可用**
- 把那些调用改成 `nil`（现实中的样子）之后，**5 条立刻变红**，**一轮就定位到真因**

**所以：写测试前先问"这个输入在现实中从哪来"。**

顺带说：`controller.addMemberToGroup` 那条链路（加人 → 发提交 → 发 Welcome → 对方入群）**至今没有端到端测试**，只在编译层验证过。

### 10.5 **"错误出现在第 N 步"不等于"第 1..N−1 步都成功了"** ✗

函数可能在第 N 步之前就**提前返回**了，而后续步骤照常执行。这个项目里**两次**缺陷是这一形状（一人群的空路径、无路径提交的 commit secret），两次的症状都是"确认标签不匹配"——一个指向密钥调度、与真正原因毫无关系的错误。

**排查时先确认前置步骤真的执行过**（加一行 `println` 或长度检查），再解释后置步骤的错误。

### 10.6 **`--public-host` 只在 `--listen` 是 `0.0.0.0` 时生效** ✗（实测）

```
--listen 0.0.0.0   + --public-host 203.0.113.10   →  h=203.0.113.10  ✓
--listen 127.0.0.1 + --public-host chat.example.com →  h=127.0.0.1     ✗ 被忽略
```

不加 `--public-host`（或加了但监听具体地址）时，连接 URI 里会写 `localhost`——**手机配置完之后连的是手机自己**，而症状看起来像"服务器没起来"。

**反向代理部署要特别注意这一条。**

### 10.7 证书在什么情况下会变（实测）

同一个 `--state-dir`、同一组参数下，证书是**复用**的（启动日志写 `reusing the persisted self-signed certificate`，连续三次启动指纹完全相同）。

**但这三者任一变化都会换指纹**，已固定指纹的客户端需要重新配置：`--name`（名字写进证书）、`--listen`（地址写进 SAN）、`--state-dir`（换目录就是换状态）。

### 10.8 **CRLF / LF 混用** ✗

这个仓库在 Windows 上开发。行尾混用造成过真实损失：

- 用文本匹配改代码时**锚点匹配不上**，而失败信息看起来像"代码变了"
- **`.gitignore` 的规则行里混进一个 `\r`，那条规则会完全失效**——五条规则一起失效过，查了三轮才找出来

现在 `.gitattributes` 已统一为 LF。**但你自己写脚本改文件时仍要注意**：`[System.IO.File]::ReadAllLines` 配 `Trim()` 比较比正则可靠。

### 10.9 **`crypto.DeriveKeyPair` 不是"由私钥求公钥"** ✗

它的参数是**用来派生的 ikm**。把私钥喂进去会得到**一把无关的密钥对**。

**这个错误犯过两次**，两次的症状完全相同且都指向别处：测试报告"**树里没有这个成员的叶子**"——而树里完全有。

**由私钥求公钥用 X25519 标量乘法**：`ecdh.X25519().NewPrivateKey(priv).PublicKey().Bytes()`。

### 10.10 推送问题（这台开发机的环境）

如果 `git push` 失败，按顺序检查：

1. **`git` 不使用 Windows 的系统代理** ✗ —— 必须显式配置：
   ```powershell
   git config --local http.proxy http://127.0.0.1:7890
   git config --local https.proxy http://127.0.0.1:7890
   ```
2. **`schannel` 的证书吊销检查在代理后面会失败** ✗（`schannel: failed to receive handshake`）：
   ```powershell
   git config --local http.schannelCheckRevoke false
   ```
   ⚠️ 这**降低了安全性**（不再验证证书是否被吊销）。网络能直连 GitHub 时应当撤掉。

### 10.11 **`.gitignore` 曾经漏掉整个 `android/core/build/`** ✗

原来的规则只有 `/android/build/` 和 `/android/app/build/`。于是 **273 个编译产物、约 226 MB** 会被提交进去——**而从文件名上完全看不出来**。

现在有一条通配规则 `/android/**/build/`。**新增模块时记得确认它的 build 目录被覆盖。**

### 10.12 **本地开发机的路径与仓库无关的**

`tools/verify.ps1` 等脚本里有本机路径（`D:\Android\Sdk`、`D:\gradle-home`）。`android/local.properties` 被忽略，每台机器各自创建。文档里的路径已泛化成占位符。

---

## 11. 下一步：按优先级

### 优先级 1 —— 真机双机验证群聊（**最该做的**）

**为什么**：`addMemberToGroup` 这条链路（加人 → 发提交 → 发 Welcome → 对方入群 → 群里其他人看到新成员）**逻辑上全都有测试，但界面上从未跑过**。协议层的四个"跟随"场景各有端到端测试，客户端只编译过。

**怎么做**：见 `docs/DEVICE-TEST.md`。两台手机，A 建群 → A 加 B → 确认 B 入群、且若群里有 C，C 也看到 B。

**可能的坑**：**用粘贴，不要用扫码**——相机路径未在真机验证过。

### 优先级 2 —— 富媒体（步骤 7）

唯一一块大功能缺口。需求里的原话是"**每种格式使用不同的加密方案**"（见 `SCHAT.md` 第 5 节）。

**注意成本**：群消息是 **N 份**（MLS 密文对全体成员相同，发送者要逐个投到每个成员的信箱）。10 人群发一个 100 MB 视频 ≈ **1 GB 出网流量**。现有部署是**按流量计费**。

### 优先级 3 —— 让 `:core` 的 CI job 变绿

它现在标着 `continue-on-error: true`。原因写在 `.github/workflows/ci.yml` 里：`:core` 自己不需要 Android SDK，但 `settings.gradle.kts` include 了 `:app`，而 `:app` 声明 `compileSdk 37`——GitHub runner 预装的 platform 不一定有 37。

**可以做的**：
- 在 CI 里装 platform 37（要网络，可能又慢又脆）
- 或者把 `:core` 拆成独立的 Gradle 构建（更彻底，但要改 `settings.gradle.kts` 结构）
- 或者接受它，并在 `README.md` 的能力表里如实标注

### 优先级 4 —— 群成员「移除」的界面入口

协议层已经有（`removal_test.go`），客户端只差一个按钮 + 调用。参考「加人」的实现（`GroupAddMemberScreen.kt` + `ChatController.addMemberToGroup`）。

### 优先级 5 —— 服务端管理界面（用户提过，未开工）

零依赖、仅回环、`/admin` 状态页：状态、12 项指标、连接 URI + 二维码、隐私说明。约束是**不能引入第三方依赖**（服务端零依赖是硬约束），所以 HTML/CSS/JS 要手写并用 `go:embed` 打包；二维码渲染如果要做，得自己实现——**这正是服务端「不画二维码」这条设计的原因**，要重新评估这个取舍。

### 优先级 6 —— 互操作性验证

`UpdatePath` / `Welcome` / 群消息**没有官方逐字节向量**，所以与**其它 MLS 实现**的互通未经第三方验证。要验证需要引入另一个 MLS 实现（很长一段时间内这会是唯一的办法）。`SECURITY.md` 里已如实写明这一点。

### 优先级 7 —— `android/data` 与 `android/feature` 两个空目录

删掉，或确认它们没有构建脚本引用。

### 顺手可以修的过时注释

`protocol/mls` 包注释的 "will implement"、`protocol/mls/messages/create.go:48`、`create_test.go:23`（见 10.1 节）。

---

## 12. 怎么开始（具体命令）

```bash
# 1. 克隆
git clone https://github.com/AyanamiRei-lu/Schat.git
cd Schat

# 2. 跑一遍全套（这是最快建立信心的方式）
cd protocol && go build ./... && go test ./...
cd ../server && go build ./... && go test ./...
cd ../android && ./gradlew :core:test

# 3. 或者一把梭（PowerShell，Windows）
powershell -ExecutionPolicy Bypass -File tools/verify.ps1
```

**环境要求**：

| 组件 | 版本 | 备注 |
|---|---|---|
| Go | **1.27** | 两个模块的 `go.mod` 都写着 1.27 |
| JDK | **25** | AGP 9.x 与 Gradle 9.5 的要求。**不是 17** —— `README.md` 曾写错，已修 |
| Android SDK | platform 37 + build-tools 37 | 位置写进 `android/local.properties`（该文件被忽略） |
| PowerShell | 5.1+ | `tools/*.ps1` 用 |

**两个最容易浪费时间的地方**：

1. **Go 命令必须在模块目录内跑**（`protocol/` 或 `server/`），不能从仓库根目录跑——根目录有 `go.work` 但根目录本身不属于任何 workspace 模块。
2. **改了 `protocol/mobile/` 的导出面，必须重建 AAR**（约 5 分钟），否则 Kotlin 报 `Unresolved reference`，看起来像代码错误。

---

## 附：这份文档里"已通过"的数字，怎么自己重新验证

| 数字 | 命令 |
|---|---|
| protocol **305 通过 / 49 子测试 / 1 SKIP** | `cd protocol && go test ./... -count=1 -v` 后数 `--- PASS` 行 |
| server **116 通过 / 32 子测试** | `cd server && go test ./... -count=1 -v` |
| `:core` **194 通过 / 4 SKIP** | `cd android && ./gradlew :core:test`；或数 `android/core/build/test-results/test/*.xml` |
| APK **37.4 MB** | `./gradlew :app:assembleDebug` 后看 `android/app/build/outputs/apk/debug/` |
| AAR **10.18 MB** | `tools/build-protocol.ps1` 的输出 |
| 部署内存 **2.7 MB** | 服务器上 `systemctl status schat-server` |

**如果某个数字对不上，先怀疑数字，再怀疑代码**——这个项目里两者都错过。
