# SCHAT

**完全开源、可自建服务器的安卓端到端加密聊天软件。**
服务器只负责转发密文信封 —— 它不保存、也无法读取任何消息、文件或通讯录。

> **当前状态：`v0.1.0-alpha` — 单聊与群聊均已实现，客户端已通过真机验证。**
> **已可用**：单聊收发、好友列表、本地留存、二维码互扫、**群聊**（建群 / 加人 / 群消息 / 成员列表）。
> **尚缺**：富媒体（图片 / 视频 / 语音 / 文件，步骤 7）、以及群成员「移除」的界面入口
> （协议层已实现并有测试，只是界面上还没有这个按钮）。
> 代码未经第三方密码学审计，请勿用于高价值机密场景。详见 [`SCHAT.md`](SCHAT.md) 第 11 节。

---

## 快速导航

| 文档 | 内容 |
|---|---|
| [`SCHAT.md`](SCHAT.md) | **主设计文档**：架构、SCS-1 加密协议规格、资源预算、用户须知 |
| [`docs/PROTOCOL-SPEC.md`](docs/PROTOCOL-SPEC.md) | SCS-1 协议实现规格（供第三方复现与审计） |
| [`docs/RELAY-API.md`](docs/RELAY-API.md) | **客户端↔服务端线协议**：`/ws` 消息格式、二进制信封、预密钥目录接口 |
| [`docs/MLS-PLAN.md`](docs/MLS-PLAN.md) | **群聊（MLS, RFC 9420）实现计划**：里程碑、逐字节验收标准、风险与接口 |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | 威胁模型与安全边界 |
| [`docs/SERVER-SETUP.md`](docs/SERVER-SETUP.md) | 服务器部署与客户端连接教程 |
| [`docs/LAN-TESTING.md`](docs/LAN-TESTING.md) | **局域网测试指南**：本机实测 IP、逐步命令、防火墙、安卓明文流量坑、排查清单 |
| [`docs/BUILDING.md`](docs/BUILDING.md) | 各组件构建指南与一键自检 |
| [`SECURITY.md`](SECURITY.md) | 漏洞报告流程与审计者指南 |
| [`docs/FAQ.md`](docs/FAQ.md) | 常见问题 |

## 特性

- **端到端加密**：SCS-1 协议（X25519 + Ed25519 + HKDF-SHA256 + ChaCha20-Poly1305/AES-256-GCM + Argon2id）
- **群组聊天**：基于 IETF **MLS (RFC 9420)**，具备完整前向保密与后妥协安全
- **富媒体**：图片 / 视频 / 语音 / 文件，**每种格式使用不同的加密方案**（见 `SCHAT.md` 第 5 节）
- **零云端留存**：服务器不落盘、不建库、不解密
- **前后端分离**：客户端与服务器可独立构建、独立部署
- **低占用**：服务端空载内存目标 < 20 MB；客户端处理 1 GB 视频峰值内存 < 8 MB
- **完全免费**：无广告、无内购、无遥测、无账号体系

## 当前可验证的能力（步骤 1–5c 实测）

上面列的是**设计目标**。下面是**今天真的能跑起来并已被验证**的部分：

| 能力 | 验证方式 | 结果 |
|---|---|---|
| 协议核心与 MLS 全部层（会话建立、双棘轮、乱序/重放/篡改/反射防护、MLS 各层） | `cd protocol && go test ./...` | ✅ **305 项通过 + 49 项子测试，1 项 SKIP** |
| **MLS 表示层编解码器（步骤 6a / M1）** | `go test ./protocol/mls/...` | ✅ 16 项 + fuzz：RFC 9420 的三个黄金向量逐字节、**非最短编码必须拒绝**、1 GiB 长度声明不分配即被拒 |
| **MLS 密码学基础层（步骤 6a / M2a）** | 官方 `crypto-basics.json` | ✅ **12 项检查逐字节通过**（套件 0x0001 与 0x0003）；未实现套件的向量被计数并报告，不静默跳过 |
| **MLS 密钥调度（步骤 6a / M2b）** | 官方 `key-schedule.json` | ✅ **140 项检查、10 个 epoch 逐字节通过**；4 种链式写法由向量裁决（group context 确实绑进 joiner secret） |
| **MLS 树数学（步骤 6a / M3a）** | 官方 `tree-math.json` | ✅ **8144 项下标关系、10 个树规模逐项通过**（叶子为偶下标、根为 n−1、`Parent` 依赖树大小） |
| 其中 HKDF 正确性 | RFC 5869 附录 A.1 / A.3 **官方测试向量** | ✅ 逐字节一致 |
| 其中 WebSocket 握手正确性 | RFC 6455 §1.3 **官方测试向量** | ✅ 一致 |
| AEAD 篡改检测 | 对密文**逐位翻转**，每一位都必须被发现 | ✅ 全部通过 |
| 服务端：WebSocket 网关、令牌订阅、转发、buffer 模式、TLS | `go test ./server/...` | ✅ **116 项通过**（含子测试 148 项） |
| 预密钥目录 | `PUT`/`GET`/`DELETE`，`GET` 原子消费一次性预密钥 | ✅ 16 并发 goroutine 抢 200 个预密钥，每个恰好发放一次 |
| 客户端核心（纯 JVM 测试） | `.\gradlew.bat :core:test` | ✅ **194 项通过**（另有 4 项集成测试默认 SKIP） |
| **好友列表（仅存本机）** | `:core` 的 `ContactCodecTest` / `ContactListTest` | ✅ 22 项：排序、未读、重命名、删除、序列化，以及"昵称无法伪造出第二条记录" |
| **消息与联系人本地留存** | 杀掉进程重开 | ✅ 启动时重开上次会话并载入历史与棘轮快照 |
| **二维码快联** | `:core` 的 `QrCodeTest` / `QrPayloadTest` | ✅ 18 项：编码→解码往返、负载解析与拒收、行距填充（相机帧的真实形态） |
| **端到端中继** | 两个真实 WebSocket 客户端经服务器互发密文 | ✅ 逐字节一致 |
| **真实服务器预密钥往返（协议层）** | `SCHAT_RELAY_URL=… go test ./mobile/ -run LiveRelay` | ✅ 发布整池 → 取两次拿到**不同**的一次性预密钥 → 建会话 → 双向加解密 |
| **真实服务器往返（客户端网络层）** | `gradlew :core:test "-Pschat.relayUrl=…"` | ✅ TLS 固定 + WebSocket 升级 + 订阅被应答；**错指纹被拒、无指纹被拒** |
| **握手可在中继信封内完成** | `TestFullHandshakeOverTheRelayPayloadFormat` | ✅ MVP 核心链路已跑通 |
| **会话控制器与聊天界面** | `:app:assembleDebug` | ✅ 编译通过并产出 APK（**真机双机对发尚待验证**） |
| **安全码双方均可计算** | `TestBothPeersCanComputeTheSafetyNumber` | ✅ 两侧算出的 60 位数字完全相同 |
| **预密钥整池发布** | `TestPublishBundleJSONCarriesTheWholePool` | ✅ 100 个一次性预密钥一次发布，而非只发布 1 个 |
| 并发安全 | `go test -race ./...` | ✅ 无竞态 |
| 服务端零留存 | `live` 模式连队列都不创建；不落盘 | ✅ 代码结构保证 |
| 服务端零依赖 | `go list -m all`（`GOWORK=off`）仅自身模块 | ✅ 机械校验 |
| 服务端无解密代码 | `go list -deps ./...` 不含协议核心 | ✅ 机械校验 |
| 服务端内存（TLS 开启） | 实测 WorkingSet | ✅ **10.9 MB**（预算 < 20 MB） |
| 服务端体积 | 静态链接单文件 | ✅ **10.64 MB**（预算 < 15 MB） |
| 安卓客户端编译 | `gradlew :app:assembleDebug` | ✅ 干净构建产出 **37.4 MB** debug APK（预算 < 40 MB；含 10.18 MB 协议 AAR 与三个 ABI 的原生库） |

> **APK 体积请以干净构建为准**：增量构建会积累陈旧的 dex 分片（曾把同一个包撑到 28–30 MB），干净构建稳定在 24.6 MB 左右。release 构建（启用 R8）尚未测量，在测出来之前本项目不声称 release 体积。

**群聊已可用**：建群、把联系人加进群、群消息收发、成员名单。**一次加人发出两封信**——一条群变更给群信箱（已有的成员据此更新成员表），一封群邀请给被加者本人的信箱；顺序固定，先让群知道再邀请本人。

**还不能用的部分**：富媒体发送（图片 / 视频 / 语音 / 文件，步骤 7）、群成员「移除」的界面入口、以及把成员下标映射到备注名之外的更多群管理。

> **群聊尚未做真机双机验证**：协议层有端到端测试（含"经邀请入群的成员能否跟进后续群变更"四个场景），客户端也已编译通过，但**两台真机互相加人**这件事还没有实际跑过。这是当前最该做的一次验证。

> ⚠️ **权限变化**：本版本申请 **`INTERNET` + `CAMERA`** 两个权限（此前只有 `INTERNET`）。相机仅在扫码界面启用，画面在内存中解码后丢弃，不保存、不上传；拒绝后仍可手动输入。详见 [`SCHAT.md`](SCHAT.md) 第 12.6 节。
>
> ⚠️ **元数据保护暂缺**：投递令牌的服务端实现已完成，但客户端尚未实现会话内令牌交换。当前由公开身份派生信箱地址，即任何知道你身份公钥的人都能观察到你何时在收发消息（**内容仍受端到端加密保护**）。详见 [`SECURITY.md`](SECURITY.md) 第 3 节。

## 仓库结构

```
schat/
├── SCHAT.md     主设计文档
├── protocol/    SCS-1 协议核心（Go，客户端侧；服务端**刻意不依赖**它）
├── server/      中继服务器（Go，单二进制，零留存，零第三方依赖）
├── android/     安卓客户端（Kotlin + Jetpack Compose）
├── docs/        协议规格、线协议、威胁模型、部署教程
└── tools/       构建与测试向量工具
```

## 开发

前置要求：Go 1.27+、**JDK 25**（AGP 9.x 与 Gradle 9.5 的要求）、Android SDK（platform 37 + build-tools 37）。

```bash
# 协议核心：构建 + 测试（含 RFC 5869 等官方测试向量）
cd protocol && go build ./... && go test ./...

# 服务端（零第三方依赖）
cd ../server && go build ./... && go test ./...
go run ./cmd/schat-server --listen 127.0.0.1:8443

# 安卓客户端（首次需要联网下载依赖）
cd ../android && ./gradlew assembleDebug
```

> **注意**：注意 Go 命令必须在**模块目录内**执行。仓库根目录有 `go.work`，但从根目录执行
> `go build ./...` 会被 Go 拒绝（`directory prefix . does not contain modules listed in go.work`），
> 因为根目录本身不属于任何 workspace 模块。用上面的写法，或直接跑一键自检。

### 一键自检

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify.ps1
```

### 环境变量

Gradle 的依赖缓存默认落在用户目录下的 `.gradle`。若系统盘空间紧张，可以把它重定向到别处：

```powershell
$env:GRADLE_USER_HOME = "D:\gradle-home"
```

Android SDK 的位置由 `android/local.properties` 里的 `sdk.dir` 指定（该文件被忽略，每台机器
各自创建）。

## 许可

**GNU AGPL-3.0-or-later**，见 [`LICENSE`](LICENSE)。

你可以自由使用、修改、分发本软件，但**任何修改后的版本如果对外提供网络服务，必须同样开源**。
这是为了保证 SCHAT 永远保持开源与免费。
