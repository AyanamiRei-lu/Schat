# 步骤 6a：MLS (RFC 9420) 核心实现计划

> 这份文档是**动工前的评审稿**。它说明要做什么、按什么顺序做、每一步的验收标准是什么、以及哪些地方我最可能失败。
>
> 对应的设计决策见 `SCHAT.md` 第 4.6 节与变更记录 v0.2（群聊方案由自研发送者密钥**改为 MLS**，不做安全妥协）。

---

## 0. 一句话说明这一步的规模

**这是整个项目最大的一块。** 前面的单聊、二维码、联系人加起来，规模都比不上它。我把它拆成 6 个可验收的里程碑；**在 M6 之前界面上不会有任何变化**。

我不会做"能用的子集"。不完整的 MLS 在加人/踢人时会**静默**失去它承诺的安全性——用户会以为群聊是安全的，而它已经不是了。那比没有群聊更危险。

---

## 1. 先确认一个关键前提：HPKE 不用自己写

### 进度

| 里程碑 | 状态 |
|---|---|
| **M1 TLS 表示层编解码器** | ✅ **完成**（2026-09-26）：`protocol/mls/tls/`，16 项测试 + fuzz 种子全通过，`gofmt`/`vet` 干净，`tools/verify.ps1` 全绿 |
| **M2a 密码套件与带标签的密码学操作** | ✅ **完成**（2026-09-26）：`protocol/mls/crypto/`，**通过官方 `crypto-basics.json` 逐字节验证**——12 项检查，覆盖套件 `0x0001` 与 `0x0003` |
| **M2b 密钥调度（`KeySchedule`）** | ✅ **完成**（2026-10-01）：`protocol/mls/schedule/`，**通过官方 `key-schedule.json` 逐字节验证**——`GroupContext` 编码 + 全部派生值，**140 项检查、10 个 epoch** 全对（含 `external_pub` 与 exporter） |
| M3 TreeKEM 与树哈希 | ⏳ **下一步**（向量已就位：`tree-math.json`、`secret-tree.json`、`tree-validation.json`） |
| M4 建群、Add/Update/Remove | ⏳ 未开始 |
| M5 Welcome 与入群 | ⏳ 未开始 |
| M6 接中继与界面 | ⏳ 未开始 |

#### M2b 用向量裁决的分歧（读文档会写错的地方）

那条链可以写成 **4 种组合**——两次 `Extract` 的参数顺序 × joiner secret 是否绑定 GroupContext——**每一种都是确定性的、自洽的，且与任何其他实现都不互通**。我查到的一手资料自相矛盾：OpenMLS 的**注释**写 `DeriveSecret(., "joiner")`（空 context），而它的**代码**把 group context 传了进去。

向量给出定论：

```
Extract(init, commit)  +  joiner context = group_context  +  Extract(joiner, psk)
```

即 **group context 确实绑进 joiner secret**（OpenMLS 的代码对、注释过时），且两次 Extract 都是**「前一个秘密当 salt、新熵当 ikm」**。

另一件顺带被证实的事：`external_pub` 与向量逐字节相同，说明 `crypto.DeriveKeyPair`（走标准库 HPKE 的 `KEM.DeriveKeyPair`）与规范一致——**这是 M3 TreeKEM 的前提**，因为每个节点的密钥对都是从 path secret 这样派生出来的。


#### 官方向量当场抓出的两个真实缺陷（已修）

M2a 第一次跑向量就抓到两个错误。**两个都是自洽性完美、靠自测得永远发现不了的类型**：

**① `ExpandWithLabel` 里的 HKDF-Expand 漏了 HMAC。** 我写成了把 `block ‖ info ‖ counter` 直接喂给裸哈希；而 HKDF-Expand 中 **PRK 是 HMAC 的密钥**，不是更多输入。这个错误在内部是确定性的、每个值看着都合理、自测必然全绿——**只有官方的期望字节能戳穿它**。

**② `SignWithLabel` 对向量给的私钥直接 panic。** 向量里的 EdDSA 私钥是 **32 字节 seed**（其格式文档写明 "native byte string representation"），而 Go 的 `ed25519.Sign` 要 64 字节。现在两种编码都接受，长度不对会返回可读错误而不是 panic。

顺带被向量确认的三处细节（**都是我会猜错的**）：`EncryptWithLabel` 把 context 放进 HPKE 的 **`info`** 且 **AAD 为空**；`RefHash` **不加** `"MLS 1.0 "` 前缀（调用方自己带）；`DeriveTreeSecret` 的 context 是 **generation 的四字节大端**。

#### 测试向量的许可与获取方式（重要）

官方向量发布在 `github.com/mlswg/mls-implementations`，**该仓库没有任何 LICENSE 文件**。无许可即默认保留所有权利，所以**不能把这些 JSON 复制进本仓库**。

- `tools/fetch-mls-vectors.ps1` 在本地下载到 `protocol/mls/vectors/`（**已加入 `.gitignore`**，不可能被误提交）；
- 需要向量的测试**在向量缺席时干净跳过**，普通离线 `go test ./...` 仍全绿；
- 测试会**统计并报告**因套件未实现而跳过的向量（当前 0x0002/0x0004/0x0005/0x0006/0x0007 各 1 条），**不做静默跳过**——否则"通过官方向量"会退化成"通过我恰好跑了的那部分"。

M1 的验收结果：RFC 9420 §2.1.2 给出的**三个例子本身就成了黄金向量**（`0x25`→37、`0x7bbd`→15293、`0x9d7f3e7d`→494878333），编码与解码双向逐字节比对通过；边界值 0/63/64/16383/16384/2³⁰−1 的**编码长度**逐一钉死；`0b11` 前缀、非最短编码、截断、向量内尾随字节全部被拒绝；**宣称 1 GiB 长度的向量在分配之前就被拒绝**（用 `testing.Benchmark` 断言每次操作分配 < 4 KiB，而不是只断言"返回了错误"）。

### 已经修正的两处旧设计意图

**① 密码套件不能只实现一个。** `protocol/mls/doc.go` 冻结的是 **`0x0003`（ChaCha20Poly1305）**，理由是它复用 SCS-1 已有的全部原语。这个理由仍然成立，所以**群聊使用 0x0003**。但**官方测试向量绝大多数是 `0x0001`（AES128GCM）**，而 M2–M5 的验收标准是"逐字节通过官方向量"——只实现 0x0003 就没有足够的向量可对。因此**两个套件都要实现**；两者都映射到 `crypto/hpke` 与标准库的 AES-GCM，代价很小。

**② 群消息内容不走 SCS-1 的 AEAD 路径。** `doc.go` 原先写着"MLS 导出密钥喂给 `protocol.GroupEpochKey`，复用 1:1 的 AEAD 矩阵"。那样会**丢掉 MLS 的按发送者棘轮、generation 重放防护与 epoch 内前向保密**——而那正是 RFC 9420 的 `SecretTree` 存在的理由。已改为：群内容走 **MLS 自己的 `PrivateMessage` 帧**（新增中继内容类型 `0x03`）。两套体系保持分离：1:1 走 SCS-1，群走 MLS。

---

### 前提：HPKE 不用自己写

MLS 的每一次加密（path secret、group secrets、key schedule 的 export）都建立在 **HPKE (RFC 9180)** 之上。动手前我核实了 Go 1.27 的标准库：

```
crypto/hpke                       ← 存在，标准库自带
  func DHKEM(curve ecdh.Curve) KEM            // DHKEM(X25519, HKDF-SHA256)
  func HKDFSHA256() KDF
  func AES128GCM() AEAD  /  ChaCha20Poly1305()
  func ExportOnly() AEAD                      // 密钥调度需要
  func (s *Sender) Seal(aad, plaintext []byte)
  func (s *Sender) Export(exporterContext string, length int)
  func (k KEM) DeriveKeyPair(ikm []byte)      // ← 决定性的能力
  func (k KEM) NewPrivateKey([]byte)
```

**这意味着：**

1. **不需要引入任何第三方依赖**，也不需要我手写 HPKE（原本要 ~300 行 + 自带一套 RFC 9180 向量）。
2. `DeriveKeyPair(ikm)` 与 `NewPrivateKey(bytes)` 是**逐字节对齐官方向量的前提**：TreeKEM 的每个节点密钥对都是从 path secret **确定性派生**的，而向量会直接给出 `init_key`、叶子 `encryption_key`、`enc` 等值。没有这两个能力，测试向量永远对不上。
3. 密码套件：**群聊使用 `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`（0x0003）**，复用 SCS-1 已有原语；**同时实现 `0x0001`（AES128GCM）以对齐官方测试向量**。两者都映射到 `DHKEM(X25519)` + `HKDF-SHA256` + 标准库 AEAD + `crypto/ed25519`，**一个外部依赖都不需要**。
4. MLS 只用 HPKE 的 **base 模式**（不用 auth 模式），标准库也不需要 auth 模式——正好。

> 顺带记录：`crypto/mlkem` 也在标准库里。后量子套件（`MLKEM768X25519`）因此是**可用的**，属于 v2 的事，但它不是一个"要换库"的大工程。

---

## 2. 需要新写的东西

| # | 组件 | 内容 | 规模 |
|---|---|---|---|
| 1 | **TLS 表示层编解码** | MLS 的线格式是 TLS 1.3 风格（RFC 8446 §3）：变长向量（1/2/3/4 字节长度）、结构体、枚举、`opaque`。**这是逐字节对齐的基础设施** | ~500 行 |
| 2 | **密码套件与 HPKE 封装** | 把 `crypto/hpke` 包成 MLS 的 `EncryptWithLabel`（`info = "MLS 1.0 " + label`）、`DeriveKeyPair`、签名的统一入口 | ~250 行 |
| 3 | **树数学与树哈希** | `log2`/`level`/`direct_path`/`copath`/**`resolution`**；`tree_hash`、`ParentHash` 链 | ~450 行 |
| 4 | **Ratchet tree 与 UpdatePath** | 节点、叶子、`UpdatePath` 生成与处理、按 copath resolution 加密 path secret | ~700 行 |
| 5 | **密钥调度与 SecretTree** | epoch secrets → `sender_data_secret`/`encryption_secret`/`exporter_secret`/`confirmation_key`/`membership_key`/`init_secret`；joiner/welcome secret；每个发送者的 handshake/application ratchet 与 generation 计数、重放防护 | ~450 行 |
| 6 | **消息结构与编解码** | `KeyPackage`、`LeafNode`、`Proposal`(Add/Update/Remove/PSK/ReInit/ExternalInit)、`Commit`、`Welcome`、`GroupInfo`、`PublicMessage`/`PrivateMessage`、`SenderData`、`ConfirmationTag`、`MembershipTag`、`AuthenticatedContent` | ~1100 行 |
| 7 | **群状态机** | `CreateGroup`、`AddMembers`、`Update`、`Remove`、`Commit` 生成与处理、`ProcessWelcome`、应用消息加解密、成员变更后 epoch 推进 | ~1200 行 |
| 8 | **官方向量测试脚手架** | 向量下载/裁剪/入库 + 逐字节断言 + 失败时定位到第一个不同字节 | ~500 行 + JSON |

**合计约 5000+ 行 Go（不含测试）**，分多轮完成。

---

## 3. 里程碑与验收标准

每一步的验收标准都是**可机械执行**的，不写成"看起来能用"。

### M1 — TLS 表示层编解码器
- 交付：`protocol/mls/tls/`，完整类型（`uint8/16/32/64`、`opaque`、变长向量、嵌套结构体、枚举）
- 验收：
  - 往返编解码测试（含边界：空向量、最大长度、截断输入必须报错而不是 panic）
  - 用向量中出现的真实结构逐字节比对
- **界面上不会有任何变化**

### M2 — 密码套件与密钥调度
- 交付：`protocol/mls/crypto/`（HPKE 封装的 `EncryptWithLabel`/`DeriveKeyPair` + 签名）、`protocol/mls/schedule/`（`KeySchedule`）
- 验收：
  - 向量里的 `joiner_secret`、`welcome_secret`、`epoch_secret`、`epoch_authenticator`、`exporter_secret`、`confirmation_key` **逐字节相同**
  - `init_secret` 链式推进正确：同一个 `init_secret` + 相同 commit 必须得到相同 `epoch_secret`
- **界面上不会有任何变化**

### M3 — TreeKEM 与树哈希（最硬的一块）
- 交付：树数学、`resolution`、`tree_hash`、ratchet tree、`UpdatePath`
- 验收：
  - 向量给出的树结构，其 `tree_hash`、每个节点的 `resolution` **逐字节相同**
  - 相同的 path secret + 相同的树 → **完全相同的 `UpdatePath` 字节**（包括每个 `enc`、每个 `encrypted_path_secret`）
- **界面上不会有任何变化**

### M4 — 建群、Add/Update/Remove 与提交处理
- 交付：`CreateGroup`、proposal/commit 状态机、"被动客户端"处理路径
- 验收：
  - 生成与向量**逐字节相同**的 `public_message` / `commit`
  - 处理向量中的 commit 后，本地 `epoch`、`confirmed_transcript_hash`、`tree_hash`、`epoch_authenticator` 与向量一致
  - 三名成员的群：任一方加密，其余两方都能解出同一明文
  - **踢人后其无法解密新 epoch 的消息**（这是群聊安全性的核心断言）
- **界面上不会有任何变化**

### M5 — Welcome 与入群
- 交付：`KeyPackage` 生成、`Welcome` 处理、joiner 侧状态初始化
- 验收：
  - `welcome` 字节与向量一致
  - **新成员独立算出的 epoch 状态与建群者一致**（`epoch_authenticator` 相同）
  - 新成员能解密建群者随后发送的应用消息
- **界面上不会有任何变化**

### M6 — 接入中继与界面（即步骤 6b）
- 交付：
  - 新增内容类型 `0x03` = MLS 消息（与现有 `0x01` SCS-1 帧、`0x02` 握手并列）
  - 群列表界面：建群、扫码/粘贴加人、显示成员、踢人、群消息收发
  - 成员变更的界面提示（"XXX 已被移出，群密钥已更换"）
- 验收：三人群收发；踢人后其收不到新消息；重启后群状态仍在；**两台真机跑通**

---

## 4. 与现有代码的接口

| 接口点 | 现状 | 这一步需要做的 |
|---|---|---|
| 内容类型 | `0x01` 帧 / `0x02` 握手（`protocol/mobile/session.go`） | 新增 `0x03` = MLS 消息，并在 `docs/RELAY-API.md` 与手机端同步 |
| 中继 | 只按投递令牌转发不透明信封 | **不需要任何改动**（这正是"服务端读不懂内容"的架构价值） |
| 群投递 | — | MLS 密文对全体成员**相同**，因此发送者要把**同一个信封逐个投到每个成员的信箱**，即 **N 份**。这是 MLS 的工作方式，不是缺陷；代价是带宽与延迟，也是将来 P2P 直连的价值所在 |
| 成员身份 | 每个成员的身份公钥 | 群成员的预密钥包仍需从目录获取（用于 `KeyPackage` 之外的一次性会话？不——**群聊不使用 SCS-1 会话**，见下） |
| 密钥体系 | SCS-1 双棘轮（1:1） | 群聊用 **MLS 自己的 SecretTree 与 `PrivateMessage` 帧**，**既不复用** SCS-1 会话，**也不复用**它的 AEAD 路径。两套体系并存：1:1 走 SCS-1，群走 MLS |
| 本地存储 | 保险库键值（`chat.*`） | 新增 `group.<id>` 状态（含 ratchet tree 私钥——**属于密钥材料，必须留在保险库里**） |

> **必须明确**：MLS 的 ratchet tree 私钥与 epoch secrets 是密钥材料。它们和会话快照一样，只能存在于加密保险库里；`SECURITY.md` 里的"快照不防篡改、完整性依赖调用方加密存储"那条限制同样适用于群状态。

---

## 5. 我最可能失败的地方（提前说明）

| 风险 | 说明 | 应对 |
|---|---|---|
| **逐字节对齐官方向量** | 这是最硬的验收标准。任何一个字段顺序、长度编码宽度（1/2/3/4 字节）、签名覆盖范围、transcript 拼接顺序错了，输出就是另一串字节 | 先把 TLS 编解码器做扎实（M1）；每个里程碑都用向量而不是自测自；失败时定位到**第一个不同的字节** |
| **随机性必须可注入** | 向量会指定 `init_key`、叶子 `encryption_key`、`enc` 等全部"随机"值。如果在代码深处直接调用 `crypto/rand`，就永远对不上 | 从第一行代码起就把随机性做成**可注入的接口**，测试注入向量的值，生产用 `crypto/rand` |
| **`resolution` 与 `tree_hash` 的边界** | 空叶子的处理、未填充节点（blank）的规则、父子哈希链，是最容易差一个节点的地方 | 用向量给出的中间值逐步断言，而不是只比最终结果 |
| **PSK 与 extensions** | 官方向量包含 PSK 场景与多种 extension，完整一致性需要支持 `external_psks` | 按向量覆盖范围实现；不支持的场景**明确列出并跳过**，不假装通过 |
| **向量仓库的许可与体积** | 官方向量在 `github.com/mlswg/mls-interop-testvectors`，是 JSON 且体积不小 | 入库前先核对许可并在 `docs/` 注明来源；只裁剪用到的子集 |

---

## 6. 在全部完成之前，什么是不安全的

**在 M6 完成之前，群聊功能不会出现在界面上，哪怕底层已经能跑测试。** 原因：

- 只做到 M4 的状态既不能加人也不能持久化，把它接进界面等于发布一个会丢消息的群聊；
- **成员变更（尤其是踢人）是群聊唯一真正困难的安全属性**。做到 M3 就上线，用户看不到"被踢的人仍然能解密"这种失败——它是静默的。

---

## 7. 需要你确认的三件事

1. **是否接受在 M6 之前界面上没有任何变化**（预计要好几轮）。
2. **是否接受"官方向量逐字节通过"作为验收标准**——它比"能收发"慢得多，但它是唯一能证明 MLS 实现正确的办法。
3. **群聊不复用 SCS-1 会话**（两套密钥体系并存）。这是 RFC 9420 的设计，不是偷懒。

确认后我从 **M1（TLS 表示层编解码器）**开始，并在动手前再说明一次该里程碑的具体内容。
