# MLS M4 交接：状态、缺口与原文位置

> 写于 M4 进行中。这份文档的唯一目的是**让下一轮不必重新摸索**。
> 每一节记录的都是已核实的事实，以及**已知的错误与陷阱**。

---

## 0. 当前状态（可复现）

```
go test ./... -count=1    →  233 通过 / 0 失败 / 1 跳过（8 个包全 ok）
gofmt -l .                →  无输出
go vet ./...              →  无输出
```

| 部分 | 状态 |
|---|---|
| M1 表示层 / M2a 密码学 / M2b 密钥调度 / M3 树与 TreeKEM | ✅ 官方向量验证 |
| M4a–M4c 消息层（proposal / framing / TBS+签名 / 引用缓存） | ✅ 往返 + 否定测试 |
| M4d 建群 | ✅ 已验证（单节点树、直接选定 epoch secret） |
| M4e-1…8 转录哈希 → 双向管线 → 排除集 → 闭环 → 踢人 | ✅ 端到端 |
| M4-R1/R2 树生长/收缩 + 截断接进两条路径 | ✅ 已验证 |
| M4-Add-1/2/3 KeyPackage + `Add` 提案 + `Add` 进 epoch 转换 | ⚠️ **只有 1、2 有测试；3 从未被执行** |
| **M4-W Welcome** | ⏳ **未开始** |
| M4f 中继接线 + 群状态持久化 + 群界面 | ⏳ 未开始 |

---

## 1. 立刻要做的三件事，按顺序

### 1.1 先修 `CreateCommit`，它根本处理不了 `Add`（最高优先）

**`ProcessCommit` 与 `CreateCommit` 现在不对称**，而这不是"没测"，是**已知的错**：

| | 处理 Remove | 处理 Add |
|---|---|---|
| `ProcessCommit` → `applyProposalsAndPath` | ✅ 置空叶子 + 截断 | ✅ 校验 KeyPackage、按需 `Extend`、放最右空位、加入排除集 |
| `CreateCommit` | ✅ 置空叶子（上一轮补的） | ❌ **完全没有** |

具体地，`protocol/mls/group/commit.go` 里：

- effects 循环只有 `case messages.ProposalTypeRemove`，**`Add` 落进 `default` 分支，什么都不做**；
- 生成路径用的 `withNewLeaf` 只替换了发送方自己的叶子，**没有把新成员的叶子放进树里**。

后果：**A 的树里没有 C，而收到这条提交的 B 会把 C 放进树里**——两边对新树哈希的看法不同，`confirmation_tag` 校验必然失败。由于双方跑的是同一份代码，只有在"发送方与接收方走不同分支"时才会暴露，而这正是 `Add` 的情形。

**正确顺序**（照 §7.7 与 §12.4）：

1. 先把 proposals **全部应用**到一棵工作树（`Add` 放置叶子、`Remove` 置空叶子、必要时 `Extend`）；
2. 再把发送方自己的叶子换成新的 `LeafNode`；
3. **在这棵树上**生成 update path（新成员已就位，但**必须排除出路径的收件人**）；
4. 应用路径，然后**截断**（若右子树全空）。

`ProcessCommit` 的 `applyProposalsAndPath` 已按此实现，`CreateCommit` 需要重构成同一顺序——**最好把这段共同逻辑抽成一个函数，两边共用**，因为这次的不对称正来自"两处各写一遍"。

### 1.2 给 `Add` 的 epoch 转换补端到端测试

修完 1.1 之后：两人群 → A 提交 Add（C 的 KeyPackage）→ 检查：

- 树是否按需 `Extend`、C 的叶子是否落在**最右空位**；
- C 是否进入**排除集**（它不该收到 path secret，而应通过 Welcome 入群）；
- **A 与 B 对新 epoch 的密钥是否逐字节一致**（这条会抓住 1.1 那类不对称）。


### 1.2 Welcome（`protocol/mls/messages/welcome.go`）

原文结构（`build/mls-draft.txt` 6120–6140 行）：

```
struct { opaque path_secret<V>; } PathSecret;

struct {
    opaque joiner_secret<V>;
    optional<PathSecret> path_secret;
    PreSharedKeyID psks<V>;
} GroupSecrets;

struct {
    KeyPackageRef new_member;
    HPKECiphertext encrypted_group_secrets;
} EncryptedGroupSecrets;
```

`Welcome` 本体在同一段的**下一屏**（`GroupSecrets` 之后），字段依次是
`CipherSuite cipher_suite;`、`EncryptedGroupSecrets secrets<V>;`、`opaque encrypted_group_info<V>;`
——**必须读原文确认，不要照抄这一行**。

原文语义（6120–6130 行）：

> the joiner_secret is then encrypted to each new member using HPKE. In the same encrypted
> package, the committer transmits the path secret for the **lowest (closest to the leaf) node
> which is contained in the direct paths of both the committer and the new member**.

三处要点：
1. **`joiner_secret`** 是新成员入群的入口（我实现的 `KeySchedule` 已经产出它，且经官方向量验证）；
2. **对称密钥与 nonce 由 `joiner_secret` 派生**（"symmetric key and nonce derived from the joiner_secret"），用于解密 `encrypted_group_info`；
3. **path secret 只发"最低公共节点"那一个**——新成员据此推出自己直接路径上被重置的节点私钥。找这个节点是 Welcome 里最容易写错的一步。

### 1.3 M4f：中继接线 + 群状态持久化 + 群界面

- 中继内容类型 **`0x03`**（`docs/RELAY-API.md` 已预留）；
- 群状态持久化：`EncryptedStore` 已有，但只存单聊会话；
- 界面到这一步才会变（建群/加人/踢人/群消息）。

---

## 2. 这一段的陷阱（踩过的，别再踩）

| 陷阱 | 现象 | 做法 |
|---|---|---|
| **PowerShell 改源码文件** | `illegal UTF-8 encoding`——`Set-Content` 用系统默认编码（本机 GBK）写盘，UTF-8 文件被写坏 | 一律用 `[System.IO.File]::ReadAllText/WriteAllText` + 显式 `UTF8Encoding($false)` |
| **`gofmt -w` 之后再用 edit 工具** | `file changed since it was read`，编辑被拒 | 先 `read` 再 edit；或改用 PowerShell 正则替换 |
| **通过数突然下降** | 例如 233 → 225，`FAIL=0` 却少了 8 项 | 这是**某个包的测试没编译过**的信号（`go build` 不编译测试文件）。先看 `go build ./...` 再看 `go vet` |
| **`crypto.SignWithLabel` / `VerifyWithLabel` 不接受套件参数** | `too many arguments` | Ed25519 不需要套件；但必须**显式拒绝**用 ECDSA 的套件（0x0002/0x0005/0x0006），否则会本地成功、被所有人拒绝 |
| **凭印象写 MLS** | 本项目已错 **10 次**：HKDF 漏 HMAC、joiner context、根节点下标、`parent_hash` 置空、`treekem.json` 是否存在、PSK 的 nonce、`ProposalRef` 是不是 MAC、`WireFormat` 的宽度、建群是否走 Commit、树是否保持形状 | **先读 `build/mls-draft.txt` 再写代码**。每次照原文改完，向量/测试就一次通过 |
| **写"凑数代码"** | `var _ = crypto.CipherSuite(0)` 之类为了消掉多余 import 的语句（我写过 5 次） | 该删 import 就删 import |

---

## 3. 一处仍未证明的事（不要含糊过去）

**UpdatePath 与 Welcome 都没有官方逐字节向量。** 官方向量集只有 6 个文件
（`crypto-basics` / `key-schedule` / `psk_secret` / `tree-math` / `secret-tree` / `tree-validation`），
全部集中在密码学与树。因此：

- **M4 的证据是自洽性 + 否定测试 + 照原文写的常量**；
- **"与 OpenMLS / mls-rs 互通"没有被验证过**，需要一次互操作测试才能声称。

这条应当写进 `SECURITY.md`，并且在写进去之前不要对外说"群聊可用"。

另：`secret-tree.json` 与 `psk_secret.json` 中，**`secret-tree.json` 尚未被使用**——它是群消息密钥树
（每个叶子每个 generation 的密钥），M6 需要它，而它是**存在的官方向量**，可以立刻用来判定。

---

## 4. 一句总结

M4 的状态机骨架已经完整：**建群、自更新、踢人三条链路端到端验证，加人的消息层与转换已写但转换未测，Welcome 与界面未做**。
剩下的每一块都不缺资料——**原文都在 `build/mls-draft.txt`（9072 行）里**，需要的只是耐心地先读再写。

---

## 5. Welcome 的权威结构（第 32 轮补：原文已核对）

`build/mls-draft.txt` 6130–6180 行：

```
struct {
    CipherSuite cipher_suite;
    EncryptedGroupSecrets secrets<V>;
    opaque encrypted_group_info<V>;
} Welcome;

struct {
    KeyPackageRef new_member;
    HPKECiphertext encrypted_group_secrets;
} EncryptedGroupSecrets;

struct { opaque joiner_secret<V>; optional<PathSecret> path_secret; PreSharedKeyID psks<V>; } GroupSecrets;
struct { opaque path_secret<V>; } PathSecret;
```

**加密方式（这一处凭印象必错）：**

```
encrypted_group_secrets = EncryptWithLabel(init_key, "Welcome",
                                           encrypted_group_info, group_secrets)

group_secrets = DecryptWithLabel(init_key_priv, "Welcome",
                                 encrypted_group_info, kem_output, ciphertext)
```

**HPKE 的 context 是 `encrypted_group_info` —— GroupInfo 的密文本身**，不是群上下文，也不是空。
它把群秘密**绑定到那份具体的 GroupInfo** 上，使其无法与另一份 GroupInfo 拼接。
`init_key` / `init_key_priv` 取自被加入者 KeyPackage 的 `init_key` 字段。

**新成员还需要一棵棘轮树**（原文同段）：树通过 Welcome 携带，通常放在 GroupInfo 的
`ratchet_tree` 扩展（`ExtensionType 0x0002`）里——见 `docs/RELAY-API.md` 与 §12.4.3.1。

**Welcome 的内容与密钥调度衔接**：`group_secrets.joiner_secret` 就是密钥调度里那个
**已由官方向量验证**的 joiner secret；`path_secret` 是"最低公共节点"（committer 与新成员
直接路径的交点中最低的那个）的路径秘密，新成员据此推出自己直接路径上被重置的节点私钥。
**找这个节点是 Welcome 里最容易写错的一步。**
---

## 6. Welcome 生成侧：冲突已解决（第 36 轮）

**§12.4.2 说 `EncryptedGroupSecrets` 封装 "the `init_secret` for the current epoch"，
而字段名是 `joiner_secret`——两者在本实现中是不同的值。原文明细如下。**

判定依据是**新成员如何使用它**（§12.4.3.1，draft 6186 行）：

```
* From the joiner_secret in the decrypted GroupSecrets object and the PSKs specified
  in the GroupSecrets, derive the welcome_secret and using that the welcome_key and
  welcome_nonce. Use the key and nonce to decrypt the encrypted_group_info field.

  welcome_nonce = ExpandWithLabel(welcome_secret, "nonce", "", AEAD.Nn)
  welcome_key   = ExpandWithLabel(welcome_secret, "key",   "", AEAD.Nk)
```

所以**送的就是 `joiner_secret`** ✓。§12.4.2 那句是过时措辞。

**并且这条把已有的构件全部接上了：**

- `welcome_secret` = `DeriveSecret(Extract(joiner_secret, psk_secret), "welcome")`
  —— **正是 `schedule.KeySchedule` 已经产出、且经 `key-schedule.json` 逐字节验证的那个字段**；
- `welcome_key` / `welcome_nonce` 的标签是 **`"key"` 与 `"nonce"`，context 为空串**，
  长度是 **AEAD.Nk / AEAD.Nn**（不是 `KDF.Nh`）；
- GroupInfo 用这对 key/nonce 做 AEAD 加密，其**密文即 Welcome 里每个 `encrypted_group_secrets`
  的 HPKE context**（见第 5 节）——所以 GroupInfo 必须先加密。

**生成侧剩下的未做部分**：最低公共节点的计算（§12.4.2 第一步）、GroupInfo 的结构与签名、
以及把上面这些串起来。
---

## 7. 群消息层规格（第 51 轮取齐，全部逐字来自原文）

`build/mls-draft.txt` 2655–2820 行：

```
PrivateMessage = {
    opaque group_id<V>;
    uint64 epoch;
    ContentType content_type;
    opaque authenticated_data<V>;
    opaque encrypted_sender_data<V>;
    opaque ciphertext<V>;
}

PrivateContentAAD = { group_id<V>; epoch; content_type; authenticated_data<V>; }
SenderData        = { uint32 leaf_index; uint32 generation; opaque reuse_guard[4]; }
SenderDataAAD     = { group_id<V>; epoch; content_type; }
```

### 三处"看起来一样、其实不同"

1. **两个 AAD 不同**：内容密文的 AAD **含** `authenticated_data`；
   发送者数据的 AAD **只含前三个字段**。用同一个 AAD 两边通吃，本地自洽、与其他实现永不互通。
2. **`reuse_guard` 是固定 4 字节**（`opaque reuse_guard[4]`），**不是变长向量**。
   它让 nonce 随机化：`nonce = sender_data_nonce XOR (reuse_guard ‖ 0…)`。
3. **`SenderData.leaf_index` 与 `generation`** 是接收方去 **secret tree** 取棘轮密钥的依据
   —— 也就是 `protocol/mls/secrettree` 里那 656 项官方向量所验证的东西的用途。

### 实现顺序（依赖已全部就位）

1. `SealApplication(epoch, senderLeaf, plaintext)`：取该叶子的**应用棘轮**当前代 → key/nonce →
   `AEAD.Seal(key, nonce XOR reuse_guard, plaintext, PrivateContentAAD)`；
2. 发送者数据：`AEAD.Seal(senderDataKey, senderDataNonce, SenderData, SenderDataAAD)`
   —— sender data 的键由 `sender_data_secret` **与密文样本**共同派生（见第 6/9 节）；
3. `OpenApplication`：先解发送者数据拿到 `leaf_index`/`generation`，再取对应棘轮密钥解内容；
   代**必须**用消息里的 generation，不能用本地棘轮位置——否则乱序消息全部解不开；
4. **§9.2 的删除时间表**：用过即删；未用过的可短期保留以支持乱序投递。

### 否定测试（与官方向量等价的证据）

篡改密文 1 bit、篡改 AAD、换 epoch、换 group_id、**重放同一条消息**（同 generation 的密钥
已被消费 → 必须失败）、错代 generation、非成员用它没有的棘轮。
---

## 8. 客户端接入的依赖链（第 59、60 轮查明）

### 8.1 `protocol/mobile` 里没有任何群组 API

64 个导出函数**全部是 1:1（SCS-1）**：身份、预密钥池、bundle、会话、中继封装、安全码、保险库、信箱令牌。
**没有一个与 MLS 群组有关。** 所以 `:core`（Kotlin）目前**造不出群、也读不了群**。

### 8.2 绑定的直接前置：`Epoch` 的状态序列化

`protocol/mls/group.Epoch` 目前**没有序列化**。而 gomobile 绑定必须在两次调用之间保持群状态
（建群 → 加人 → 收发），所以顺序是：

| 顺序 | 内容 | 说明 |
|---|---|---|
| **1** | **`group.Epoch` 的序列化**（JSON 或二进制） | 需要保存：`Number`、`Suite`、**棘轮树**（含每个节点的密钥/父哈希/未合并叶子）、`GroupContext`、**epoch 密钥**、**转录哈希**、自己的叶子与私钥材料 |
| 2 | `protocol/mobile/group.go` 的导出函数 | `GroupCreate` / `GroupKeyPackage` / `GroupAddMember` / `GroupProcessWelcome` / `GroupSeal` / `GroupOpen` / `GroupStateJSON` / `GroupRestore` |
| 3 | `:core`：发布/获取 KeyPackage（**服务端字段已就绪**）、构造 `0x03` 信封（**服务端不检查类型，已验证**） | |
| 4 | 群状态持久化（`:core` 快照版本 3） | |
| 5 | Compose 群界面 | |

### 8.3 序列化的两条硬要求

- **密钥材料必须能被子进程/进程重启还原**，所以不能只存派生值：`EpochSecrets` 的每个字段、
  棘轮树的节点密钥、以及**本地棘轮的当前位置**都要存，否则重启后收不到乱序消息；
- **快照版本要显式**，旧版本**拒绝而不迁移**（与 1:1 会话快照版本 2 的既有规则一致）；
- §9.2 的"用过即删"与"为乱序保留"之间存在张力：**存下来的棘轮密钥越少越安全，越少越容易漏收**。
  这个取舍要在实现时明确写出来，而不是默默选了保守或激进的一边。
---

## 9. 客户端接入的陷阱清单（第 78–85 轮实证）

**下列八项全部不在密码学里，全部逃过了 668 项官方向量与原有全部测试**，
每一项都只有"按真实顺序走一遍"才会暴露。做 `:core` 接入前请逐条核对。

| # | 陷阱 | 症状 | 状态 |
|---|---|---|---|
| 1 | `GroupKeyPackage` 丢掉 init 私钥 | Welcome 收得到、**打不开** | 已修（返回 `InitKeyPrivateHex`） |
| 2 | GroupInfo 里没有棘轮树 | Welcome 解开了、**不知道群里有谁** | 已修（`ratchet_tree` 扩展 `0x0002`） |
| 3 | `AcceptWelcome` 要求调用方提供树 | **调用方不可能有树**（树在消息里） | 已修（`Tree` 可空，从 GroupInfo 取） |
| 4 | 一人群首条提交被判为错误 | **正常加人操作直接失败** | 已修（§12.4.1：null optional 路径 + 全零 commit_secret） |
| 5 | `SealApplication` 要调用方提供依赖其自身输出的密钥 | **真实顺序下无法调用** | 已修（改收 `sender_data_secret`，顺序由函数保证） |
| 6 | 密文必须 ≥ `KDF.Nh` | **短消息完全发不出** | 客户端须填充（长度前缀 + 补零到 `Nh−16`） |
| 7 | GroupInfo 加密**无 AAD**，内容加密**有 AAD** | 用错则"作者能开、别人不能" | 已分两个函数（`aesGCMSeal` / `aesGCMSealAAD`） |
| 8 | 棘轮位置有两个来源（棘轮自身 vs `SenderData.Generation`） | **发送方成功、接收方全失败** | 已修（以消息声称的为准，唯一来源） |

### 三条给客户端的具体要求

1. **填充不可省**：群消息明文须至少 16 字节（suite 0x0001），绑定层已做
   `长度前缀(4BE) ‖ 载荷 ‖ 补零`，且**必须带长度前缀**——纯补零会截断以零结尾的合法载荷。
2. **棘轮代数由客户端保存**：群快照不含本地棘轮位置，`GroupSeal` 传入并返回
   （`generation` → `NextGeneration`），调用方必须随状态一起存。
3. **快照含 epoch 密钥**：必须存进 Kotlin 侧的加密保险库，与身份同等级对待。

### 端到端测试是可用的唯一证据

协议层有 668 项官方向量、269 项测试，而第 4、8 两项让**完全正常的操作不可用**。
判据不是"测试全绿"，而是：

- **Alice 建群 → 加 Bob → Bob 用 Welcome 入群 → 双方 epoch authenticator 逐字节一致**；
- **Alice 发 → Bob 收且逐字节还原 → 另一群的合法成员读不到**。

这两条现在都是通过的（`protocol/mobile` 的 `TestBindingEndToEndCreateAddAndJoin`、
`TestGroupMessageRoundTripAcrossTheBinding`、`TestAnOutsiderCannotReadAGroupMessage`）。
---

## 10. 接收方跟进提交：两个真缺陷与一个方法论（第 154–195 轮）

### 10.1 缺陷一：入群者的转录哈希

`AcceptWelcome` 曾把转录设为**空** ✗。规范 §8.2 与 §12.4.3.1：

```
confirmed_transcript_hash_[epoch] = Hash(interim_[epoch-1] || ConfirmedTranscriptHashInput)
interim_transcript_hash_[epoch]   = Hash(confirmed_[epoch] || <编码后的 confirmation_tag>)
```

**新成员的**：`Confirmed` ← GroupContext 里的值 ✓；
`Interim` ← **`Hash(confirmed ‖ InterimTranscriptHashInput{GroupInfo.confirmation_tag})`** ✓。

**两处易错**（我各错了一次 ✓）：
1. 用 **GroupInfo 的** tag（不是自己的 ✓）；
2. tag 进入时是**编码后的字段**（带长度前缀 ✓），不是裸字节 ✗ —— 而 `confirmed` 也必须在里面 ✓。

### 10.2 缺陷二：`commit_secret` 的来源（**主因**）

**发送方曾使用调用方传入的任意值** ✗ → **接收方无从复现** ✗ → 两侧从相同状态导出不同 epoch ✗。

**正确**：有路径时 = **根节点的 path secret**（`PathSecrets` 的最后一项 ✓，`updatepath_gen.go:134` ✓）；
无路径时 = **长度 `KDF.Nh` 的全零向量**（§12.4.1 ✓）。

**两侧现在按构造一致** ✓。`CommitSpec.CommitSecret` 已标注为**被忽略** ✗。

### 10.3 方法论：**不忠实的测试比红色更危险**

8 处测试把**发送方的 commit secret 直接传给接收方** ✗ —— 那是**现实中不存在**的输入 ✓。

| | |
|---|---|
| 改忠实之前 | 297 项全绿 ✓，而"经 Welcome 入群的成员跟进提交"**完全不可用** ✗ |
| **改忠实之后** | **5 条立刻变红** ✓ → **一轮定位到发送方** ✓ |
| 在改之前 | 我在**接收方找了九轮** ✗ |

**结论**：**测试若给了被测代码一个现实中不存在的输入，它证明的只是"代码在虚假输入下自洽"** ✗。
**先问"这个输入现实中从哪来"，再写测试** ✓。

### 10.4 另外两条

- **`println` 写 stderr** ✓ —— 管道里少了 `2>&1` 就会**静默丢失** ✗（我因此白花一轮 ✓）；
- **"错误出现在第 N 步"≠"第 1..N−1 步都成功了"** ✗ —— **提前返回**会让"错误位置"完全失去诊断价值 ✓（第 78 轮的一人群 ✓、无路径提交 ✓，同一形状 ✓）。

### 10.5 仍未完成（M4 收尾清单）

1. **建群者自己的叶子私钥没有保存** ❌ —— `GroupCreate` 生成后丢弃 ✓ → **建群者无法跟进他人的提交** ✗（与第 133 轮 `GroupKeyPackage` 同一形状 ✓）；
2. **接收方的内联提案逻辑与 `applyProposalEffects` 分叉** ❌ —— 多提案顺序 ✓、扩展时机 ✓（**真实但非上述两缺陷之因** ✓）；
3. **删除 `CommitSpec.CommitSecret`** ❌（现为"说谎的字段" ✓，已标注 ✓）；
4. `:core` 接线与界面 ✓。
---

## 11. 加人流程：两封内容不同、去向也不同的信（第 201–228 轮）

### 11.1 一次"把人加进群"产生两封信

| 内容类型 | 内容 | 投向 | 为什么 |
|---|---|---|---|
| **0x05** 提交 | `AuthenticatedContent` | **群信箱**（由 epoch 导出） | 只有成员能应用它，而成员恰好是能派生出这些信箱的人 |
| **0x04** Welcome | 加密的 GroupSecrets | **新成员个人的**信箱 | 它还不是成员，推不出群信箱 |

**顺序也是内容的一部分**：**先提交、后 Welcome**。反过来，新成员会先拿到一份指向某个 epoch 的入群材料，而那个 epoch 在群里还不存在。

**逐令牌发送，不是发一次**：每个令牌是一个独立信箱，中继按令牌路由。只发一个令牌时，恰好订阅了另一个令牌的成员就收不到——而那正是"有人没跟上群"的来源。

**信封里只有令牌、没有群 ID**（0x05）：接收方算出每个已保存群在**当前与上一个**令牌 epoch 下的信箱，令牌相符的那个群就是它要去的群。令牌 epoch 由**墙上时钟**派生（`Mobile.currentEpoch`），所以边界两侧算出的信箱不同，两个都要认。

### 11.2 入群者的叶子下标是**推导**出来的，不是传进来的

`AcceptWelcome` 用**叶子私钥**推出公钥，在该群的树里找到相符的叶子——因为：

> **一个成员无法在入群前知道自己的下标。** 那个数字只存在于群的树里，而树里唯一能标识它的是它刚用来打开 Welcome 的那把钥匙所对应的公钥。

**这不是记账**：下标决定成员尝试打开哪一个加密的路径秘密。用错的下标 → 解开**别人的**秘密 → 重建出**不是这个群的**树 → **在确认标签处失败**（一个指向密钥调度、而非一个错数字的症状）。

`GroupProcessWelcome` 因此是**三参数**（Welcome、init 私钥、叶子私钥）。调用方**没有机会**手写一个数字。

### 11.3 三条方法论（都是花钱买来的）

**① 增量编译会给假绿。**
给 `GroupScreen` 加了必填参数、而调用点没传，`./gradlew :app:compileDebugKotlin` 仍然报 `NO KOTLIN ERRORS`——因为那个文件没有被重新编译。
**结论：宣称"能编译"之前，用 `--rerun-tasks` 强制全量重编一次。**

**② 行级手术的残片，症状总是夸张的。**
用"删除含某标识符的行"做清理，会删掉块首行而留下块体；用状态机跳过一段，会多吃几十行。
**两次的症状都是同一形状**：十几到二十个 `Unresolved reference`，看起来像丢了整个 `companion object`——而实际损失是**一个孤立的 `}`**，或**一个函数**（净行数只差 1，从行数看不出来）。
**结论：删块要按行号并校验行内容；改完立刻编译。**

**③ `DeriveKeyPair` 不是"由私钥求公钥"。**
它的参数是**用来派生的 ikm**。把私钥喂进去会得到**一把无关的密钥对**。
**这个错误犯了两次**，两次症状相同且都指向别处："树里没有这个成员的叶子"——**而树里完全有**（17 个测试同时失败）。
**结论：由私钥求公钥用 X25519 标量乘法**（`ecdh.X25519().NewPrivateKey(priv).PublicKey()`）。

### 11.4 M4 收尾时的验证状态

| 层 | 证据 |
|---|---|
| 协议层"跟随"四场景（建群者 / 发送方自更新 / 接收方 / 入群者） | 端到端测试，各自通过 |
| `protocol` 全部测试 | **303 通过 / 0 失败 / 1 跳过** |
| `:core` 单元测试 | **全绿**（含"缺叶子私钥的记录读回 null"） |
| `:app` | **`--rerun-tasks` 全量编译通过** |
| 加人流程 | 代码 + 编译；**尚无设备端到端测试**（下一步） |