# SCS-1 协议实现规格

> 本文档是 [`../SCHAT.md`](../SCHAT.md) 第 4、5 节的可实现化扩展，面向**协议实现者与第三方审计者**。
> 规范性来源始终是 `SCHAT.md`；如有冲突，以 `SCHAT.md` 为准。

**版本**：SCS-1 v1（WireVersion `0x01`）
**实现**：`protocol/`（Go），经 gomobile 编译为 `.aar` 供安卓客户端调用
**状态**：基础层已实现并测试；会话层与棘轮层在路线图步骤 2 实现

---

## 1. 原语与依赖

SCS-1 **不发明密码学原语**。下表是全部密码学依赖，任何新增依赖都必须经过评审。

| 用途 | 算法 | 实现来源 | 验证方式 |
|---|---|---|---|
| 密钥协商 | X25519 | 标准库 `crypto/ecdh` | Go 官方实现 |
| 身份签名 | Ed25519 | 标准库 `crypto/ed25519` | Go 官方实现 |
| 密钥派生 | HKDF-SHA256 (RFC 5869) | 标准库 `crypto/hkdf` | **RFC 5869 附录 A 测试向量** |
| 对称加密 | ChaCha20-Poly1305 (RFC 8439) | `golang.org/x/crypto/chacha20poly1305` | XOF 官方实现 |
| 对称加密 | XChaCha20-Poly1305 | 同上（`NewX`，192-bit nonce） | 同上 |
| 对称加密 | AES-256-GCM | 标准库 `crypto/aes` + `crypto/cipher` | Go 官方实现 |
| 口令派生 | Argon2id (RFC 9106) | `golang.org/x/crypto/argon2` | XOF 官方实现 |
| 哈希 | BLAKE2b-256 (RFC 7693) | `golang.org/x/crypto/blake2b` | XOF 官方实现 |
| 后量子（v2 预留） | ML-KEM-768 | 标准库 `crypto/mlkem` | Go 官方实现 |

**唯一的第三方依赖是 `golang.org/x/crypto`**，且只用于标准库尚未覆盖的三个原语。

---

## 2. 域分隔标签

所有密钥派生必须携带标签。标签是**冻结的线格式契约**，修改任何一个都必须同时提升 `WireVersion`。

```
L_ROOT    = "SCS1/root/v1"       L_CHUNK   = "SCS1/chunk/v1"
L_CHAIN   = "SCS1/chain/v1"      L_WRAP    = "SCS1/wrap/v1"
L_MSG     = "SCS1/msg/v1"        L_VAULT   = "SCS1/vault/v1"
L_FILE    = "SCS1/file/v1"       L_MAILBOX = "SCS1/mbx/v1"
L_GROUP   = "SCS1/group/v1"      L_CALL    = "SCS1/call/v1"
L_SAFETY  = "SCS1/safety/v1"     L_TRANSCRIPT = "SCS1/transcript/v1"
```

派生惯用法（`DeriveLabeled`）：

```
out = HKDF-SHA256(ikm, salt = label, info = label ‖ 0x00 ‖ context, len)
```

标签同时出现在 salt 与 info 中，使 extract 与 expand 两个阶段都被域分隔。

**测试要求**：`protocol/kdf_test.go` 中的 `TestDeriveLabeledSeparatesDomains` 断言任意两个标签在同一输入下产出不同密钥。此测试必须在 CI 中始终通过。

---

## 3. 帧格式

```
hdr = ver(1) ‖ flags(1) ‖ DH_pub(32) ‖ pn(4) ‖ n(4)          共 42 字节
AD  = AD₀ ‖ hdr
```

| 字节 | 字段 | 说明 |
|---|---|---|
| 0 | `ver` | 必须等于 `0x01`；不等即拒绝，**绝不降级** |
| 1 | `flags` | 见下表 |
| 2–33 | `DH_pub` | 发送方当前 X25519 棘轮公钥 |
| 34–37 | `pn` | 上一条发送链的消息数（大端） |
| 38–41 | `n` | 当前发送链中的消息序号（大端） |

**标志位**

| 位 | 名称 | 含义 |
|---|---|---|
| `1<<0` | `HasOneTimePreKey` | 已消费一次性预密钥，首条消息具备完整前向保密 |
| `1<<1` | `UnverifiedIdentity` | 对端身份未经验证，UI 必须显著提示 |
| `1<<2` | `GroupMessage` | 内容密钥来自 MLS exporter 而非双棘轮 |
| `1<<3` | `PaddingExtended` | 保留，禁止复用 |

---

## 4. 密钥派生链

### 4.1 会话建立（SCS-HSK）

```
EK   ← 新生成的 X25519 临时密钥对
DH1  = X25519(IK_dh^A, SPK^B)
DH2  = X25519(EK,      IK_dh^B)
DH3  = X25519(EK,      SPK^B)
DH4  = X25519(IK_dh^A, OPK^B)      # OPK 池空则跳过

material  = LEXSORT(DH1, DH2, DH3, DH4)          # 按字节序字典序排序
transcript = BLAKE2b-256(L_TRANSCRIPT ‖ ver ‖ LEXSORT(IK_pub^A, IK_pub^B) ‖ SPK^B ‖ OPK^B)
salt      = L_ROOT ‖ LE64(epoch=0) ‖ transcript

RK₀ = HKDF-SHA256(ikm = material, salt = salt, info = L_ROOT, len = 32)
AD  = transcript
```

**LEXSORT 的必要性**：教科书式实现按角色顺序拼接 DH 输出，一旦实现方把发起方/响应方写反，双方导出的根密钥不同且**不会报错**，只表现为"连不上"。排序使派生与角色无关。

### 4.2 对称棘轮

```
CK_{n+1} = HMAC-SHA256(CK_n, 0x02)

info = dir ‖ LE64(n) ‖ type          # dir: 0x41 = A→B, 0x42 = B→A
MK_n = HKDF-SHA256(ikm = CK_n, salt = L_MSG, info, len = 44)
key  = MK_n[0..32]   nonce = MK_n[32..44]
ct   = AEAD_Seal(key, nonce, plaintext, AD ‖ hdr)

用后立即：Zero(CK_n), Zero(MK_n), Zero(plaintext)
```

**方向字节的必要性**：若两个方向在同一计数器下导出相同密钥，攻击者可将受害者的密文原样反射回去并被当作有效入站消息接受。

### 4.3 DH 棘轮

DH 棘轮的触发条件只有一条：**收到对端携带新棘轮公钥的消息**。

```
1. 先为旧接收链尾部派生并缓存跳过密钥（数量由消息头的 pn 决定）
2. (RK', ckRecv) = KDF_RK(RK, DH(本地棘轮私钥, 对端新棘轮公钥))
3. 生成本地新棘轮密钥对：
   (RK'', ckSend) = KDF_RK(RK', DH(新本地棘轮私钥, 对端新棘轮公钥))

KDF_RK(RK, dhOut) = HKDF-SHA256(ikm = dhOut, salt = RK, info = L_CHAIN, len = 64)
                    → 前 32 字节为新 RK，后 32 字节为链密钥
```

> **⚠️ 已删除的设计：自适应棘轮阈值 T**
>
> 本规格早期版本规定了 `T = 8 + (BE32(BLAKE2b-256(RK₀ ‖ L_CHAIN)[0:4]) mod 24)`，即本地发满 T 条消息后主动刷新发送链，另有 12 小时时间上限。
>
> **该机制在密码学上不可实现，已删除。** 棘轮密钥必须严格交替推进：接收方用 `DH(自己当前私钥, 收到公钥)` 推导共享密钥，若发送方持有**过期**的远端公钥主动刷新，接收方早已换用更新的私钥，两边算出的值不同，**会话永久断裂**。
>
> 反例：A 单向连发 → B 回复一次（B 持有 R_B2）→ A 用过期 R_B1 第二次主动刷新 → A 算 `DH(R_A_new, R_B1)`，B 算 `DH(R_B2, R_A_new)`，不匹配。
>
> 该优化也不必要：标准双棘轮每往返仅 1 次 DH，已是后妥协安全的最小代价。

### 4.3.1 未认证帧的防护（必须实现）

帧头在 AEAD 认证通过前**不可信**。因此：

1. 判定棘轮**之前**先查跳过密钥缓存（迟到的旧链消息携带旧棘轮公钥，天真实现会把它误判为新棘轮并摧毁会话）；
2. 推进棘轮前**快照**状态，认证失败即**回滚**；
3. 对称链**仅在解密成功后**推进。

缺少第 2、3 条时，一个伪造的棘轮公钥或计数器即可使会话永久失效——一次廉价的拒绝服务。

### 4.3.2 消息头中的内容类型

```
hdr = ver(1) ‖ flags(1) ‖ profile(1) ‖ DH_pub(32) ‖ pn(4) ‖ n(4)     共 43 字节
```

内容类型**不参与消息密钥派生**，而是放在帧头并通过 AAD 认证。原因是乱序投递：接收方缓存"跳过的消息密钥"时无从得知那些消息的类型，且不同 profile 的 nonce 长度不同（12 vs 24）。

消息密钥输出**固定 56 字节**（32 key + 24 nonce），使用时按 profile 截断。

### 4.4 文件分块密钥梯

```
FK      ← 32 字节随机，每个文件唯一，禁止复用
K_root  = HKDF(FK, salt = L_FILE ‖ profile_byte, info = L_FILE, len = 32)
CK_i    = HKDF(K_root, salt = LE64(i), info = L_CHUNK, len = 44)

h_i   = BLAKE2b-256(ciphertext_chunk_i)
root  = 分层两两哈希（奇数节点原样上传，同 RFC 6962）
```

`root` 存放在**加密后的文件头**内，接收方逐块校验并验证到 root。

### 4.5 群组：MLS exporter 桥接

```
epochKey = HKDF(MLS_Export(exporter_secret, label="SCS1/group/v1", context=group_id),
                salt = L_GROUP, info = L_GROUP ‖ 0x00 ‖ group_id, len = 32)
SK_i     = HKDF(epochKey, salt = L_GROUP, info = L_GROUP ‖ 0x00 ‖ LE32(leaf_index), len = 32)
```

群聊内容加密与单聊**走完全相同的 AEAD 配置矩阵**，不存在第二套实现。

### 4.6 投递令牌

```
epoch = floor(unix_seconds / 86400)
token = HKDF(ikm = routeKey, salt = L_MAILBOX, info = LE64(epoch) ‖ LE32(index), len = 16)
```

---

## 5. AEAD 配置矩阵

见 `SCHAT.md` 第 5.1 节。规范约束：

| Profile | 值 | 算法 | Nonce | 分块 |
|---|---|---|---|---|
| `ProfileText` | `0x01` | ChaCha20-Poly1305 | 12 | 不分块 |
| `ProfileImage` | `0x02` | ChaCha20-Poly1305 | 12 | 256 KiB |
| `ProfileVideo` | `0x03` | ChaCha20-Poly1305 | 12 | 1 MiB |
| `ProfileFile` | `0x04` | **XChaCha20-Poly1305** | **24** | 1 MiB |
| `ProfileVoice` | `0x05` | ChaCha20-Poly1305 | 12 | 200 ms |
| `ProfileHeader` | `0x06` | **AES-256-GCM** | 12 | — |
| `ProfileDatabase` | `0x07` | **AES-256-GCM** | 12 | 4 KiB |

`protocol/aead_test.go` 的 `TestProfileMatrixMatchesSpec` 把这七个组合**钉死**，任何改动都会导致测试失败。

---

## 6. 填充

```
布局： LE32(real_length) ‖ plaintext ‖ 零填充
桶：   256, 1024, 4096, 16384, 65536, 262144
超出最大桶：向上取整到 262144 的整数倍
```

长度前缀位于 AEAD 认证范围内，因此截断或扩展都会导致认证失败。

---

## 7. 实现强制约束

以下为**安全要求**，不是风格偏好。任何 PR 违反其中一条都必须被拒绝。

1. 认证标签比较必须使用 `crypto/subtle`，禁止 `==`。
2. 禁止用秘密数据索引查表。
3. 密钥使用后必须立即 `Zero()`。
4. 禁止记录密钥、明文、nonce。
5. 随机数只能来自 `crypto/rand`，`math/rand` 一律禁用。
6. 版本或参数不匹配必须**拒绝**，禁止降级或"忽略错误继续"。
7. 服务端模块（`server/`）**禁止导入** `protocol/`，以保证中继二进制中不存在任何解密代码。

---

## 8. 测试与验证要求

| 层次 | 验证方式 | 状态 |
|---|---|---|
| HKDF | RFC 5869 附录 A.1 / A.3 官方测试向量 | ✅ 已通过 |
| 域分隔 | 全标签两两不等 | ✅ 已通过 |
| AEAD | 全 profile 往返 + 逐位翻转篡改检测 + 错误密钥 + AAD 绑定 | ✅ 已通过 |
| 填充 | 边界值 + 不泄漏长度 + 畸形输入拒绝 | ✅ 已通过 |
| 帧格式 | 字段偏移 + 版本拒绝 + 短缓冲 | ✅ 已通过 |
| 并发 | `go test -race` | ✅ 已通过 |
| 会话建立 | 双向一致 + 中间人替换可检测 | ⏳ 步骤 2 |
| 棘轮 | 乱序/跳过/重放/前向保密 | ⏳ 步骤 2 |
| MLS | **IETF 官方测试向量逐字节** | ⏳ 步骤 6a |
