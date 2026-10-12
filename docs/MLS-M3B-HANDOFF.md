# M3b 交接：Node 编解码 → resolution/tree_hash → UpdatePath

> 这份文档是**开工前的状态快照**，为的是让下一轮不必重新摸索线格式。
> 它记录的都是**已确认的事实**，不是我打算怎么做。

---

## 0. 现在的状态

| 里程碑 | 状态 |
|---|---|
| M1 表示层编解码器 | ✅ 已验证（RFC 自带的三个黄金向量） |
| M2a 密码学基础层 | ✅ 已验证（`crypto-basics.json` 12 项） |
| M2b 密钥调度 | ✅ 已验证（`key-schedule.json` 140 项、10 个 epoch） |
| M3a 树数学 | ✅ 已验证（`tree-math.json` 8144 项下标关系） |
| **M3b** | ⏳ **未开始**（本文档描述它） |
| M4 / M5 / M6 | 未开始 |

`tools/verify.ps1` 全绿；协议 175 通过 + 1 SKIP。

---

## 1. 为什么顺序不能变

`tree-validation.json` 里的 `tree` 字段**不是 JSON**，而是**序列化后的 `optional<Node>` 向量**的十六进制。因此：

- 不知道"哪些节点是空白"，就算不出 `resolution`；
- 不知道叶子的完整内容，就算不出 `tree_hash`；
- 没有 `resolution`，`UpdatePath` 就不知道该把 path secret 加密给谁。

**所以必须先做 `Node` 编解码，不能挑软的先做。** 这一点在动手前就写下来，免得后来图省事跳步。

---

## 2. 已经解出的线格式（手工核对过）

`tree-validation.json` 第 1 条的 `tree` 开头：

```
41 a5                 外层向量长度 = 0x01a5 = 421 字节
01                    第一个 optional<Node> 存在
01                    NodeType.leaf (=1)
20 c699b3…5ff9        HPKE 公钥：varint 长度 0x20 = 32，随后 32 字节
…（凭据、能力、生命周期、扩展、签名）
```

两条可直接使用的结论：

1. **`Node` 是自定界的**，所以向量内部**没有**逐元素的长度前缀——每个元素靠解析其内容确定边界。这意味着"跳过解析直接数节点"是做不到的，必须真正解析。
2. 手工解读与 `tree_hashes` 的条数吻合：第 1 条有 3 个哈希（2 叶树 = 3 节点），第 2 条更多（4 叶树 = 7 节点）。**往返验证时"解析出的节点数 == tree_hashes 条数"是一条独立的交叉校验**，不依赖我是否理解正确。

---

## 3. 需要实现的结构（线格式）

按 RFC 9420 §7 的编码，**只做解析与重编码所需的部分**（签名 TBS 留到 M4/M5）：

```
NodeType  = reserved(0) | leaf(1) | parent(2)
CredentialType = basic(1) | x509(2)

Credential = { CredentialType; select { basic: opaque identity<V>; x509: Certificate chain<V> } }
Capabilities = { ProtocolVersion versions<V>; CipherSuite cipher_suites<V>;
                 ExtensionType extensions<V>; ProposalType proposals<V>;
                 CredentialType credentials<V> }
Lifetime = { uint64 not_before; uint64 not_after }
LeafNodeSource = key_package(1) | update(2) | commit(3)

LeafNode = { HPKEPublicKey encryption_key; SignaturePublicKey signature_key;
             Credential credential; Capabilities capabilities;
             LeafNodeSource leaf_node_source;
             select { key_package: Lifetime; update: {}; commit: { opaque parent_hash<V> } }
             Extension extensions<V>;
             opaque signature<V> }

ParentNode = { HPKEPublicKey encryption_key; opaque parent_hash<V>;
               uint32 unmerged_leaves<V> }

Node = { NodeType; select { leaf: LeafNode; parent: ParentNode } }

ratchet_tree = optional<Node> 的向量   // 见第 2 节
```

> ⚠️ **`LeafNodeSource` 的 select 三分支**与 **`Capabilities` 的字段顺序**要以 RFC 原文为准。我抓取 RFC 全文时被工具截断在 §7.5 之前，**没有拿到这一段的一手文本**——这一点必须补上，不能凭记忆。抓取工具每次只给前约 25%，所以要换能定位到 §7 的来源（例如把完整结果落到本地文件再 grep）。

---

## 4. 验证方法（按此顺序，每步都必须过）

1. **往返**：把第 1 条的 `tree` 十六进制解析成节点数组，再重新序列化，**必须逐字节等于原字节**。这是唯一能证明"我理解的线格式是对的"的办法。
2. **交叉校验**：解析出的节点数 == `tree_hashes` 的条数；对所有条目都成立。
3. **失败的诊断**：解析失败时必须报出**出错时的字节偏移**——一个只说"格式错误"的解析器在这类文件上毫无用处。
4. 之后才做 `resolution`（对照 `resolutions` 字段）与 `tree_hash`（对照 `tree_hashes` 字段），最后才是 `UpdatePath`（对照 `treekem.json`）。

**空白节点的定义**（`resolution` 的前提）：`optional<Node>` 里"不存在"的元素就是空白节点。

---

## 5. 环境注意事项（不照做会浪费一轮）

| 事项 | 说明 |
|---|---|
| **向量不入库** | 在 `protocol/mls/vectors/`，已 gitignore。换机器先跑 `tools/fetch-mls-vectors.ps1`。**向量缺席时相关测试是"跳过"而不是"失败"**，所以看到绿色要确认它真的跑了 |
| **向量无许可** | 上游 `mlswg/mls-implementations` 没有 LICENSE，因此**不能提交进仓库** |
| **Gradle 镜像** | `android/settings.gradle.kts` 配了阿里云镜像，因为本机网络**在劫持 Maven Central 的 TLS**（证书与主机名不匹配）。注释里写了原因与如何删掉 |
| **`--offline` 也可能失败** | 依赖缓存不全时离线构建会报 `No cached version`。别把这两种失败混为一谈 |
| **构建要提权** | 编译、测试、Gradle、网络操作在受限沙箱下会被拒绝 |

---

## 6. 完成 M3 的验收标准（不可讨价还价）

- `tree-validation.json` 的每一条：树往返逐字节一致、节点数吻合、**每个节点的 `resolution` 与 `tree_hash` 逐字节相同**；
- `treekem.json` 的每一条：**`UpdatePath` 逐字节相同**（含每个 `enc` 与 `encrypted_path_secret`）；
- 全部离线可跑（向量缺席时跳过而非失败），`verify.ps1` 全绿。

做不到就不算完成——尤其**不要**用"看起来能收发"替代逐字节判定：`resolution` 差一个节点时，密码学依然完全正确，只是 path secret 被加密给了错误的子树，而失败会推迟到成员无法解密时才出现。
