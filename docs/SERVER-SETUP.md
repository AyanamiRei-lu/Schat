# 服务器部署与客户端连接

> **状态：本文档将在路线图步骤 9 完成。**
> 当前服务端的 WebSocket 网关与 TLS 终结尚未实现（步骤 3），因此**现在还不能真正收发消息**。
> 本页先记录已经可以验证的部分，避免写出无法复现的教程。

---

## 当前可用（已验证）

### 0. 传输层：TLS 默认开启

服务端**默认使用 TLS**，自签名证书持久化在 `--state-dir`（默认是用户缓存目录），启动时打印 SHA-256 指纹与完整连接 URI。证书重启后不变，所以客户端**配置一次即可长期使用**。

TLS 下限是 **1.2 而非 1.3**：Android 8.0/9.0（正是 `minSdk` 26 覆盖的设备）与 Windows 10 都不支持 TLS 1.3。Go 为 1.2 提供的全部套件都是 ECDHE + AEAD，前向保密与认证加密都有保证，而引发争议的 CBC/RC4 套件根本不会被协商；支持 1.3 的对端会自动升级。

### 0.1 公网部署：由反向代理终结 TLS

**服务端不内置 ACME 客户端**，也不会自动申请 Let's Encrypt 证书。原因是那需要 `golang.org/x/crypto/acme/autocert`，会成为服务端模块的**第一个第三方依赖**，直接破坏"服务端零依赖、不含解密代码"——而这条保证正是可以用 `go list -m all` 机械校验的。

公网部署的正确做法：

```
# Caddyfile — 自动申请与续期证书，零配置
chat.example.com {
    reverse_proxy 127.0.0.1:8443
}
```

```bash
schat-server --listen 127.0.0.1:8443 --public-host chat.example.com
```

这比在服务端内置 ACME 客户端更标准也更安全：证书续期、OCSP stapling、HSTS 都由成熟组件负责，服务端只监听 loopback。

持有自有证书的部署改用：

```bash
schat-server --cert-file /etc/schat/cert.pem --key-file /etc/schat/key.pem
```

### 1. 构建

```bash
cd server
go build -o schat-server ./cmd/schat-server
```

产物约 **9.7 MB**，静态链接，**无任何第三方依赖**，无需运行时。

### 2. 零配置启动

```bash
./schat-server
```

不带任何参数即可启动。所有配置项都有可用默认值：

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `listen` | `0.0.0.0:8443` | 监听地址 |
| `mode` | `live` | **不存储任何数据** |
| `name` | `schat` | 客户端显示的名称 |
| `metrics_listen` | `127.0.0.1:9090` | 指标端点 |
| `tls` | 自签名 | 无需域名即可工作 |

### 3. 验证运行状态

```bash
curl http://127.0.0.1:18443/api/v1/health
```

返回内容会**明确列出尚未实现的功能**：

```json
{
  "status": "ok",
  "version": "0.1.0-alpha",
  "protocol": "SCS-1/v1",
  "mode": "buffer",
  "storage": "none",
  "unimplemented": [
    "the WebSocket gateway is not implemented yet (roadmap step 3)",
    "TLS termination and certificate fingerprints are not implemented yet (roadmap step 3)",
    "QR code rendering is not implemented yet (roadmap step 3)"
  ]
}
```

`/ws` 现在是**真实网关**。用非 WebSocket 请求访问它会得到 **400 `bad websocket handshake`**（不再是 501）。真正的收发行为由 `go test ./server/internal/gateway/` 覆盖：两个真实 WebSocket 客户端经服务器互发信封，逐字节一致。

### 4. 配置文件（可选）

配置使用 **JSON**（不是 YAML）。这是刻意的取舍：`encoding/json` 属于标准库，而 YAML 会引入一个第三方依赖，与服务端"零依赖、零占用"的目标冲突。

创建 `schat.json`：

```json
{
  "listen": "0.0.0.0:8443",
  "name": "我的服务器",
  "mode": "live",
  "tls": { "domain": "chat.example.com" },
  "log": { "level": "info" }
}
```

启动：

```bash
./schat-server --config /etc/schat/schat.json
```

**任何字段都可以省略**，省略的字段保留默认值。键名拼错会**直接报错**而不是被忽略，避免配置静默失效。

### 5. 资源占用（本机实测）

| 指标 | 实测值 | 目标 |
|---|---|---|
| 二进制体积 | 10.61 MB | < 15 MB ✅ |
| 空载内存（WorkingSet，TLS 开启） | **10.6 MB** | < 20 MB ✅ |
| 磁盘数据占用 | **0** | 0 ✅ |

#### 5.1 每连接成本与选配建议（实测）

由 `tools/measure-relay-load.ps1` 测出（`server/cmd/schat-loadtest` 开连接并持有）：

| 在线连接 | 工作集 | 相对空载的增量 | 每连接 |
|---|---|---|---|
| 0（空载） | 8.69 MB | — | — |
| 100 | 11.69 MB | +3.00 MB | 31 KB |
| 500 | 21.73 MB | +13.04 MB | 27.3 KB |
| 1000 | 34.43 MB | +25.74 MB | 27.0 KB |
| 2000 | 59.66 MB | +50.97 MB | **26.7 KB** |

**每连接约 27 KB，且 100 → 2000 之间几乎恒定**——缩放是线性的，没有随连接数增长的额外开销或泄漏。

> ⚠️ **这个数字来自明文 WebSocket（`--no-tls`）**，因为测试客户端不做证书处理。真实部署里每条 TLS 连接还要持有它自己的记录缓冲区与握手状态，所以**真实成本高于此表**。做容量规划时按 **~50 KB/连接** 留余量是稳妥的。

**由此得到的选配结论：**

| 规模 | 同时在线 | 建议配置 | 说明 |
|---|---|---|---|
| 家人/朋友小圈子 | < 50 | **1 vCPU / 512 MB–1 GB / 20 GB** | 最小可用规格就够，实测 2000 连接才 60 MB |
| 小社区 | 数百 | 1–2 vCPU / 1 GB / 20–40 GB | 1 GB 按 50 KB/连接算可容纳约 2 万人同时在线 |
| 数千人在线 | 数千 | 2 vCPU / 2 GB / 40 GB | CPU 几乎不是瓶颈，见下 |

**为什么 CPU 和磁盘几乎不重要：**

- **中继不解密、不签名、不做任何密码学运算**（它连协议核心都不导入，这一点由 `tools/verify.ps1` 机械校验）。它的工作只是把字节从一条连接搬到另一条连接，CPU 开销几乎只有系统调用与内存拷贝。
- **磁盘占用为 0**：唯一的落盘内容是自签名证书（几 KB，位于 `--state-dir`）。**没有数据库**，预密钥目录与离线队列都在内存里。磁盘只需要装下操作系统。

**真正决定成本的是流量，不是配置：**

- 单聊文字消息：一个信封约 43 字节帧头 + 认证标签 + 密文，**每条一两百字节**，可以忽略。
- **群消息是 N 份**：MLS 的密文对全体成员相同，所以发送者要把同一个信封逐个投到每个成员的信箱。10 人群的一条消息 = 10 份流量。这是 MLS 的工作方式，不是缺陷。
- **图片/文件（步骤 7，尚未实现）才是账单的来源**：一个 100 MB 的视频发给 10 个人 = 约 1 GB 出网流量。选服务器时**优先看流量计费方式与出网带宽**，而不是 CPU/内存。

**其他部署要点：**

1. **不需要域名，也不需要 Let's Encrypt。** 客户端**固定证书指纹**，所以直接跑自签名证书 + 公网 IP 即可，把服务器打印的那条 `schat://connect?...&fp=...` 发给人就行。这省掉了域名、证书与反向代理。（域名备案等问题请以你的服务商与所在地要求为准，本文件不构成法律意见。）
2. **保持 `live` 模式**（默认）则服务器**什么都不存**；若希望对方离线时消息暂存一下，用 `--mode buffer`，但那也**只在内存里**，重启即丢。
3. **服务器重启会清空预密钥目录**（纯内存）。客户端会在每次连上时自动重新发布，所以不需要人工干预，但**重启瞬间对方取包会得到 404**。
4. **指标端口默认只绑 `127.0.0.1:9090`**，不要把它暴露到公网。
5. **运维方能看到什么、看不到什么**（给他人开服务器时应当如实告知）：看不到任何消息内容；**能看到** IP 地址、连接时间、投递令牌流量，以及——由于当前 MVP 的信箱地址由公开身份派生——**哪些身份正在活动**。见 `SECURITY.md` 第 3 节。
6. 加固建议：仅密钥登录 SSH、开启自动安全更新、防火墙只放行 8443（与 SSH），并考虑对 8443 做连接频率限制。

### 6. systemd 部署

```bash
sudo install -m 0755 schat-server /usr/local/bin/schat-server
sudo install -m 0644 schat-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now schat-server
```

unit 文件已经做了严格加固：只读根文件系统、无任何可写路径、丢弃全部 capability、内存上限 256 MB。服务端**没有任何状态需要保存**，因此这些限制不会影响功能。

### 7. Docker

```bash
docker build -t schat-server .
docker run -d --name schat -p 8443:8443 schat-server
```

---

## 尚未实现（步骤 3 与步骤 9 完成）

| 功能 | 步骤 | 影响 |
|---|---|---|
| WebSocket 网关 | ✅ 3a | 已实现，非升级请求返回 400 |
| TLS 终结与证书指纹 | ✅ 3b | 已实现，自签名证书持久化且指纹稳定 |
| 二维码渲染 | 3c | 目前可打印完整 URI，需手动输入 |
| Let's Encrypt 自动证书 | — | **不做**：需要引入第一个第三方依赖，会破坏"服务端零依赖"的可机械校验保证。公网部署由反向代理终结 TLS（Caddy 零配置）。见上节 |
| 客户端扫码/粘贴配置 | 4 | 无法在 App 内配置服务器 |
| 端到端联调教程 | 9 | 本页将补齐完整流程 |

---

## 客户端的连接 URI 格式

服务端已经可以生成该 URI（`schat-server --print-uri`）：

```
schat://connect?h=<主机>&p=<端口>&n=<名称>&fp=<证书指纹>&ss=<是否自签名>
```

| 参数 | 含义 |
|---|---|
| `h` | 主机名（若监听在 `0.0.0.0` 则回退到域名或 `localhost`） |
| `p` | 端口 |
| `n` | 服务器显示名称 |
| `fp` | 证书指纹（自签名时用于固定，步骤 3 产出） |
| `ss` | `1` 表示自签名证书，客户端必须校验证书指纹 |

步骤 3 完成后，这条 URI 会被渲染成二维码，手机扫码即可完成配置（对应需求八"配置难度不得过高"）。
