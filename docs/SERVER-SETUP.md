# 服务器部署与客户端连接

> **状态：本页描述的是已经实现并实测过的服务端。**
> WebSocket 网关、TLS 终结与证书指纹都已可用（第 3 步完成），自签名证书持久化且指纹稳定。
> 本文里的每一条命令都在一台真实机器上跑过；凡是**实测出来的行为**，都用「实测」标出。

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
| `mode` | `live` | `live` 不存储任何数据；`buffer` 会在内存里暂存（见 §5.2） |
| `name` | `schat` | 客户端显示的名称 |
| `metrics_listen` | `127.0.0.1:9090` | 指标端点 |
| `tls` | 自签名 | 无需域名即可工作 |

### 3. 验证运行状态

```bash
curl -k https://127.0.0.1:18443/api/v1/health
```

> **实测：这里必须是 `https://` 并且带 `-k`。** 用 `http://` 访问会得到
> `Client sent an HTTP request to an HTTPS server` —— 这句话看起来像服务器坏了，
> 其实只是协议用错了。`-k` 是因为证书是自签的，`curl` 默认不认它。
>
> 端口：`8443` 是默认值。本文里为了不与已占用的端口冲突，示例一直用 `18443`——
> 你自己部署时填 `--listen` 指定的那个。

返回的是**这台服务器此刻的真实状态**（下面是一台本机实例实测的输出，指纹已换成占位符）：

```json
{
  "status": "ok",
  "version": "0.1.0-alpha",
  "protocol": "SCS-1/v1",
  "mode": "live",
  "storage": "none",
  "retention": {
    "mode": "live",
    "on_disk": false,
    "queued": false,
    "note": "an offline recipient's envelope is refused, not stored"
  },
  "fingerprint": "<这台服务器的证书指纹>",
  "live_connections": 0,
  "uptime_seconds": 4.8,
  "prekey_directory": {
    "identities": 0,
    "one_time_prekeys": 0,
    "note": "public key material only; held in RAM, never written to disk"
  },
  "unimplemented": [
    "the relay does not print a QR code, by design: it has no third-party dependencies. The client shows a connection code that another device can scan",
    "media transfer (images, video, voice, files) is not implemented yet (roadmap step 7). Group chat IS implemented, in the client: this relay carries group envelopes without knowing or caring that they are group envelopes"
  ]
}
```

> `unimplemented` 这一项是**给运维看的诚实清单**，不是装饰。它曾经写着「WebSocket 网关尚未实现」
> 和「群聊未实现」——两条都过时了，而它们出现在一个**任何人 curl 一下就能看到**的地方。

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
2. **保持 `live` 模式**（默认）则服务器**什么都不存**；若希望对方离线时消息暂存一下，切到 `buffer` 模式——**具体步骤、内存陷阱与代价见 §5.2**。
3. **服务器重启会清空预密钥目录**（纯内存）。客户端会在每次连上时自动重新发布，所以不需要人工干预，但**重启瞬间对方取包会得到 404**。
4. **指标端口默认只绑 `127.0.0.1:9090`**，不要把它暴露到公网。
5. **运维方能看到什么、看不到什么**（给他人开服务器时应当如实告知）：看不到任何消息内容；**能看到** IP 地址、连接时间、投递令牌流量，以及——由于当前 MVP 的信箱地址由公开身份派生——**哪些身份正在活动**。见 `SECURITY.md` 第 3 节。
6. 加固建议：仅密钥登录 SSH、开启自动安全更新、防火墙只放行 8443（与 SSH），并考虑对 8443 做连接频率限制。

#### 5.2 开启 buffer 模式（离线暂存）

> **先读这一段再动手。** 这不是一个"性能开关"，它改变的是**服务器对外承诺的内容**。

**它解决什么**：`live` 模式下，收件人不在线时服务器直接回 `offline` 并丢弃信封——于是"对方离线时发的消息"和"对方离线时发来的添加请求"都永远到不了。`buffer` 模式把这些信封在**内存里**留一段时间，收件人上线订阅信箱时排空给他。

**它不解决什么**（每一条都会真的丢消息）：

| 情况 | 结果 |
|---|---|
| 服务器重启 | 内存队列全丢（设计如此，进程不落盘） |
| 超过 `buffer.ttl`（默认 72 小时） | 过期清掉 |
| 单信箱超过 `buffer.max_per_token`（默认 100 条） | **挤掉最老的**，离线被刷屏的人回来只能看到最后 100 条 |
| 排空时连接中途断开 | `Drain` 是先删后写，剩下那批永久丢失（已知缺陷，见 `docs/OFFLINE-DELIVERY-PLAN.md` §3） |

**第一步：确认内存上限（最容易踩的坑）**

systemd 单元里写着 `MemoryMax=256M`，而 buffer 的默认全局预算是 **512 MiB**。直接开 buffer，**队列还没到自己的上限，cgroup 就会先把进程 OOM 杀掉**。

而 `buffer.max_global_memory` **没有命令行参数**，只能写在配置文件里。所以要故意把预算调到 256 MiB 以内（示例取 128 MiB，给 Go 运行时和多连接留余量）：

```bash
sudo mkdir -p /etc/schat
sudo tee /etc/schat/config.json >/dev/null <<'JSON'
{
  "mode": "buffer",
  "buffer": {
    "ttl": "72h",
    "max_per_token": 100,
    "max_global_memory": 134217728
  }
}
JSON
sudo chmod 600 /etc/schat/config.json
```

> 配置文件的规则：**省略的字段沿用默认值**；**拼错的字段名会让启动直接失败**（不是静默忽略）；**命令行参数优先于配置文件**。三项 buffer 界限都必须大于 0。

**第二步：改 systemd（用 override，别改包里的 unit）**

包里那份 unit 写死了 `--mode live`，直接编辑它会在下次安装时被覆盖：

```bash
sudo systemctl edit schat-server
```

在编辑器里写入（**`ExecStart=` 的空值那行不能省**，否则 systemd 会认为你是在追加第二条启动命令，结果是两个进程抢同一个端口）：

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/schat-server --listen 0.0.0.0:8443 --config /etc/schat/config.json --state-dir /var/lib/schat $SCHAT_PUBLIC_HOST
```

> `--listen` 要显式写 `0.0.0.0:8443`：**只有当监听地址是 `0.0.0.0` 时 `--public-host` 才生效**，否则连接 URI 里会写成 `localhost`，手机配置完之后连的是手机自己（见交接文档 10.6 节）。

```bash
sudo systemctl daemon-reload
sudo systemctl restart schat-server
sudo systemctl status schat-server --no-pager
```

**第三步：验证**

1. 启动日志里应有 `buffer mode enabled: envelopes are held in RAM only and are lost on restart`；
2. 健康端点显示 `"mode":"buffer"`、`"storage":"ram-only"`，且 `retention` 里带着你设的三个界限：

   ```bash
   curl -sk https://127.0.0.1:8443/api/v1/health
   ```

   > 健康端点在**主端口** `/api/v1/health`（默认 8443，用 `https` + `-k`，因为证书是自签的）。`/metrics` 才在 `127.0.0.1:9090`，两者不是同一个端口。

3. 功能验证：让 A 完全退出 App，B 给 A 发一条消息——B 的状态行应显示 **"对端离线，消息已暂存在服务器内存中"**（而不是"未送达"）；A 重新打开 App 应收到；
4. 内存观察：跑一阵后 `systemctl show schat-server -p MemoryCurrent`，确认没有贴着 `MemoryMax`。

**第四步：同步口径（不做这一步就是文档在骗人）**

开了 buffer 之后，下面这些说法都需要限定，否则与实际不符：

| 位置 | 现在写的 | 应改为 |
|---|---|---|
| `README.md` 能力表 | 服务端零留存 | `live` 模式零留存；`buffer` 模式在内存中暂存，不落盘 |
| `SCHAT.md` §7 与术语表 | 不解析、不解密、不存储 | 不解析、不解密、**不落盘**；`buffer` 下内存暂存 ≤TTL |
| `SECURITY.md` §4 | 把"服务端暂存"列为严重威胁 | 说明这是需要运维方显式开启、且必须在用户协议里披露的模式 |
| `docs/RELAY-API.md` §3 | 不解析、不存储、不解密 | 同 §7 的限定 |
| 隐私政策 / 儿童规则 | "不收集、不存储、不分析"消息内容 | **需要运营方判断**：内存中 ≤72h 的密文是否仍属"存储"。若改动，必须提升文档版本号并重新取得同意（客户端按版本记录同意） |

> 最后一行**不是技术决定**。`docs/legal/` 里的文本是逐字节同步到 `assets/legal/` 的，客户端会解析版本号并记录同意——改一个字就是一次重新同意。**在对外提供服务之前，这件事应当先由做运营决定的人拍板。**

### 6. systemd 部署

```bash
# 先创建服务账号：systemd 单元里写着 User=schat，而这个用户不会自己出现。
# 少了这一步，服务会启动失败，日志是 "Failed to determine user credentials"。
sudo useradd --system --no-create-home --shell /usr/sbin/nologin schat

sudo install -m 0755 schat-server /usr/local/bin/schat-server
sudo install -m 0644 schat-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now schat-server
```

> **实测提醒：还要告诉服务器它对外叫什么。** 单元文件里的 `ExecStart` 带一个
> `$SCHAT_PUBLIC_HOST` 变量，默认是空的。空着的话，服务器生成的连接 URI 里
> 主机名是 `localhost`——手机配置完之后**连的是手机自己**，症状看起来像"服务器没起来"。
>
> 编辑 `/etc/systemd/system/schat-server.service`，把那一行改成你的地址：
>
> ```ini
> Environment=SCHAT_PUBLIC_HOST=--public-host=203.0.113.10
> ```
>
> 然后 `sudo systemctl daemon-reload && sudo systemctl restart schat-server`。
>
> **只有 `--listen` 是 `0.0.0.0` 时它才生效**（实测）：监听具体地址时，服务器用那个地址。
> 所以「前面挂反向代理、服务端监听 `127.0.0.1`」这种部署，URI 里会写 `127.0.0.1` ✗ ——
> 那种场景需要自己把 URI 里的主机名改掉，或者在客户端手动填写域名。

```bash
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
| `h` | 主机名。**实测**：`--listen` 是 `0.0.0.0` 时用 `--public-host` 的值，没给就是 `localhost`；`--listen` 是具体地址时用它，`--public-host` 被忽略 |
| `p` | 端口 |
| `n` | 服务器显示名称 |
| `fp` | 证书指纹（自签名时用于固定，步骤 3 产出） |
| `ss` | `1` 表示自签名证书，客户端必须校验证书指纹 |

### 证书什么时候会变（实测）

同一个 `--state-dir`、同一组参数下，证书是**复用**的：启动日志会写
`reusing the persisted self-signed certificate`，连续启动三次指纹完全相同。
所以「配置一次即可长期使用」这句话是成立的。

**但这几种改动会让指纹变**，客户端需要重新配置：

| 改了什么 | 为什么 |
|---|---|
| `--name` | 服务器名字写进证书里 |
| `--listen` | 监听地址写进证书的 SAN；`0.0.0.0` 与 `127.0.0.1` 会得到不同的证书 |
| `--state-dir` | 换目录就是换一份状态，那里没有旧证书可复用 |

改这些之前，先想一下有多少客户端已经固定了旧指纹。

步骤 3 完成后，这条 URI 会被渲染成二维码，手机扫码即可完成配置（对应需求八"配置难度不得过高"）。
