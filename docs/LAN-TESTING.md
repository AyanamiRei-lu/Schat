# 局域网测试指南

> **关于本文档中的地址与路径**
>
> 本文档原为一台开发机的实测记录。为公开发布，其中的服务器地址已替换为示例地址
> `192.168.1.100`，项目路径已替换为 `<项目目录>`，证书指纹已替换为占位符。
> 命令可以直接照抄，但请把地址换成**你自己**服务器的局域网地址。
>
> **证书指纹必须来自你自己的服务器**（首次启动时会打印，或用 `--print-uri` 查看）。
> 不要使用本文档里出现过的任何指纹值——一个公开的指纹配上泄露的私钥，等于任何人都能
> 冒充那台服务器，而客户端只验证指纹。

> **先看结论**：**真正的"聊天"还不能在局域网里测。**
> SCS-1 协议核心（步骤 2）与服务端网关（步骤 3a/3b）**都已实现并有测试覆盖**，两个真实客户端可经服务器互发密文；缺的是**客户端的网络层与聊天界面**（步骤 4–5）。
> 现在能在局域网里测的是**服务器可达性 + TLS 证书指纹固定**——这是后续所有测试的基础，值得先跑通。
>
> 本文档随路线图推进而更新。第 7 节给出"每一步能测什么"的对照表。

---

## 1. 本机实测环境（2026-09-24）

已实测确认的事实，你可以直接对照：

| 项目 | 实测值 |
|---|---|
| 活动网卡 | **WLAN**（Intel Dual Band Wireless-AC 8260），以太网未连接 |
| 局域网 IP | **192.168.1.100/24** |
| 默认网关 | 192.168.1.1 |
| Windows 防火墙 | **三个配置档全部关闭**（Domain/Private/Public 均为 `Enabled: False`） |
| 服务端监听 | `::`（全接口，IPv4+IPv6 双栈） |
| 服务端 TLS | ✅ **默认开启**，自签名证书持久化后指纹稳定 |
| 局域网访问实测 | ✅ `https://192.168.1.100:8443/api/v1/health` → **HTTP 200** |

> ⚠️ 本机 IP 是 DHCP 分配的，**重启路由器或休眠后可能变化**。每次测试前重新确认第 2 步。

---

## 2. 五分钟跑通局域网可达性

### 步骤 1：确认本机局域网 IP

```powershell
(Get-NetIPAddress -AddressFamily IPv4 |
  Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -eq 'Dhcp' }
).IPAddress
```

本机预期输出：`192.168.1.100`

### 步骤 2：启动服务端（监听全接口 + 通告局域网 IP）

```powershell
cd <项目目录>
.\build\schat-server.exe --listen 0.0.0.0:8443 --public-host 192.168.1.100 --name lan-test
```

关键参数说明：

| 参数 | 为什么必须这样写 |
|---|---|
| `--listen 0.0.0.0:8443` | 只监听 `127.0.0.1` 的话，手机永远连不上。必须绑定全接口 |
| `--public-host 192.168.1.100` | 决定**连接 URI 里写哪个地址**。不写它，服务端会退化成通告 `localhost`，手机扫码后连的是手机自己 |
| `--state-dir <目录>` | 证书存放位置。指纹因此**在重启后保持不变**，配置一次即可长期使用 |
| `--no-tls` | **仅本地调试**。TLS 默认开启；加它会走明文 HTTP，省掉浏览器证书警告 |

启动后会打印**证书指纹**与**完整连接 URI**：

```
  Certificate fingerprint (SHA-256):
    11:99:30:4B:C3:6C:BA:07:4C:90:70:7E:95:15:A7:3B:A5:70:D5:D3:64:E3:0C:0D:D5:66:A2:4B:B0:71:42:F4

  Client connection URI:
    schat://connect?fp=1199...42f4&h=192.168.1.100&n=lan-test&p=8443&ss=1
```

> **浏览器会提示证书不可信，这是预期行为。** 自签名证书的正确用法是**客户端固定指纹**（URI 里的 `fp=`），而不是依赖公共 CA。浏览器里点"继续访问"即可——你只是在确认链路可达，不是在信任这张证书。

### 步骤 3：先在本机验证

```powershell
# PowerShell 5.1 没有 -SkipCertificateCheck，用 curl（Windows 10+ 自带）
curl.exe -k https://192.168.1.100:8443/api/v1/health
```

预期：JSON，含 `"storage": "none"`、`"fingerprint": "<64 位十六进制>"`，以及尚未实现的功能列表。

### 步骤 4：在手机上验证

确保手机连的是**同一个 Wi-Fi**，然后用手机浏览器打开：

```
https://192.168.1.100:8443/api/v1/health
```

先接受证书警告，再看到同样的 JSON，就说明**局域网链路完全打通了**。这一步很重要：它把"服务器问题"和"客户端问题"彻底分开。

### 步骤 5：拿到连接 URI（后续给客户端用）

启动时已打印，也可单独输出：

```powershell
.\build\schat-server.exe --listen 0.0.0.0:8443 --public-host 192.168.1.100 --name lan-test --print-uri
```

| 参数 | 含义 |
|---|---|
| `h` | 客户端要拨的地址 |
| `p` | 端口 |
| `n` | 服务器显示名 |
| `fp` | **证书指纹（SHA-256，64 位十六进制）**，客户端据此固定证书 |
| `ss=1` | 自签名证书标记，提示客户端必须固定指纹而非依赖公共 CA |

---

## 3. 防火墙：本机不需要，别人可能需要

本机防火墙已全部关闭，所以不挡。**但如果你在其他机器上部署，Windows 默认会拦掉入站 8443。**

以管理员身份运行 PowerShell，放行入站 TCP 8443（仅限专用网络）：

```powershell
New-NetFirewallRule `
  -DisplayName "SCHAT relay (LAN test)" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort 8443 `
  -Action Allow `
  -Profile Private
```

删除规则：

```powershell
Remove-NetFirewallRule -DisplayName "SCHAT relay (LAN test)"
```

> 只放行 `Private` 配置档。不要顺手放开 `Public`——那会让咖啡厅、机场的公共网络也能扫到你的服务端。

---

## 4. 安卓端的坑：明文 HTTP 会被系统拦掉

**这是局域网测试最容易踩的坑，现在就知道能省几小时。**

Android 9（API 28）起，系统默认**禁止明文 HTTP/WebSocket 流量**。也就是说，即使第 2 步手机浏览器能打开，App 内部发起 `http://192.168.1.100:8443` 也会直接被系统拒绝。

当前服务端**还没有 TLS**（TLS 终结在路线图步骤 3），所以现在有两条路：

| 方案 | 适用 | 说明 |
|---|---|---|
| **只做浏览器验证** | 现在 | 浏览器不受该限制，足以证明链路可达 |
| **等步骤 3** | 之后 | 服务端做自签名 TLS，客户端固定证书指纹（`ss=1` + `fp=`），这才是正式路径 |

**不推荐**为了局域网测试在 App 里长期打开 `usesCleartextTraffic="true"`。那是一个"忘了删就上线"的安全隐患。如果调试确实需要，应当用 `network_security_config.xml` 只对特定 IP 放行，且仅限 debug 构建——这一步在步骤 3 一并处理。

---

## 5. 当前能测 / 不能测

| 验证项 | 现在 | 命令 |
|---|---|---|
| 服务端能否启动 | ✅ | `.\build\schat-server.exe --version` |
| 服务端是否监听全接口 | ✅ | `Get-NetTCPConnection -State Listen -LocalPort 8443` |
| 局域网设备能否访问 | ✅ | 手机浏览器打开 `https://<LAN-IP>:8443/api/v1/health`（接受自签名警告） |
| TLS 证书指纹是否稳定 | ✅ | 重启服务端，对比启动时打印的 `fp=` |
| 连接 URI 是否正确 | ✅ | `--print-uri` |
| 配置文件的 JSON 是否生效 | ✅ | `--config lan.json` |
| 内存与体积预算 | ✅ | `tools\verify.ps1` |
| **WebSocket 网关** | ✅ | `/ws` 对非升级请求返回 **400**（已实现；`go test ./server/internal/gateway/` 覆盖真实收发） |
| **App 内配置服务器** | ❌ | 步骤 4 |
| **两台设备互相发消息** | ❌ | 步骤 5（协议与服务端已就绪，缺客户端网络层与 UI） |
| **配置二维码** | ❌ | 步骤 3c（目前需手动输入 URI） |
| **局域网群聊** | ❌ | 步骤 6b |
| **局域网 P2P 大文件直传** | ❌ | 步骤 7 |

服务端已**不再是存根**。用非 WebSocket 请求访问 `/ws` 会得到：

```
HTTP 400
bad websocket handshake
```

真正的客户端收发由 `server/internal/gateway/gateway_test.go` 覆盖：两个真实 WebSocket 客户端经服务器互发信封，**逐字节一致**。

---

## 6. 排查清单：手机连不上时按顺序查

| # | 检查项 | 命令 / 做法 |
|---|---|---|
| 1 | 手机和电脑在**同一个** Wi-Fi？ | 手机上查看 Wi-Fi 名与网关 IP；常见坑是连到了"访客网络"或 5G/2.4G 的不同 SSID |
| 2 | **AP 隔离 / 客户端隔离**是否开启？ | 很多路由器默认开启，导致同一 Wi-Fi 下设备互不可见。这是"浏览器打不开"最常见的原因。登录路由器后台关闭该选项 |
| 3 | 服务端是否监听全接口？ | `Get-NetTCPConnection -State Listen -LocalPort 8443`，`LocalAddress` 应为 `::` 或 `0.0.0.0`，不能是 `127.0.0.1` |
| 4 | 防火墙是否拦截？ | `Get-NetFirewallProfile`，或临时关闭专用网络配置档测试 |
| 5 | 地址是否写错？ | 现在是 `https://`（TLS 默认开启）。浏览器需先接受自签名证书警告。若用 `--no-tls` 启动则仍是 `http://` |
| 6 | IP 是否变了？ | 重新执行第 2 步；建议在路由器上给本机绑定静态 IP / DHCP 保留 |
| 7 | 端口被占用？ | 服务端启动会报错；换 `--listen 0.0.0.0:9443` 试试 |
| 8 | 公司/学校网络 | 这类网络常做端口隔离与出站限制，局域网直连基本不可行。改用手机热点：让电脑连手机热点，此时两者在同一子网 |

---

## 7. 随路线图推进，局域网测试能力的演进

| 里程碑 | 局域网可测内容 | 需要几台设备 |
|---|---|---|
| **现在（步骤 3a/3b 完成）** | 服务器可达性、健康检查（TLS + 指纹）、连接 URI、WebSocket 网关 | 1 台电脑 + 1 部手机（浏览器） |
| 步骤 2 完成 | SCS-1 握手与棘轮（✅ 已可在本机用 `go test` 验证） | 0（本机测试） |
| 步骤 3a/3b 完成 | ✅ WebSocket 真正连通、TLS 自签名 + 指纹固定 | 1 + 1 |
| 步骤 3c 完成 | 二维码生成（扫码代替手输 URI） | 1 + 1 |
| 步骤 4 完成 | App 内配置服务器、连接成功/失败提示 | 1 + 1 |
| **步骤 5 完成** | **两部手机真正互发加密消息**（这是第一个"能聊天"的里程碑） | 2 部手机（或 1 手机 + 1 模拟器） |
| 步骤 6b 完成 | 局域网群聊（三人以上） | 3+ |
| 步骤 7 完成 | 局域网内 P2P 直传图片/视频/文件，不经服务器中转 | 2+ |

**建议的验证顺序**：先在**一台机器上跑两个客户端实例**（模拟器 + 手机）验证协议正确性，再上多台真机。局域网联调的主要价值是验证真实网络条件下的行为（NAT、丢包、切网、休眠重连），协议正确性不该在这里调。

---

## 8. 安全警告

服务端**默认开启 TLS**（TLS 1.2 起，自签名证书，客户端固定指纹）。

| 风险 | 说明 |
|---|---|
| 流量可被旁观 | 同一局域网内的任何设备都能看到你访问了哪个端点、包有多大 |
| **消息内容仍然安全** | 因为 SCHAT 的加密是端到端的设计——不过目前还没有消息功能，所以这条现在无从体现 |
| 不要在公共网络测试 | 咖啡厅、机场、酒店 Wi-Fi 上不要启动，也不要放行 `Public` 防火墙配置档 |
| 用 `live` 模式最干净 | 默认模式，什么都不存。`buffer` 模式的内容也只在内存，进程退出即消失 |

**TLS 终结与证书指纹固定在路线图步骤 3 实现。** 在那之前，这套服务端只适合在**你自己信任的局域网**里做开发验证。

---

## 附：本机常用命令速查

```powershell
$root = '<项目目录>'
$exe  = "$root\build\schat-server.exe"

# 查局域网 IP
(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '127.*' -and $_.PrefixOrigin -eq 'Dhcp' }).IPAddress

# 构建（若 exe 不存在或已过期）
cd "$root\server"; go build -o "$root\build\schat-server.exe" ./cmd/schat-server

# 启动（局域网模式）
& $exe --listen 0.0.0.0:8443 --public-host 192.168.1.100 --mode buffer --name lan-test

# 查看监听状态
Get-NetTCPConnection -State Listen -LocalPort 8443

# 本机自测
Invoke-WebRequest http://192.168.1.100:8443/api/v1/health -UseBasicParsing | Select-Object -ExpandProperty Content

# 打印连接 URI
& $exe --listen 0.0.0.0:8443 --public-host 192.168.1.100 --name lan-test --print-uri

# 一键全量自检（含内存与体积预算断言）
powershell -ExecutionPolicy Bypass -File "$root\tools\verify.ps1"
```

**本机实测可用的启动命令：**

```powershell
.\build\schat-server.exe --listen 0.0.0.0:8443 --public-host 192.168.1.100 --mode buffer --name lan-test
```
