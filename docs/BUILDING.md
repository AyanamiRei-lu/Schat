# 构建指南

本文件说明如何在这台开发机上从零构建 SCHAT 的各个部分。

---

## 0. 环境现状（本机实测，2026-09-24）

| 组件 | 位置 / 版本 | 备注 |
|---|---|---|
| Go | `go1.27.0 windows/amd64` | 正常 |
| JDK | Temurin **25.0.4.1 LTS** | `JAVA_HOME` 未设置，由 Gradle toolchain 机制解析 |
| Android SDK | **`D:\Android\Sdk`**（非标准路径） | 含 platform 27/35/36/37、build-tools 35/36/37、NDK、emulator、adb |
| Gradle | 由 Wrapper 提供（9.5.0） | 发行版已缓存于 `~/.gradle/wrapper/dists` |
| Gradle 依赖缓存 | **`D:\gradle-home`**（本项目约定） | C 盘仅剩约 5.6 GB，必须重定向 |
| 网络 | 沙箱内**不通**，提权后**可用** | 首次构建需要联网拉取依赖 |

---

## 1. 重要：Gradle 缓存目录必须重定向

本机 C 盘空间紧张（约 5.6 GB 可用），而 Compose 依赖约需 1.5–2.5 GB。
**每次调用 Gradle 前都要设置环境变量**，否则可能写满系统盘：

```powershell
$env:GRADLE_USER_HOME = "D:\gradle-home"
```

建议写入 PowerShell 配置文件，避免每次手动设置：

```powershell
Add-Content $PROFILE '$env:GRADLE_USER_HOME = "D:\gradle-home"'
```

---

## 2. 协议核心与服务端（Go）

无需网络（依赖下载一次后可离线构建）。

> **重要：Go 命令必须在模块目录内执行。**
> 仓库根目录有 `go.work`，它让两个模块无需先发布就能互相引用，但**从根目录执行
> `go build ./...` 会被 Go 拒绝**：
>
> ```
> pattern ./...: directory prefix . does not contain modules listed in go.work
> ```
>
> 因为根目录本身不属于任何 workspace 模块。请按下面的方式逐个模块执行。

```powershell
$root = '<项目目录>'

# ---- 协议核心 ----
cd "$root\protocol"
go build ./...
go vet ./...
go test ./... -count=1
go test ./... -count=1 -race

# ---- 服务端（零第三方依赖）----
cd "$root\server"
go build ./...
go vet ./...
go test ./... -count=1
go test ./... -count=1 -race

# ---- 格式检查（CI 中必须为空）----
cd $root
gofmt -l protocol server

# ---- 构建服务端二进制 ----
cd "$root\server"
go build -o "$root\build\schat-server.exe" ./cmd/schat-server
```

### 机械校验"服务端不含解密代码"

这两条断言是 SCHAT 零知识承诺的**可验证依据**，不依赖任何人的口头保证。
必须加 `GOWORK=off`，否则 workspace 模式会强行把 protocol 模块算进来，使校验失去意义。

```powershell
cd "$root\server"
$env:GOWORK = 'off'

# 必须无输出：服务端不得依赖协议核心
go list -deps ./... | Select-String 'schat/protocol'

# 必须只有自身模块：服务端不得有任何第三方依赖
go list -m all

Remove-Item Env:\GOWORK
```

### 运行服务端

```powershell
# 零配置启动（自签名 TLS + live 模式）
.\build\schat-server.exe

# 指定端口与 buffer 模式
.\build\schat-server.exe --listen 127.0.0.1:18443 --metrics-listen 127.0.0.1:19090 --mode buffer

# 只打印客户端连接 URI
.\build\schat-server.exe --print-uri

# 验证
Invoke-WebRequest http://127.0.0.1:18443/api/v1/health -UseBasicParsing
Invoke-WebRequest http://127.0.0.1:19090/metrics -UseBasicParsing
```

> `--help` 不可用是因为 `flag` 包在 `-h` 时返回 `flag.ErrHelp`，当前实现会把它当作错误打印到 stderr。

---

## 3. 安卓客户端

**首次构建必须联网**（需要下载 Compose 与 AGP 依赖）。

```powershell
$env:GRADLE_USER_HOME = "D:\gradle-home"
cd <项目目录>\android

# 调试包
.\gradlew.bat assembleDebug

# 只看配置是否正确，不编译（快得多）
.\gradlew.bat :app:tasks

# 安装到已连接的设备
.\gradlew.bat installDebug
```

产物路径：`android\app\build\outputs\apk\debug\app-debug.apk`

### 如果依赖下载失败

Gradle 会缓存已下载的依赖，后续构建可加 `--offline` 完全离线执行：

```powershell
.\gradlew.bat assembleDebug --offline
```

---

## 4. 协议核心编译为 Android AAR

**状态：已验证可用**（步骤 4a）。开发机实测产出 `schat-protocol.aar`，7.99 MB，arm64 + arm + amd64，约 118 秒。

```powershell
powershell -ExecutionPolicy Bypass -File tools\build-protocol.ps1
```

产物写入 `android/app/libs/schat-protocol.aar`，属构建产物，已在 `.gitignore` 中。

前置条件（开发机已满足，换机器需注意）：

1. 安装 gomobile 与 gobind：
   ```powershell
   go install golang.org/x/mobile/cmd/gomobile@latest
   go install golang.org/x/mobile/cmd/gobind@latest
   ```
2. 在 `protocol/go.mod` 中记录 `golang.org/x/mobile`。否则 gomobile 会直接拒绝运行，报 `requires golang.org/x/mobile in the current module`：
   ```powershell
   cd protocol
   go get -tool golang.org/x/mobile/cmd/gobind
   ```
   > 这会给**客户端**协议模块引入 `x/mobile` 桥接依赖。**服务端不受影响，仍是零第三方依赖**——该性质由 `tools/verify.ps1` 机械校验。
3. Android SDK 含 NDK（本机 `D:\Android\Sdk\ndk\28.2.13676358`）。

> **ABI 覆盖**：默认构建 `arm64,arm,amd64`，**不含 32 位 `x86`**。真机几乎全是 ARM，不受影响；但 32 位 x86 模拟器会因缺少 `libgojni.so` 而崩溃。需要时在脚本 `-Target` 中加入 `android/386` 重建。

---

## 5. 一键自检

```powershell
powershell -ExecutionPolicy Bypass -File tools\verify.ps1
```

该脚本依次执行：gofmt 检查 → 逐模块 `go build` → `go vet` → `go test` → `go test -race` →
服务端依赖策略断言 → 二进制体积断言 → 实测启动 TLS 服务端并断言健康检查返回 200 与证书指纹、
`/ws` 对非升级请求返回 400（证明网关已实现）、内存不超预算、证书已持久化。
任一项失败即非零退出，可直接作为 CI 门禁。

安卓侧的编译验证需要单独执行第 3 节命令（因为首次需要联网）。

---

## 6. 常见问题

| 现象 | 原因 | 解决 |
|---|---|---|
| Gradle 报 `SDK location not found` | `android/local.properties` 缺失 | 创建该文件并写入 `sdk.dir=D\:\\asdk` |
| Gradle 报找不到 JDK 25 | toolchain 未安装且无网络 | 安装 Temurin 25，或联网让 foojay 自动下载 |
| C 盘空间告警 | 未设置 `GRADLE_USER_HOME` | 见第 1 节 |
| `go: downloading ...` 卡住 | 沙箱阻断了网络 | 需要在允许网络的权限下运行；依赖下载一次后即可离线 |
| `permission denied` 执行 `go.exe` / `java.exe` | 沙箱限制 | 同上 |
| Compose 依赖解析失败 | 网络不通 | 联网重试，或使用 `--offline`（前提是已缓存） |
