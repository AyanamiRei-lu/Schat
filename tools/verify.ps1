# SCHAT one-command self-check (Go side).
#
# Runs every verification that does not need a network connection: formatting,
# build, vet, tests, the race detector, dependency-policy assertions, and a real
# server smoke test with memory and size budgets.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\verify.ps1
#
# Exit code is 0 only when every step passed, so this is suitable as a CI gate.
#
# WHY GO COMMANDS RUN PER MODULE
#
# The repository has a go.work at its root listing ./protocol and ./server, which
# makes `go build ./...` from the module directories work without publishing the
# protocol module first. It does NOT make `go build ./...` work from the
# repository root: Go rejects that with
#
#   pattern ./...: directory prefix . does not contain modules listed in go.work
#
# because the root directory is not itself inside a workspace module. Every Go
# command below therefore runs inside a specific module.

[CmdletBinding()]
param(
    # Skip the race detector when cgo is unavailable in the environment.
    [switch]$SkipRace,

    # Keep the smoke-test server port configurable in case of a conflict.
    [int]$SmokePort = 18443
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$modules = @('protocol', 'server')
$env:GOTELEMETRY = 'off'

$script:Failures = 0

function Write-Step([string]$Name) {
    Write-Host ''
    Write-Host ('=' * 68) -ForegroundColor DarkGray
    Write-Host "  $Name" -ForegroundColor Cyan
    Write-Host ('=' * 68) -ForegroundColor DarkGray
}

function Invoke-Checked([string]$Name, [scriptblock]$Body) {
    Write-Step $Name
    try {
        & $Body
        Write-Host "PASS  $Name" -ForegroundColor Green
    }
    catch {
        Write-Host "FAIL  $Name -- $_" -ForegroundColor Red
        $script:Failures++
    }
}

# Runs one go command in every module, failing on the first non-zero exit.
function Invoke-GoInModules([string[]]$GoArgs) {
    foreach ($m in $modules) {
        Write-Host "  -> $m : go $($GoArgs -join ' ')" -ForegroundColor DarkGray
        Push-Location "$root\$m"
        try {
            & go @GoArgs
            if ($LASTEXITCODE -ne 0) {
                throw "go $($GoArgs -join ' ') failed in module '$m' (exit $LASTEXITCODE)"
            }
        }
        finally { Pop-Location }
    }
}

Write-Host ''
Write-Host '  SCHAT self-check' -ForegroundColor White
Write-Host "  repository: $root" -ForegroundColor DarkGray

# --------------------------------------------------------------------------
# 1. Formatting. A non-empty result here fails CI; the codebase is kept gofmt
#    clean so that formatting never shows up in a review diff.
# --------------------------------------------------------------------------
Invoke-Checked 'gofmt (formatting)' {
    $unformatted = & gofmt -l "$root\protocol" "$root\server"
    if ($unformatted) {
        Write-Host ($unformatted -join "`n")
        throw 'files need formatting; run: gofmt -w protocol server'
    }
    Write-Host 'all files formatted'
}

Invoke-Checked 'go build ./... (per module)' {
    Invoke-GoInModules @('build', './...')
}

Invoke-Checked 'go vet ./... (per module)' {
    Invoke-GoInModules @('vet', './...')
}

Invoke-Checked 'go test ./... (per module)' {
    Invoke-GoInModules @('test', './...', '-count=1')
}

if (-not $SkipRace) {
    Invoke-Checked 'go test -race ./... (per module)' {
        Invoke-GoInModules @('test', './...', '-count=1', '-race')
    }
}

# --------------------------------------------------------------------------
# 2. Dependency-policy assertions.
#
#    The relay server must not link the protocol core. That is the architectural
#    basis for the "the server cannot read your messages" claim in SCHAT.md
#    section 7.2, so it is checked mechanically rather than trusted.
#
#    GOWORK=off is essential: in workspace mode `go list -deps` would pull in the
#    protocol module even though server/go.mod does not require it, which would
#    defeat the whole point of the check.
# --------------------------------------------------------------------------
Invoke-Checked 'server must not depend on the protocol core' {
    Push-Location "$root\server"
    $savedWork = $env:GOWORK
    $env:GOWORK = 'off'
    try {
        $deps = & go list -deps ./... 2>&1
        if ($LASTEXITCODE -ne 0) { throw "go list -deps failed: $deps" }
        $leak = $deps | Where-Object { $_ -like '*schat/protocol*' }
        if ($leak) {
            Write-Host ($leak -join "`n")
            throw 'the server links the protocol core, which breaks the zero-knowledge guarantee'
        }
        Write-Host 'server dependency graph contains no protocol core'
    }
    finally {
        $env:GOWORK = $savedWork
        Pop-Location
    }
}

Invoke-Checked 'server has no third-party dependencies' {
    Push-Location "$root\server"
    $savedWork = $env:GOWORK
    $env:GOWORK = 'off'
    try {
        $mods = & go list -m all
        if ($LASTEXITCODE -ne 0) { throw "go list -m all failed" }
        $external = $mods | Where-Object { $_ -notmatch '^github\.com/schat/schat/server' }
        if ($external) {
            Write-Host ($external -join "`n")
            throw 'the server gained a dependency; server/go.mod documents why it must not'
        }
        Write-Host 'server depends on nothing but the standard library'
    }
    finally {
        $env:GOWORK = $savedWork
        Pop-Location
    }
}

# --------------------------------------------------------------------------
# 3. Build the binary and smoke test it for real.
# --------------------------------------------------------------------------
Invoke-Checked 'build schat-server' {
    New-Item -ItemType Directory -Force -Path "$root\build" | Out-Null
    Push-Location "$root\server"
    try {
        & go build -o "$root\build\schat-server.exe" ./cmd/schat-server
        if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
    }
    finally { Pop-Location }

    $exe = Get-Item "$root\build\schat-server.exe"
    $mb = [math]::Round($exe.Length / 1MB, 2)
    Write-Host "binary size: $mb MB (budget: 15 MB)"
    if ($mb -gt 15) { throw "binary is $mb MB, over the 15 MB budget in SCHAT.md section 8.1" }
}

Invoke-Checked 'server smoke test (TLS + gateway)' {
    $exe = "$root\build\schat-server.exe"
    $stateDir = Join-Path ([System.IO.Path]::GetTempPath()) ("schat-verify-" + [guid]::NewGuid().ToString("n"))

    Write-Host "  state dir: $stateDir" -ForegroundColor DarkGray

    $proc = Start-Process -FilePath $exe `
        -ArgumentList '--listen', "127.0.0.1:$SmokePort",
                     '--metrics-listen', "127.0.0.1:$($SmokePort + 1000)",
                     '--state-dir', $stateDir,
                     '--mode', 'buffer' `
        -PassThru -WindowStyle Hidden

    try {
        Start-Sleep -Seconds 3

        if ($proc.HasExited) { throw "the server exited immediately with code $($proc.ExitCode)" }

        # curl.exe is used rather than Invoke-WebRequest because -k works identically
        # under both Windows PowerShell 5.1 and PowerShell 7, and because it gives us
        # the status code without throwing on a non-2xx response.
        $health = & curl.exe -sk --max-time 10 -o - -w "`nHTTPSTATUS:%{http_code}" "https://127.0.0.1:$SmokePort/api/v1/health" 2>&1 | Out-String
        if ($health -notmatch 'HTTPSTATUS:200') {
            throw "health over TLS did not return 200: $health"
        }
        if ($health -notmatch '"storage"\s*:\s*"none"') {
            throw 'the server did not report zero storage'
        }
        # A pinned self-signed certificate is only usable if the fingerprint is
        # published, so its presence is part of the contract.
        if ($health -notmatch '"fingerprint"\s*:\s*"[0-9a-f]{64}"') {
            throw 'health did not report a SHA-256 certificate fingerprint'
        }
        Write-Host '/api/v1/health over TLS returns 200 with a fingerprint'

        # /ws must now reject a plain GET as a malformed upgrade (400), rather than
        # reporting that the gateway is unimplemented (501). This single assertion is
        # what distinguishes "the relay is wired up" from "the relay is a stub".
        $ws = & curl.exe -sk --max-time 10 -o /dev/null -w "%{http_code}" "https://127.0.0.1:$SmokePort/ws" 2>&1 | Out-String
        $wsCode = $ws.Trim()
        if ($wsCode -ne '400') {
            throw "/ws returned $wsCode for a non-upgrade request; expected 400 from the real gateway"
        }
        Write-Host '/ws is implemented (rejects a non-upgrade request with 400)'

        $rss = [math]::Round((Get-Process -Id $proc.Id).WorkingSet64 / 1MB, 1)
        Write-Host "resident memory: $rss MB (budget: 20 MB)"
        if ($rss -gt 20) { throw "server used $rss MB, over the 20 MB budget" }

        # The persisted certificate is what makes "scan once" survive a restart.
        if (-not (Test-Path (Join-Path $stateDir 'self-signed-cert.pem'))) {
            throw 'the self-signed certificate was not persisted'
        }
        Write-Host 'the self-signed certificate was persisted'
    }
    finally {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
        Remove-Item -Recurse -Force $stateDir -ErrorAction SilentlyContinue
    }
}

Invoke-Checked 'printed connection URI is complete' {
    $exe = "$root\build\schat-server.exe"
    $stateDir = Join-Path ([System.IO.Path]::GetTempPath()) ("schat-uri-" + [guid]::NewGuid().ToString("n"))

    try {
        $uri = & $exe --listen '0.0.0.0:8443' --public-host '192.168.1.158' --name 'verify' --state-dir $stateDir --print-uri 2>&1 | Out-String
        $uri = $uri.Trim()
        Write-Host "  $uri"

        foreach ($want in @('schat://connect?', 'h=192.168.1.158', 'ss=1', 'fp=')) {
            if ($uri -notmatch [regex]::Escape($want)) {
                throw "the connection URI is missing '$want'"
            }
        }
        if ($uri -notmatch 'fp=[0-9a-f]{64}') {
            throw 'the connection URI does not carry a SHA-256 fingerprint'
        }
    }
    finally {
        Remove-Item -Recurse -Force $stateDir -ErrorAction SilentlyContinue
    }
}

# --------------------------------------------------------------------------
Write-Host ''
if ($script:Failures -eq 0) {
    Write-Host '  ALL CHECKS PASSED' -ForegroundColor Green
    Write-Host ''
    Write-Host '  Not covered here: the Android build.' -ForegroundColor Yellow
    Write-Host '  Run it separately; see docs/BUILDING.md section 3.' -ForegroundColor Yellow
    exit 0
}

Write-Host "  $script:Failures CHECK(S) FAILED" -ForegroundColor Red
Write-Host '  Not covered here: the Android build.' -ForegroundColor Yellow
Write-Host '  Run it separately; see docs/BUILDING.md section 3.' -ForegroundColor Yellow
exit 1
