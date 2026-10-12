# Build the SCS-1 protocol core into an Android AAR with gomobile.
#
# STATUS: WORKING as of roadmap step 4a. Verified on the development machine:
#   schat-protocol.aar, 7.99 MB, arm64 + arm + amd64, 118 seconds.
#
# Prerequisites, all already satisfied on the development machine and recorded here
# so they can be reproduced elsewhere:
#
#   1. gomobile and gobind installed:
#        go install golang.org/x/mobile/cmd/gomobile@latest
#        go install golang.org/x/mobile/cmd/gobind@latest
#   2. golang.org/x/mobile recorded in protocol/go.mod. gomobile bind refuses to run
#      otherwise ("requires golang.org/x/mobile in the current module"), so the
#      dependency is declared as a tool directive:
#        cd protocol && go get -tool golang.org/x/mobile/cmd/gobind
#      Note: this adds x/mobile to the CLIENT-side protocol module only. The relay
#      still depends on nothing but the standard library, which tools/verify.ps1
#      asserts mechanically.
#   3. Android SDK with NDK (D:\asdk\ndk\28.2.13676358 on this machine).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File tools\build-protocol.ps1

[CmdletBinding()]
param(
    # Android API level to target. 26 matches the app's minSdk.
    [int]$AndroidApi = 26,

    # ABIs to build for. x86 (32-bit) is omitted deliberately: no current Android
    # device uses it, and it would add ~3 MB for emulator-only coverage. If you need
    # a 32-bit x86 emulator, add android/386 here.
    [string]$Target = 'android/arm64,android/arm,android/amd64',

    # Where to write the AAR.
    [string]$Output = ''
)

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$env:GOTELEMETRY = 'off'

if (-not $Output) {
    $Output = Join-Path $root 'android\app\libs\schat-protocol.aar'
}

# gomobile needs the NDK from the Android SDK.
if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
    $sdk = 'D:\asdk'
    if (Test-Path $sdk) {
        $env:ANDROID_HOME = $sdk
        $env:ANDROID_SDK_ROOT = $sdk
        Write-Host "Android SDK: $sdk" -ForegroundColor DarkGray
    }
    else {
        throw 'Android SDK not found. Set ANDROID_HOME or edit the fallback path in this script.'
    }
}

if (-not $env:ANDROID_NDK_HOME) {
    $ndkRoot = Join-Path $env:ANDROID_HOME 'ndk'
    if (Test-Path $ndkRoot) {
        $newest = Get-ChildItem $ndkRoot -Directory | Sort-Object Name -Descending | Select-Object -First 1
        if ($newest) {
            $env:ANDROID_NDK_HOME = $newest.FullName
            Write-Host "Android NDK: $($newest.FullName)" -ForegroundColor DarkGray
        }
    }
}

# The build must resolve the protocol module on its own. Leaving the repository's
# go.work active makes gomobile complain about the workspace.
$env:GOWORK = 'off'
if (-not ($env:PATH -split ';' | Where-Object { $_ -like '*\go\bin' })) {
    $env:PATH = "$env:PATH;$env:USERPROFILE\go\bin"
}

Write-Host ''
Write-Host '  Building SCS-1 protocol AAR' -ForegroundColor Cyan
Write-Host "  target: $Target   api: $AndroidApi" -ForegroundColor DarkGray

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Output) | Out-Null

$sw = [System.Diagnostics.Stopwatch]::StartNew()
Push-Location (Join-Path $root 'protocol')
try {
    & gomobile bind "-target=$Target" -androidapi $AndroidApi -o $Output ./mobile
    if ($LASTEXITCODE -ne 0) { throw "gomobile bind failed with exit code $LASTEXITCODE" }
}
finally {
    Pop-Location
    $env:GOWORK = ''
}
$sw.Stop()

$aar = Get-Item $Output
Write-Host ''
Write-Host ("  built {0}  ({1:N2} MB) in {2:N1}s" -f $aar.Name, ($aar.Length / 1MB), $sw.Elapsed.TotalSeconds) -ForegroundColor Green
Write-Host '  The AAR is gitignored: it is a build artifact, not source.' -ForegroundColor DarkGray
