<#
.SYNOPSIS
    Measures the relay's memory and CPU cost per connected client.

.DESCRIPTION
    Answers "what size server do I need" with a measurement rather than an estimate.

    It starts a local relay, records its idle working set, then opens a series of client
    counts with cmd/schat-loadtest and records the working set at each step. The difference
    divided by the connection count is the per-client cost, which is the number the sizing
    table in docs/SERVER-SETUP.md is built from.

    Plain WebSocket (--no-tls) is used so that the test client needs no certificate
    handling. That UNDERESTIMATES the real figure: a TLS connection additionally holds the
    TLS record buffers and handshake state for its lifetime. The script prints that caveat
    with its result rather than hiding it.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\measure-relay-load.ps1
#>

[CmdletBinding()]
param(
    # Connection counts to measure, in order, comma separated.
    #
    # A string rather than [int[]] because this script is normally invoked with
    # `powershell -File`, which passes every argument as a string and cannot bind an array.
    [string]$Counts = '1,100,500,1000',

    # How long each step is held open before the working set is read.
    [int]$HoldSeconds = 12,

    [int]$Port = 8443
)

$ErrorActionPreference = 'Stop'

$countList = @($Counts.Split(',') | ForEach-Object { [int]$_.Trim() })

$repoRoot = Split-Path -Parent $PSScriptRoot
$serverDir = Join-Path $repoRoot 'server'
$binary = Join-Path $repoRoot 'build\schat-server.exe'
$loadtest = Join-Path $repoRoot 'build\schat-loadtest.exe'
$stateDir = Join-Path $repoRoot 'build\load-state'

$env:GOWORK = 'off'
New-Item -ItemType Directory -Force -Path (Join-Path $repoRoot 'build') | Out-Null
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null

Write-Host ''
Write-Host '  Building the relay and the load generator' -ForegroundColor Cyan
Push-Location $serverDir
& go build -o $binary ./cmd/schat-server
& go build -o $loadtest ./cmd/schat-loadtest
Pop-Location

Write-Host '  Starting the relay (plain WebSocket, loopback only)' -ForegroundColor Cyan
$relay = Start-Process -FilePath $binary `
    -ArgumentList @('--listen', "127.0.0.1:$Port", '--no-tls', '--name', 'load-measure', '--state-dir', $stateDir) `
    -PassThru -WindowStyle Hidden

try {
    # Wait for the listener rather than sleeping a fixed amount.
    $ready = $false
    for ($i = 0; $i -lt 40; $i++) {
        Start-Sleep -Milliseconds 250
        if (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) {
            $ready = $true
            break
        }
    }
    if (-not $ready) { throw "the relay did not start listening on port $Port" }

    Start-Sleep -Seconds 2
    $relay.Refresh()
    $idleMb = [math]::Round($relay.WorkingSet64 / 1MB, 2)
    Write-Host ''
    Write-Host ("  idle working set: {0} MB" -f $idleMb) -ForegroundColor Green
    Write-Host ''
    Write-Host ("  {0,-10} {1,-14} {2,-14} {3,-14}" -f 'clients', 'working set', 'delta', 'bytes/client')
    Write-Host ("  {0,-10} {1,-14} {2,-14} {3,-14}" -f '-------', '-----------', '-----', '------------')

    $rows = @()
    foreach ($n in $countList) {
        $client = Start-Process -FilePath $loadtest `
            -ArgumentList @('-url', "ws://127.0.0.1:$Port/ws", '-n', "$n", '-hold', "$($HoldSeconds + 10)s") `
            -PassThru -WindowStyle Hidden
        try {
            # Let the connections settle and the relay reach a steady state.
            Start-Sleep -Seconds $HoldSeconds

            $relay.Refresh()
            $mb = $relay.WorkingSet64 / 1MB
            $delta = $mb - $idleMb
            $perClient = if ($n -gt 0) { ($relay.WorkingSet64 - ($idleMb * 1MB)) / $n } else { 0 }

            Write-Host ("  {0,-10} {1,-14} {2,-14} {3,-14:N0}" -f $n, ("{0:N2} MB" -f $mb), ("{0:N2} MB" -f $delta), $perClient)

            $rows += [pscustomobject]@{
                Clients        = $n
                WorkingSetMb   = [math]::Round($mb, 2)
                DeltaMb        = [math]::Round($delta, 2)
                BytesPerClient = [math]::Round($perClient)
            }
        } finally {
            if (-not $client.HasExited) { $client.Kill() }
        }
        Start-Sleep -Seconds 3
    }

    Write-Host ''
    Write-Host '  Caveat: plain WebSocket. A TLS connection also holds its record buffers, so a' -ForegroundColor Yellow
    Write-Host '          real deployment costs somewhat more per client than these figures.' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  Result (paste into docs/SERVER-SETUP.md):' -ForegroundColor Cyan
    $rows | Format-Table -AutoSize | Out-String | Write-Host
} finally {
    if (-not $relay.HasExited) { $relay.Kill() }
    Remove-Item $stateDir -Recurse -Force -ErrorAction SilentlyContinue
}
