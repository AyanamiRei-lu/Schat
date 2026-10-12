<#
.SYNOPSIS
    Downloads the official MLS test vectors used by protocol/mls.

.DESCRIPTION
    The vectors are NOT vendored into this repository, on purpose.

    They are published by the MLS working group in github.com/mlswg/mls-implementations,
    which carries NO LICENSE file. With no license the default applies — all rights
    reserved — so copying those files into SCHAT would be a licensing problem. Fetching
    them locally to verify an implementation is the intended use of a test vector.

    The directory they land in is gitignored, so they can never be committed by accident.
    Tests that need them skip cleanly when they are absent, which keeps an ordinary offline
    `go test ./...` green while still allowing the byte-exact verification this project
    requires as the acceptance criterion for step 6a.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\fetch-mls-vectors.ps1
#>

[CmdletBinding()]
param(
    # Fetch every vector file, not just the ones the current milestone needs.
    [switch]$All
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$dest = Join-Path $repoRoot 'protocol\mls\vectors'
$base = 'https://raw.githubusercontent.com/mlswg/mls-implementations/main/test-vectors'

# The defaults are the files the milestones implemented so far actually read:
#   crypto-basics  -> M2  the labelled KDF, signature and HPKE operations
#   key-schedule   -> M2  the epoch key schedule
#   tree-math      -> M3  node indices, parents, siblings
#   secret-tree    -> M3  per-sender ratchets
#   tree-validation-> M3  tree hashes and resolutions
#   psk_secret     -> M2  the PSK combiner
$defaultFiles = @(
    'crypto-basics.json',
    'key-schedule.json',
    'psk_secret.json',
    'tree-math.json',
    'secret-tree.json',
    'tree-validation.json'
)

$allFiles = $defaultFiles + @(
    'tree-operations.json',
    'treekem.json',
    'transcript-hashes.json',
    'message-protection.json',
    'welcome.json',
    'messages.json',
    'deserialization.json',
    'passive-client-welcome.json',
    'passive-client-handling-commit.json',
    'passive-client-random.json'
)

$files = if ($All) { $allFiles } else { $defaultFiles }

New-Item -ItemType Directory -Force -Path $dest | Out-Null

Write-Host ''
Write-Host '  Fetching official MLS test vectors' -ForegroundColor Cyan
Write-Host "  source: $base"
Write-Host "  dest:   $dest"
Write-Host ''

$total = 0
foreach ($file in $files) {
    $target = Join-Path $dest $file

    if (Test-Path $target) {
        $size = (Get-Item $target).Length
        Write-Host ("  {0,-40} already present ({1:N0} bytes)" -f $file, $size) -ForegroundColor DarkGray
        $total += $size
        continue
    }

    try {
        # -UseBasicParsing keeps this working on PowerShell 5.1 without the IE engine.
        Invoke-WebRequest -Uri "$base/$file" -OutFile $target -UseBasicParsing
        $size = (Get-Item $target).Length
        Write-Host ("  {0,-40} {1:N0} bytes" -f $file, $size) -ForegroundColor Green
        $total += $size
    } catch {
        Write-Host ("  {0,-40} FAILED: {1}" -f $file, $_.Exception.Message) -ForegroundColor Red
    }
}

Write-Host ''
Write-Host ("  {0:N0} bytes total" -f $total)
Write-Host ''
Write-Host '  NOTE: this directory is gitignored because the upstream repository has no' -ForegroundColor Yellow
Write-Host '        license. Do not commit these files.' -ForegroundColor Yellow
Write-Host ''
Write-Host '  Run the verification with:' -ForegroundColor Cyan
Write-Host '    cd protocol; $env:GOWORK="off"; go test ./mls/... -count=1 -v'
Write-Host ''
