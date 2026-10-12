<#
.SYNOPSIS
    Regenerates the Android launcher icon from the master artwork.

.DESCRIPTION
    The launcher icon is an adaptive icon: a background colour plus a foreground layer
    drawn on a 108x108dp canvas of which only the middle ~72dp is guaranteed to survive
    whatever mask the launcher applies (circle, squircle, rounded square...).

    Because of that safe zone, the master art cannot simply be copied to the target size.
    This script finds the artwork's actual bounding box, scales THAT to 66% of the canvas
    and centres it, so the glyph is framed identically under every mask shape instead of
    being cropped by the round one.

    It also renders a preview showing the result under the two mask shapes Android uses, so
    the framing can be checked without installing anything.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\make-icon.ps1
#>

[CmdletBinding()]
param(
    # Master artwork: the white glyph on a transparent canvas.
    [string]$Master = '',

    # Fraction of the canvas the glyph's bounding box should occupy. 0.66 matches the
    # 72dp/108dp safe zone.
    [double]$SafeZone = 0.66
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $Master) { $Master = Join-Path $repoRoot 'assets\icon\icon-master.png' }

$resRoot = Join-Path $repoRoot 'android\app\src\main\res'
$previewPath = Join-Path $repoRoot 'build\icon-preview.png'

if (-not (Test-Path $Master)) { throw "master artwork not found: $Master" }

$source = [System.Drawing.Bitmap]::FromFile($Master)
Write-Host ''
Write-Host ("  master: {0} ({1}x{2})" -f (Split-Path -Leaf $Master), $source.Width, $source.Height) -ForegroundColor Cyan

# ----------------------------------------------------------------------
# 1. Confirm the artwork really is transparent.
#
# A "transparent-looking" checkerboard can be painted into an opaque PNG by mistake, and
# the result would be a checkerboard tile on the launcher. Checking the alpha channel is
# the only way to tell the two apart.

$corner = $source.GetPixel(0, 0)
$midTop = $source.GetPixel([int]($source.Width / 2), 2)
Write-Host ("  alpha at corner={0} top-centre={1}" -f $corner.A, $midTop.A) -ForegroundColor DarkGray
if ($corner.A -ne 0 -and $midTop.A -ne 0) {
    throw "the master artwork has no transparent pixels: it looks like the checkerboard is PAINTED IN rather than real transparency. Fix the source image first."
}

# ----------------------------------------------------------------------
# 2. Find the glyph's bounding box.
#
# Sampled on a coarse grid: a full scan of 2.7 million pixels through PowerShell takes
# minutes, and a 4-pixel grid is exact to within 4 pixels on a 1656-pixel canvas, which is
# far below anything visible.

$step = 4
$minX = $source.Width; $minY = $source.Height; $maxX = -1; $maxY = -1

for ($y = 0; $y -lt $source.Height; $y += $step) {
    for ($x = 0; $x -lt $source.Width; $x += $step) {
        if ($source.GetPixel($x, $y).A -gt 8) {
            if ($x -lt $minX) { $minX = $x }
            if ($y -lt $minY) { $minY = $y }
            if ($x -gt $maxX) { $maxX = $x }
            if ($y -gt $maxY) { $maxY = $y }
        }
    }
}

if ($maxX -lt 0) { throw "the master artwork is fully transparent" }

$boxW = $maxX - $minX + $step
$boxH = $maxY - $minY + $step
Write-Host ("  glyph bounding box: {0}x{1} at ({2},{3})" -f $boxW, $boxH, $minX, $minY) -ForegroundColor DarkGray

# ----------------------------------------------------------------------
# 3. Render the foreground layer at every density.
#
# The foreground is a full 108dp canvas; the glyph is scaled so that its bounding box
# occupies $SafeZone of it, then centred on the bounding box rather than on the source
# image, because the artwork has uneven transparent margins.

$densities = [ordered]@{ 'mdpi' = 108; 'hdpi' = 162; 'xhdpi' = 216; 'xxhdpi' = 324; 'xxxhdpi' = 432 }

foreach ($density in $densities.Keys) {
    $size = $densities[$density]
    $targetBox = $size * $SafeZone
    $scale = [Math]::Min($targetBox / $boxW, $targetBox / $boxH)

    $drawW = [int][Math]::Round($boxW * $scale)
    $drawH = [int][Math]::Round($boxH * $scale)
    $dstX = [int](($size - $drawW) / 2)
    $dstY = [int](($size - $drawH) / 2)

    $canvas = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($canvas)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality

    $srcRect = New-Object System.Drawing.Rectangle($minX, $minY, $boxW, $boxH)
    $dstRect = New-Object System.Drawing.Rectangle($dstX, $dstY, $drawW, $drawH)
    $g.DrawImage($source, $dstRect, $srcRect, [System.Drawing.GraphicsUnit]::Pixel)

    $dir = Join-Path $resRoot "mipmap-$density"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $target = Join-Path $dir 'ic_launcher_foreground.png'
    $canvas.Save($target, [System.Drawing.Imaging.ImageFormat]::Png)
    Write-Host ("  {0,-8} {1,4}x{1,-4} glyph {2}x{3} at ({4},{5})  -> {6}" -f $density, $size, $drawW, $drawH, $dstX, $dstY, "mipmap-$density/ic_launcher_foreground.png")

    $g.Dispose()
    $canvas.Dispose()
}

# ----------------------------------------------------------------------
# 4. Render a preview: the same foreground on the real background colour, under the mask
#    shapes Android actually applies, so the framing can be judged without installing.

$backgroundHex = '#0B3D2E'
$xml = Get-Content (Join-Path $resRoot 'values\colors.xml') -Raw
if ($xml -match 'ic_launcher_background">\s*(#[0-9A-Fa-f]{6,8})') { $backgroundHex = $Matches[1] }
$background = [System.Drawing.ColorTranslator]::FromHtml($backgroundHex)
Write-Host ("  background colour: {0}" -f $backgroundHex) -ForegroundColor DarkGray

$tile = 384
$gap = 24
$preview = New-Object System.Drawing.Bitmap(($tile * 3 + $gap * 4), ($tile + $gap * 2), [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
$pg = [System.Drawing.Graphics]::FromImage($preview)
$pg.Clear([System.Drawing.Color]::FromArgb(255, 245, 245, 245))
$pg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic

# The largest foreground available, to preview at the highest fidelity.
$foreground = [System.Drawing.Bitmap]::FromFile((Join-Path $resRoot 'mipmap-xxxhdpi\ic_launcher_foreground.png'))

for ($i = 0; $i -lt 3; $i++) {
    $x = $gap + $i * ($tile + $gap)
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    switch ($i) {
        0 { $path.AddRectangle((New-Object System.Drawing.Rectangle($x, $gap, $tile, $tile))) }
        1 { $path.AddEllipse($x, $gap, $tile, $tile) }
        default {
            $r = $tile * 0.22
            $x0 = $x; $y0 = $gap; $w = $tile; $h = $tile
            $path.AddArc($x0, $y0, $r * 2, $r * 2, 180, 90)
            $path.AddArc($x0 + $w - $r * 2, $y0, $r * 2, $r * 2, 270, 90)
            $path.AddArc($x0 + $w - $r * 2, $y0 + $h - $r * 2, $r * 2, $r * 2, 0, 90)
            $path.AddArc($x0, $y0 + $h - $r * 2, $r * 2, $r * 2, 90, 90)
            $path.CloseFigure()
        }
    }

    $state = $pg.Save()
    $pg.SetClip($path)
    $pg.FillRectangle((New-Object System.Drawing.SolidBrush($background)), $x, $gap, $tile, $tile)
    $pg.DrawImage($foreground, $x, $gap, $tile, $tile)
    $pg.Restore($state)
    $path.Dispose()
}

New-Item -ItemType Directory -Force -Path (Split-Path -Parent $previewPath) | Out-Null
$preview.Save($previewPath, [System.Drawing.Imaging.ImageFormat]::Png)
$pg.Dispose(); $preview.Dispose(); $foreground.Dispose(); $source.Dispose()

Write-Host ''
Write-Host ("  preview written: {0}" -f $previewPath) -ForegroundColor Green
Write-Host '  (left: no mask, middle: circle, right: rounded square)' -ForegroundColor DarkGray
Write-Host ''
