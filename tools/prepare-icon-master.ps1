<#
.SYNOPSIS
    Turns the flat-background master artwork into a transparent one.

.DESCRIPTION
    The launcher icon needs a glyph on a transparent canvas: the adaptive icon supplies its
    own background colour, and the launcher mask (circle, squircle, rounded square) decides
    the shape. Artwork delivered on a flat background therefore has to have that background
    removed first.

    Keying on a flat background is exact, unlike the earlier checkerboard version: there the
    "transparent" squares were painted in and shared the glyph's own white, which no colour
    test can separate.

    Two details make this robust rather than merely working on this one file:

      * The background level is estimated PER PIXEL by bilinearly interpolating the four
        corners, instead of assumed to be one constant. A flat export often carries a faint
        gradient; a single global threshold then eats into one corner of the glyph and
        leaves a rim of background in the other.

      * Pixels DARKER than the local background are removed too. A drop shadow is darker
        than a dark background, and treating "not background" as "glyph" would turn that
        shadow into a white halo.

    Output is a pure-white glyph with an anti-aliased alpha edge.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\prepare-icon-master.ps1
#>

[CmdletBinding()]
param(
    # Artwork on a flat background, as delivered.
    [string]$Source = '',

    # Transparent output that tools/make-icon.ps1 consumes.
    [string]$Target = '',

    # Luminance distance from the local background that still counts as background.
    [int]$Tolerance = 35,

    # Width of the soft ramp from transparent to opaque, in luminance.
    [int]$Feather = 40
)

$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$repoRoot = Split-Path -Parent $PSScriptRoot
$iconDir = Join-Path $repoRoot 'assets\icon'
if (-not $Source) { $Source = Join-Path $iconDir 'icon-source.png' }
if (-not $Target) { $Target = Join-Path $iconDir 'icon-master.png' }

if (-not (Test-Path $Source)) { throw "source artwork not found: $Source" }

# Pixel work in C#, not PowerShell: a 1780x1780 image is 3.2 million pixels, and a
# per-pixel GetPixel/SetPixel loop in PowerShell takes minutes.
#
# Written to compile as C# 5, because Add-Type under Windows PowerShell 5.1 uses the
# .NET Framework compiler: no tuples, no string interpolation, no pattern matching.
$code = @'
using System;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using System.Runtime.InteropServices;

public static class IconKeyer
{
    private static int Lum(int r, int g, int b)
    {
        return (r * 299 + g * 587 + b * 114) / 1000;
    }

    private static int LumAt(byte[] buf, int stride, int x, int y)
    {
        int o = y * stride + x * 4;
        return Lum(buf[o + 2], buf[o + 1], buf[o]);
    }

    public static string Key(string sourcePath, string targetPath, int tolerance, int feather)
    {
        using (Bitmap src = new Bitmap(sourcePath))
        {
            int w = src.Width;
            int h = src.Height;
            Rectangle rect = new Rectangle(0, 0, w, h);

            BitmapData data = src.LockBits(rect, ImageLockMode.ReadOnly, PixelFormat.Format32bppArgb);
            int stride = data.Stride;
            byte[] buf = new byte[stride * h];
            Marshal.Copy(data.Scan0, buf, 0, buf.Length);
            src.UnlockBits(data);

            // Background level at each corner, then bilinear across the image.
            int tl = LumAt(buf, stride, 1, 1);
            int tr = LumAt(buf, stride, w - 2, 1);
            int bl = LumAt(buf, stride, 1, h - 2);
            int br = LumAt(buf, stride, w - 2, h - 2);

            long kept = 0, cleared = 0, soft = 0, darker = 0;

            for (int y = 0; y < h; y++)
            {
                int row = y * stride;

                for (int x = 0; x < w; x++)
                {
                    // Bilinear background estimate for this pixel.
                    int top = tl + ((tr - tl) * x) / (w - 1);
                    int bottom = bl + ((br - bl) * x) / (w - 1);
                    int bg = top + ((bottom - top) * y) / (h - 1);

                    int o = row + x * 4;
                    int lum = Lum(buf[o + 2], buf[o + 1], buf[o]);
                    int d = lum - bg;

                    int alpha;
                    if (d <= tolerance)
                    {
                        alpha = 0;
                        if (d < -tolerance) darker++;
                    }
                    else if (d >= tolerance + feather)
                    {
                        alpha = 255;
                    }
                    else
                    {
                        alpha = (255 * (d - tolerance)) / feather;
                        soft++;
                    }

                    // Pure white glyph: the artwork is a white shape, and forcing the
                    // colour removes any compression tint the flat background left on the
                    // anti-aliased edge.
                    buf[o + 0] = 255;
                    buf[o + 1] = 255;
                    buf[o + 2] = 255;
                    buf[o + 3] = (byte)alpha;

                    if (alpha == 0) cleared++; else if (alpha == 255) kept++;
                }
            }

            // Written without going through GDI+'s file path handling, which reports
            // "A generic error occurred in GDI+" for several unrelated reasons and gives no
            // way to tell which one happened.
            IntPtr native = Marshal.AllocHGlobal(buf.Length);
            try
            {
                Marshal.Copy(buf, 0, native, buf.Length);
                using (Bitmap dst = new Bitmap(w, h, stride, PixelFormat.Format32bppArgb, native))
                using (MemoryStream ms = new MemoryStream())
                {
                    dst.Save(ms, ImageFormat.Png);
                    File.WriteAllBytes(targetPath, ms.ToArray());
                }
            }
            finally
            {
                Marshal.FreeHGlobal(native);
            }

            return string.Format(
                "{0}x{1}  corners TL={2} TR={3} BL={4} BR={5}  kept={6} cleared={7} soft={8} darker-than-bg={9}",
                w, h, tl, tr, bl, br, kept, cleared, soft, darker);
        }
    }
}
'@

Add-Type -TypeDefinition $code -ReferencedAssemblies 'System.Drawing'

Write-Host ''
Write-Host ("  keying: {0}" -f (Split-Path -Leaf $Source)) -ForegroundColor Cyan
Write-Host ("  tolerance={0} feather={1}" -f $Tolerance, $Feather) -ForegroundColor DarkGray

$report = [IconKeyer]::Key((Resolve-Path $Source).Path, $Target, $Tolerance, $Feather)
Write-Host ("  {0}" -f $report) -ForegroundColor Green
Write-Host ("  -> {0}" -f $Target) -ForegroundColor Green
Write-Host ''
