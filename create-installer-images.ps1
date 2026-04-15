Add-Type -AssemblyName System.Drawing

$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$logoPath = Join-Path $repo 'Resources\logo.png'
$sidebarOut = Join-Path $repo 'Resources\installer-sidebar.bmp'
$iconOut = Join-Path $repo 'Resources\installer-icon.bmp'

$logo = [System.Drawing.Image]::FromFile($logoPath)
$navy = [System.Drawing.Color]::White

$sidebar = New-Object System.Drawing.Bitmap(164, 314)
$g = [System.Drawing.Graphics]::FromImage($sidebar)
$g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g.Clear($navy)

$logoW = 120
$ratio = $logoW / $logo.Width
$logoH = [int]($logo.Height * $ratio)
$logoX = [int]((164 - $logoW) / 2)
$logoY = 50
$g.DrawImage($logo, $logoX, $logoY, $logoW, $logoH)

$fontTitle = New-Object System.Drawing.Font('Segoe UI', 11, [System.Drawing.FontStyle]::Bold)
$fontSub = New-Object System.Drawing.Font('Segoe UI', 8)
$whiteBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(26, 35, 50))
$grayBrush = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::FromArgb(100, 115, 135))
$sf = New-Object System.Drawing.StringFormat
$sf.Alignment = [System.Drawing.StringAlignment]::Center

$titleY = $logoY + $logoH + 14
$g.DrawString('SEACURE(TOOL)', $fontTitle, $whiteBrush, [System.Drawing.RectangleF]::new(0, $titleY, 164, 24), $sf)
$g.DrawString('Cyber Security Solution', $fontSub, $grayBrush, [System.Drawing.RectangleF]::new(0, $titleY + 22, 164, 20), $sf)

$g.Dispose()
$sidebar.Save($sidebarOut, [System.Drawing.Imaging.ImageFormat]::Bmp)
$sidebar.Dispose()

$icon = New-Object System.Drawing.Bitmap(55, 55)
$g2 = [System.Drawing.Graphics]::FromImage($icon)
$g2.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
$g2.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
$g2.Clear($navy)

$target = 48
$ratio2 = $target / [Math]::Max($logo.Width, $logo.Height)
$w2 = [int]($logo.Width * $ratio2)
$h2 = [int]($logo.Height * $ratio2)
$g2.DrawImage($logo, [int](( 55 - $w2 ) / 2), [int](( 55 - $h2 ) / 2), $w2, $h2)

$g2.Dispose()
$icon.Save($iconOut, [System.Drawing.Imaging.ImageFormat]::Bmp)
$icon.Dispose()
$logo.Dispose()

$icoOut = Join-Path $repo 'Resources\logo.ico'
$sizes = 16, 32, 48, 64, 128, 256
$logo2 = [System.Drawing.Image]::FromFile($logoPath)

$pngBytes = @()
foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s)
    $bg = [System.Drawing.Graphics]::FromImage($bmp)
    $bg.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $bg.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $bg.Clear([System.Drawing.Color]::Transparent)
    $bg.DrawImage($logo2, 0, 0, $s, $s)
    $bg.Dispose()
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytes += ,$ms.ToArray()
    $ms.Dispose()
    $bmp.Dispose()
}
$logo2.Dispose()

$fs = [System.IO.File]::Create($icoOut)
$bw = New-Object System.IO.BinaryWriter($fs)
$bw.Write([uint16]0)
$bw.Write([uint16]1)
$bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $s = $sizes[$i]
    $len = $pngBytes[$i].Length
    $dim = if ($s -eq 256) { 0 } else { $s }
    $bw.Write([byte]$dim)
    $bw.Write([byte]$dim)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([uint16]1)
    $bw.Write([uint16]32)
    $bw.Write([uint32]$len)
    $bw.Write([uint32]$offset)
    $offset += $len
}
foreach ($b in $pngBytes) { $bw.Write($b) }
$bw.Flush()
$fs.Close()

Write-Host "Created $sidebarOut (164x314), $iconOut (55x55), $icoOut (multi-size)"
