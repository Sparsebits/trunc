# Render the README graphics (banner and proof chart, dark and light) with headless Chrome or Edge.
# Output: docs/assets/{banner,chart}-{dark,light}.png at 2x.
$ErrorActionPreference = 'Continue'  # Chrome reports progress on stderr
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Split-Path -Parent $here
$browser = @(
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $browser) { Write-Error 'Chrome or Edge is required'; exit 1 }
$pages = @{ banner = '1280,400'; chart = '1200,300' }
foreach ($name in $pages.Keys) {
    $src = 'file:///' + ((Join-Path $here "$name.html") -replace '\\', '/')
    foreach ($theme in 'dark', 'light') {
        $png = Join-Path $out "$name-$theme.png"
        & $browser --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 `
            "--window-size=$($pages[$name])" --virtual-time-budget=8000 `
            "--screenshot=$png" "$src`?theme=$theme" 2>$null | Out-Null
        Write-Output "wrote $png"
    }
}
