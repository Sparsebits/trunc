# Install trunc from its GitHub releases (Windows x64; also runs on ARM64 under emulation).
#
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/Sparsebits/trunc/main/install.ps1 | iex"
#
# Environment:
#   TRUNC_VERSION          release tag to install, e.g. v0.1.0 (default: the latest release)
#   TRUNC_INSTALL_DIR      where to put trunc.exe (default: %LOCALAPPDATA%\Programs\trunc)
#   TRUNC_NO_MODIFY_PATH   set to 1 to leave your PATH alone

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # the progress bar slows downloads down badly in Windows PowerShell

$repo = 'Sparsebits/trunc'
$base = if ($env:TRUNC_DOWNLOAD_BASE) { $env:TRUNC_DOWNLOAD_BASE } else { "https://github.com/$repo/releases" }
$version = if ($env:TRUNC_VERSION) { $env:TRUNC_VERSION } else { 'latest' }
$dir = if ($env:TRUNC_INSTALL_DIR) { $env:TRUNC_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\trunc' }

if (@('AMD64', 'ARM64') -notcontains $env:PROCESSOR_ARCHITECTURE) {
    throw "trunc-install: unsupported CPU $env:PROCESSOR_ARCHITECTURE"
}
# There is no native ARM64 build yet. Windows 11 on ARM runs x64 programs; Windows 10 on ARM
# does not.
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64' -and [Environment]::OSVersion.Version.Build -lt 22000) {
    throw "trunc-install: Windows 10 on ARM cannot run the x64 build; build from source with cargo"
}
$name = 'trunc-x86_64-pc-windows-msvc'
$asset = "$name.zip"
$url = if ($version -eq 'latest') { "$base/latest/download/$asset" } else { "$base/download/$version/$asset" }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("trunc-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Host "trunc-install: downloading $url"
    $zip = Join-Path $tmp $asset
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
    Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256" -OutFile "$zip.sha256"
    $expected = ((Get-Content -Raw "$zip.sha256").Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "trunc-install: checksum mismatch for ${asset}: expected $expected, got $actual" }
    Expand-Archive -Path $zip -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    Copy-Item -Force (Join-Path $tmp "$name\trunc.exe") (Join-Path $dir 'trunc.exe')
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$exe = Join-Path $dir 'trunc.exe'
Write-Host "trunc-install: installed $(& $exe --version) to $exe"

# Add the directory to the user PATH. The value is read unexpanded and written back as
# REG_EXPAND_SZ, so entries like %USERPROFILE%\bin keep expanding.
$key = Get-Item 'HKCU:\Environment'
$path = [string]$key.GetValue('Path', '', 'DoNotExpandEnvironmentNames')
if (($path -split ';') -contains $dir) { return }
if ($env:TRUNC_NO_MODIFY_PATH -and $env:TRUNC_NO_MODIFY_PATH -ne '0') {
    Write-Host "trunc-install: $dir is not on your PATH; add it to use trunc from any terminal"
    return
}
$new = if ($path) { $path.TrimEnd(';') + ';' + $dir } else { $dir }
[Microsoft.Win32.Registry]::SetValue('HKEY_CURRENT_USER\Environment', 'Path', $new, 'ExpandString')
# Setting any user variable through .NET broadcasts the change, so new terminals see the PATH.
[Environment]::SetEnvironmentVariable('TRUNC_INSTALL_REFRESH', '1', 'User')
[Environment]::SetEnvironmentVariable('TRUNC_INSTALL_REFRESH', $null, 'User')
$env:Path = "$env:Path;$dir"
Write-Host "trunc-install: added $dir to your user PATH (open a new terminal to use it)"
