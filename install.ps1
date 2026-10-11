# Install trunc from its GitHub releases (Windows x64 and ARM64).
#
#   powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/Sparsebits/trunc/main/install.ps1 | iex"
#
# Environment:
#   TRUNC_VERSION          release tag to install, e.g. v0.1.0 (default: the latest release)
#   TRUNC_INSTALL_DIR      where to put trunc.exe (default: %LOCALAPPDATA%\Programs\trunc)
#   TRUNC_NO_MODIFY_PATH   set to 1 to leave your PATH alone
#   TRUNC_VERIFY_ATTESTATION
#                          check the download's signed build provenance with the GitHub CLI
#                          (`gh attestation verify`, see docs/security.md): 1 = required,
#                          0 = skip, auto (default) = only when gh is installed, and a warning
#                          rather than a failure when it cannot verify (e.g. gh is not logged in)
#
# The SHA-256 checksum is always verified.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # the progress bar slows downloads down badly in Windows PowerShell

$repo = 'Sparsebits/trunc'
$base = if ($env:TRUNC_DOWNLOAD_BASE) { $env:TRUNC_DOWNLOAD_BASE } else { "https://github.com/$repo/releases" }
$version = if ($env:TRUNC_VERSION) { $env:TRUNC_VERSION } else { 'latest' }
$dir = if ($env:TRUNC_INSTALL_DIR) { $env:TRUNC_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\trunc' }
$attest = if ($env:TRUNC_VERIFY_ATTESTATION) { $env:TRUNC_VERIFY_ATTESTATION } else { 'auto' }

if (@('0', '1', 'auto') -cnotcontains $attest) {
    throw "trunc-install: TRUNC_VERIFY_ATTESTATION must be 0, 1 or auto, not '$attest'"
}

# The machine's CPU, not this process's: PowerShell itself may be running as x64 under emulation
# on ARM64 (where $env:PROCESSOR_ARCHITECTURE says AMD64), or as 32-bit on x64. The system-wide
# value in the registry is the native one.
$cpu = $env:PROCESSOR_ARCHITECTURE
try {
    $native = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -Name PROCESSOR_ARCHITECTURE -ErrorAction Stop).PROCESSOR_ARCHITECTURE
    if ($native) { $cpu = $native }
}
catch {}
try { if ([string][Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') { $cpu = 'ARM64' } } catch {}
$cpu = "$cpu".ToUpperInvariant()

# Release assets to try, in order. Releases before the native ARM64 build (v0.1.0) have only the
# x64 one; Windows 11 on ARM runs it under emulation, Windows 10 on ARM cannot.
$x64 = 'trunc-x86_64-pc-windows-msvc'
$arm64 = 'trunc-aarch64-pc-windows-msvc'
$names = @(switch ($cpu) {
    'AMD64' { @($x64) }
    'ARM64' { if ([Environment]::OSVersion.Version.Build -ge 22000) { @($arm64, $x64) } else { @($arm64) } }
    default { throw "trunc-install: unsupported CPU $cpu" }
})
$release = if ($version -eq 'latest') { 'the latest release' } else { $version }

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("trunc-install-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    foreach ($name in $names) {
        $asset = "$name.zip"
        $url = if ($version -eq 'latest') { "$base/latest/download/$asset" } else { "$base/download/$version/$asset" }
        $zip = Join-Path $tmp $asset
        Write-Host "trunc-install: downloading $url"
        try {
            Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $zip
            break
        }
        catch {
            $status = $null
            if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
            if ($status -ne 404) { throw }
            if ($name -ne $names[-1]) {
                Write-Warning "trunc-install: $release has no native ARM64 build ($asset); installing the x64 build, which Windows 11 on ARM runs under emulation"
                continue
            }
            if ($name -eq $arm64) {
                throw "trunc-install: $release has no native ARM64 build ($asset), and Windows 10 on ARM cannot run the x64 build; install a newer release or build from source with cargo"
            }
            throw "trunc-install: $url was not found; check that $release is a trunc release"
        }
    }
    Invoke-WebRequest -UseBasicParsing -Uri "$url.sha256" -OutFile "$zip.sha256"
    $expected = ((Get-Content -Raw "$zip.sha256").Trim() -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    if ($expected -ne $actual) { throw "trunc-install: checksum mismatch for ${asset}: expected $expected, got $actual" }

    # Build provenance: a Sigstore attestation from the release workflow, checked by the GitHub CLI.
    if ($attest -ne '0') {
        if (Get-Command gh -CommandType Application -ErrorAction SilentlyContinue) {
            # gh writes to stderr; under 'Stop', Windows PowerShell would turn that into an error.
            $ErrorActionPreference = 'Continue'
            try {
                $out = & gh attestation verify $zip --repo $repo --signer-workflow "$repo/.github/workflows/release.yml" 2>&1 | ForEach-Object { "$_" } | Out-String
                $verified = $LASTEXITCODE -eq 0
            }
            finally { $ErrorActionPreference = 'Stop' }
            if ($verified) {
                Write-Host "trunc-install: verified the build provenance of $asset"
            }
            elseif ($attest -eq '1') {
                Write-Host $out.TrimEnd()
                throw "trunc-install: could not verify the build provenance of $asset"
            }
            else {
                Write-Warning "trunc-install: gh could not verify the build provenance of $asset (not logged in, or no attestation for this release); relying on the checksum. Set TRUNC_VERIFY_ATTESTATION=1 to require it."
            }
        }
        elseif ($attest -eq '1') {
            throw "trunc-install: TRUNC_VERIFY_ATTESTATION=1 needs the GitHub CLI (gh): https://cli.github.com"
        }
    }
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
