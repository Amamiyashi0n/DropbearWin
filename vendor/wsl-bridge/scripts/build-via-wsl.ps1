param(
    [switch]$Deploy,
    [string]$Distro = "Debian",
    [string]$WslUser = "amamiya"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$repoWin = Split-Path -Parent $PSScriptRoot
$repoLinux = "/mnt/" + $repoWin.Substring(0,1).ToLower() + $repoWin.Substring(2).Replace('\', '/')
$distDir = "C:\Program Files\wsl-bridge"

# Cross-compile inside Debian WSL1
$args = @("-d", $Distro, "-u", $WslUser, "--exec", "/usr/bin/bash", "$repoLinux/scripts/build-cross.sh")
& C:\Windows\System32\wsl.exe @args
if ($LASTEXITCODE -ne 0) {
    throw "WSL cross-compilation failed with exit code $LASTEXITCODE"
}

if ($Deploy) {
    $builtExe = Join-Path $repoWin "dist\wsl-bridge.exe"
    Write-Output "=== Stopping WslBridgeDaemon for binary swap ==="
    Stop-ScheduledTask -TaskName WslBridgeDaemon -ErrorAction SilentlyContinue
    Get-Process wsl-bridge -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Get-Process wsl -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 300

    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
    Copy-Item -LiteralPath $builtExe -Destination (Join-Path $distDir "wsl-bridge.exe") -Force
    Copy-Item -LiteralPath $builtExe -Destination (Join-Path $distDir "bash.exe") -Force
    Copy-Item -LiteralPath $builtExe -Destination (Join-Path $distDir "sh.exe") -Force

    Write-Output "=== Restarting WslBridgeDaemon ==="
    Start-ScheduledTask -TaskName WslBridgeDaemon
    Start-Sleep -Milliseconds 1500
    & (Join-Path $distDir "wsl-bridge.exe") status
}
