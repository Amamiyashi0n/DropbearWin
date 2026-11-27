[CmdletBinding()]
param(
    [ValidateSet('all', 'x64', 'x86')]
    [string]$Architecture = 'all',
    [switch]$Clean,
    [int]$Jobs = 6,
    [string]$Distro = 'Debian',
    [switch]$Deploy
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$repoWin = Split-Path -Parent $PSScriptRoot
$repoLinux = '/mnt/' + $repoWin.Substring(0, 1).ToLower() + $repoWin.Substring(2).Replace('\', '/')

$cleanFlag = if ($Clean) { ' --clean' } else { '' }
$bashCmd = "set -euo pipefail; cd '$repoLinux'; bash scripts/build-cross.sh --architecture $Architecture --jobs $Jobs$cleanFlag"

Write-Output "=== DropbearWin Primary Release Build (via Debian WSL1 Cross-Compilation) ==="
Write-Output "  Repo : $repoWin ($repoLinux)"
Write-Output "  Arch : $Architecture  Jobs: $Jobs  Clean: $([bool]$Clean)"

$wslBridge = 'C:\Program Files\wsl-bridge\wsl-bridge.exe'
if (Test-Path -LiteralPath $wslBridge) {
    & $wslBridge bash -c $bashCmd
} else {
    & C:\Windows\System32\wsl.exe -d $Distro --exec /usr/bin/bash -c $bashCmd
}
if ($LASTEXITCODE -ne 0) {
    throw "WSL cross-compilation failed with exit code $LASTEXITCODE"
}

$manifestPath = Join-Path $repoWin 'dist\build-manifest.json'
if (Test-Path -LiteralPath $manifestPath) {
    Write-Output "=== Release Manifest ($manifestPath) ==="
    Get-Content -LiteralPath $manifestPath
}

if ($Deploy) {
    $srcExe = Join-Path $repoWin 'dist\dropbear-win-x64.exe'
    $dstDir = 'C:\Program Files\DropbearWin'
    $dstExe = Join-Path $dstDir 'dropbear-win-x64.exe'
    $bakExe = Join-Path $dstDir 'dropbear-win-x64.exe.bak-release'

    if (-not (Test-Path -LiteralPath $srcExe)) {
        throw "Built x64 release EXE not found: $srcExe"
    }

    Write-Output "=== Deploying Release EXE to $dstDir ==="
    New-Item -ItemType Directory -Path $dstDir -Force | Out-Null
    if (Test-Path -LiteralPath $dstExe) {
        Copy-Item -LiteralPath $dstExe -Destination $bakExe -Force
    }
    Stop-Service -Name DropbearWin -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 1200
    try {
        Copy-Item -LiteralPath $srcExe -Destination $dstExe -Force
        & $dstExe --wsl-bridge --extract $dstDir | Out-Null
        if (Test-Path -LiteralPath 'C:\Program Files\wsl-bridge') {
            & $dstExe --wsl-bridge --install-shims 'C:\Program Files\wsl-bridge' | Out-Null
        }
        Start-Service -Name DropbearWin
        Start-Sleep -Milliseconds 1500
        $svc = Get-Service -Name DropbearWin
        if ($svc.Status -ne 'Running') {
            throw "DropbearWin service status is $($svc.Status)"
        }
        Remove-Item -LiteralPath $bakExe -Force -ErrorAction SilentlyContinue
        Write-Output 'DEPLOY_OK'
    } catch {
        Write-Warning "Deploy failed: $($_.Exception.Message); rolling back..."
        if (Test-Path -LiteralPath $bakExe) {
            Copy-Item -LiteralPath $bakExe -Destination $dstExe -Force -ErrorAction SilentlyContinue
        }
        Start-Service -Name DropbearWin -ErrorAction SilentlyContinue
        throw
    }
}
