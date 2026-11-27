param(
    [string]$TaskName = "WslBridgeDaemon"
)
$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"
Stop-ScheduledTask -TaskName $TaskName
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
Get-Process -Name "wsl-bridge" | Where-Object {
    try { (Get-CimInstance Win32_Process -Filter "ProcessId=$($_.Id)").CommandLine -match '\bdaemon\b' } catch { $false }
} | Stop-Process -Force
Write-Output "UNINSTALLED_OK"
