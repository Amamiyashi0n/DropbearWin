param(
    [string]$TaskName = "WslBridgeDaemon",
    [string]$BridgeExe = "C:\Program Files\wsl-bridge\wsl-bridge.exe",
    [string]$UserAccount = "$env:COMPUTERNAME\Amamiya",
    [string]$Distro = "Debian",
    [string]$WslUser = "amamiya"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if (-not (Test-Path -LiteralPath $BridgeExe)) {
    throw "Bridge binary not found: $BridgeExe"
}

# Create system-wide shared data directory C:\ProgramData\wsl-bridge with strict ACL (SYSTEM + Administrators + target user)
$sharedDir = "C:\ProgramData\wsl-bridge"
New-Item -ItemType Directory -Path $sharedDir -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $sharedDir "tmp") -Force | Out-Null
& icacls.exe $sharedDir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "${UserAccount}:(OI)(CI)F" | Out-Null

# Ensure LxssManager starts automatically at boot (use sc.exe to avoid Set-Service description ACL error)
try {
    $null = & sc.exe config LxssManager start= auto 2>&1
    $lxss = Get-Service -Name LxssManager -ErrorAction SilentlyContinue
    if ($lxss -and $lxss.Status -ne "Running") {
        Start-Service -Name LxssManager -ErrorAction SilentlyContinue
    }
} catch {}

# Stop existing task / daemon if running
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Task Scheduler XML:
# - BootTrigger: runs at system boot even with NO user logged on
# - LogonType=S4U + RunLevel=HighestAvailable: loads user's HKCU\Lxss without storing password
# - Priority=1 (HIGH_PRIORITY_CLASS) + daemon also calls SetPriorityClass(HIGH_PRIORITY_CLASS)
# - ExecutionTimeLimit=PT0S (unlimited) + RestartOnFailure
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>High-priority Debian WSL1 boot supervisor for wsl-bridge (runs at system startup even when no user is logged on).</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
      <Delay>PT5S</Delay>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>$UserAccount</UserId>
      <LogonType>S4U</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>false</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>true</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>1</Priority>
    <RestartOnFailure>
      <Interval>PT1M</Interval>
      <Count>999</Count>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>$BridgeExe</Command>
      <Arguments>daemon --distro $Distro --user $WslUser</Arguments>
    </Exec>
  </Actions>
</Task>
"@

Register-ScheduledTask -TaskName $TaskName -Xml $xml -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Milliseconds 1500

$task = Get-ScheduledTask -TaskName $TaskName
$info = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Output ("TASK_STATE=" + $task.State + " LAST_RESULT=" + $info.LastTaskResult)
