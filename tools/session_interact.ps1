param([Parameter(Mandatory=$true)][string]$RequestBase64)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$request=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($RequestBase64)) | ConvertFrom-Json
$utf8=New-Object Text.UTF8Encoding($false)

function Write-Atomic($path,$value) {
    [IO.File]::WriteAllText(($path+'.tmp'),($value | ConvertTo-Json -Depth 30 -Compress),$utf8)
    Move-Item -LiteralPath ($path+'.tmp') -Destination $path -Force
}
function Runtime-Root {
    return Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'DropbearWin'
}
function Identity {
    $id=[Security.Principal.WindowsIdentity]::GetCurrent()
    return @{session_id=[Diagnostics.Process]::GetCurrentProcess().SessionId; windows_user=$id.Name; sid=$id.User.Value;
        pid=$PID; userprofile=$env:USERPROFILE; appdata=$env:APPDATA; cwd=[Environment]::CurrentDirectory}
}
function Invoke-Work($work) {
    $identity=Identity
    if($work.expected_session -ne $identity.session_id -or $work.expected_sid -ne $identity.sid){throw 'Worker identity/session changed'}
    $p=$work.params
    switch($work.method) {
        'context' {return $identity}
        'exec' {
            $environment=New-Object 'Collections.Generic.Dictionary[string,string]'
            if($p.env){foreach($v in $p.env.PSObject.Properties){$environment.Add($v.Name,[string]$v.Value)}}
            $inputBytes=[Convert]::FromBase64String([string]$p.stdin_base64)
            $r=[DropbearInteraction]::Run([string]$p.program,[string[]]@($p.args),[string]$p.cwd,$environment,$inputBytes,[int]($p.timeout*1000))
            return @{execution=$r; security_context=$identity}
        }
        'powershell' {
            # A dedicated runspace retains $global: state without exposing the queue loop.
            if(!$script:workerRunspace){$script:workerRunspace=[RunspaceFactory]::CreateRunspace(); $script:workerRunspace.Open()}
            $pipeline=[PowerShell]::Create()
            try {
                $pipeline.Runspace=$script:workerRunspace
                $null=$pipeline.AddScript([string]$p.code)
                $running=$pipeline.BeginInvoke()
                if(!$running.AsyncWaitHandle.WaitOne([int]($p.timeout*1000))){$pipeline.Stop(); throw 'PowerShell request timed out; side effects may already have occurred'}
                $values=@($pipeline.EndInvoke($running))
                if($pipeline.HadErrors){throw ($pipeline.Streams.Error | Out-String)}
                return @{values=$values; security_context=$identity}
            } finally {$pipeline.Dispose()}
        }
        'ui' {
            $null=[DropbearInteraction]::SetProcessDPIAware()
            $desktop=[DropbearInteraction]::InputDesktop()
            switch([string]$p.action) {
                'windows' {$value=@([DropbearInteraction]::Windows())}
                'focus' {[DropbearInteraction]::Focus([string]$p.window_id); $value=@{focused=$true}}
                'click' {[DropbearInteraction]::Click([string]$p.window_id,[int]$p.x,[int]$p.y,[string]$p.button); $value=@{clicked=$true}}
                'text' {[DropbearInteraction]::Text([string]$p.window_id,[string]$p.text); $value=@{characters=([string]$p.text).Length}}
                'keys' {[DropbearInteraction]::Keys([string]$p.window_id,[string[]]@($p.keys)); $value=@{sent=$true}}
                default {throw 'Unknown UI action'}
            }
            return @{result=$value; input_desktop=$desktop; foreground_window=[DropbearInteraction]::GetForegroundWindow().ToInt64().ToString(); security_context=$identity}
        }
        default {throw 'Unknown worker method'}
    }
}
try {
    if(!('DropbearInteraction' -as [type])){Add-Type -Path (Join-Path $PSScriptRoot 'session_interact.cs')}
    switch($request.mode) {
        'list' { @{sessions=@([DropbearInteraction]::Sessions()); runtime_root=(Runtime-Root); utc_ticks=[DateTime]::UtcNow.Ticks} | ConvertTo-Json -Depth 8 -Compress }
        'prepare' {
            if([string]$request.worker_id -notmatch '^[0-9a-f]{32}$'){throw 'Invalid worker ID'}
            $selected=@([DropbearInteraction]::Sessions() | Where-Object {$_.session_id -eq $request.session_id -and $_.sid -eq $request.sid -and $_.selectable})
            if($selected.Count -ne 1){throw 'Selected Windows login changed or is unavailable'}
            $root=Runtime-Root
            $protected=New-Object Security.AccessControl.DirectorySecurity
            $protected.SetAccessRuleProtection($true,$false)
            foreach($sid in @('S-1-5-18','S-1-5-32-544')) {
                $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier($sid)),'FullControl','ContainerInherit,ObjectInherit','None','Allow')
                $protected.AddAccessRule($rule)
            }
            if(!(Test-Path -LiteralPath $root)){[IO.Directory]::CreateDirectory($root,$protected) | Out-Null}
            $directory=Join-Path $root ('session-'+$request.worker_id)
            if(Test-Path -LiteralPath $directory){throw 'Worker directory already exists'}
            $rule=New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier([string]$request.sid)),'Modify','ContainerInherit,ObjectInherit','None','Allow')
            $protected.AddAccessRule($rule)
            [IO.Directory]::CreateDirectory($directory,$protected) | Out-Null
            @{directory=$directory; session=$selected[0]} | ConvertTo-Json -Depth 8 -Compress
        }
        'worker' {
            if([string]$request.worker_id -notmatch '^[0-9a-f]{32}$'){throw 'Invalid worker ID'}
            $directory=Join-Path (Runtime-Root) ('session-'+$request.worker_id)
            $identity=Identity
            if($identity.session_id -ne $request.session_id -or $identity.sid -ne $request.sid){throw 'Worker started in wrong user/session'}
            if($request.idle_timeout -lt 10 -or $request.idle_timeout -gt 3600){throw 'Invalid idle timeout'}
            Set-Location -LiteralPath $env:USERPROFILE
            [Environment]::CurrentDirectory=$env:USERPROFILE
            $identity=Identity
            $identity.worker_id=[string]$request.worker_id
            Write-Atomic (Join-Path $directory 'ready.json') $identity
            $last=[DateTime]::UtcNow
            $stopping=$false
            while(!$stopping -and ([DateTime]::UtcNow-$last).TotalSeconds -lt $request.idle_timeout) {
                foreach($file in @(Get-ChildItem -LiteralPath $directory -Filter '*.request.json' | Sort-Object LastWriteTime,Name)) {
                    if($file.Name -notmatch '^([0-9a-f]{32})\.request\.json$'){continue}
                    $callId=$Matches[1]
                    try {
                        if($file.Length -gt 524288){throw 'Worker request exceeds 512 KiB'}
                        $work=[IO.File]::ReadAllText($file.FullName,$utf8) | ConvertFrom-Json
                        Remove-Item -LiteralPath $file.FullName -Force
                        if($work.id -ne $callId){throw 'Request ID mismatch'}
                        $remaining=([long]$work.expires_ticks-[DateTime]::UtcNow.Ticks)/10000000.0
                        if($remaining -le 0){throw 'Request expired before execution'}
                        if($work.method -in @('exec','powershell')){$work.params.timeout=[Math]::Min([double]$work.params.timeout,$remaining)}
                        if($work.expected_session -ne $identity.session_id -or $work.expected_sid -ne $identity.sid){throw 'Request targets another user/session'}
                        if($work.method -eq 'stop') {$value=@{stopped=$true}; $stopping=$true}
                        else {$value=Invoke-Work $work}
                        $response=@{id=$callId; result=$value; security_context=$identity}
                    } catch {$response=@{id=$callId; error=$_.ToString(); security_context=$identity}}
                    Write-Atomic (Join-Path $directory ($callId+'.response.json')) $response
                    $last=[DateTime]::UtcNow
                    if($stopping){break}
                }
                if(!$stopping){Start-Sleep -Milliseconds 100}
            }
            Write-Atomic (Join-Path $directory 'stopped.json') @{stopped=$true; security_context=$identity}
            if($script:workerRunspace){$script:workerRunspace.Close(); $script:workerRunspace.Dispose()}
        }
        default {throw 'Unknown session helper mode'}
    }
} catch {
    if($request.mode -eq 'worker' -and [string]$request.worker_id -match '^[0-9a-f]{32}$') {
        $failure=@{error=$_.ToString()}
        try {Write-Atomic (Join-Path (Join-Path (Runtime-Root) ('session-'+$request.worker_id)) 'error.json') $failure} catch {}
    }
    @{error=$_.ToString()} | ConvertTo-Json -Compress
    exit 1
}
