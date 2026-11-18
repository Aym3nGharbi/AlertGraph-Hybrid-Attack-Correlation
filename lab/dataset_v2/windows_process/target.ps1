param([ValidateSet('Preflight','Execute')][string]$Mode = 'Preflight')
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Identity-Of($Process) {
    $null = $Process.Handle # Retenir le handle reel, pas seulement son PID.
    [ordered]@{
        pid = [int]$Process.Id
        creation_filetime = $Process.StartTime.ToUniversalTime().ToFileTimeUtc()
        image = $Process.MainModule.FileName
        computer = $env:COMPUTERNAME
        observed_filetime = [DateTime]::UtcNow.ToFileTimeUtc()
        live_handle_retained = (-not $Process.HasExited)
    }
}
function Read-LineBounded($Reader, [int]$Milliseconds) {
    $task = $Reader.ReadLineAsync()
    if (-not $task.Wait($Milliseconds)) { throw 'pipe-read-timeout' }
    if ($null -eq $task.Result) { throw 'pipe-closed-before-receipt' }
    $task.Result
}
function Stop-Known($Process, $Creation) {
    if ($null -eq $Process) { return $true }
    try {
        if ($Process.HasExited) { return $true }
        if ($Process.StartTime.ToUniversalTime().ToFileTimeUtc() -ne $Creation) { return $false }
        $Process.Kill()
        return $Process.WaitForExit(2000)
    } catch { return $false }
}
function Get-ChildCode {
@'
$ErrorActionPreference='Stop'
$p=[Diagnostics.Process]::GetCurrentProcess()
$identity=[ordered]@{pid=$PID;creation_filetime=$p.StartTime.ToUniversalTime().ToFileTimeUtc();image=$p.MainModule.FileName;command_line=[Environment]::CommandLine}
[Console]::Out.WriteLine(($identity|ConvertTo-Json -Compress));[Console]::Out.Flush()
$gate=[Console]::In.ReadLineAsync()
if(-not $gate.Wait(8000) -or $gate.Result -cne 'GO'){exit 125}
[Console]::Out.WriteLine(('BENIGN_USERNAME='+[Environment]::UserName))
exit 0
'@
}
function Get-ParentCode {
@'
$ErrorActionPreference='Stop'
$c=$null;$cleanup=$false;$result=$null
try {
 $psi=[Diagnostics.ProcessStartInfo]::new()
 $psi.FileName="$PSHOME\powershell.exe"
 $psi.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand __CHILD_SOURCE_B64__'
 $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
 $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
 $c=[Diagnostics.Process]::Start($psi);$null=$c.Handle
 $birth=$c.StartTime.ToUniversalTime().ToFileTimeUtc()
 $task=$c.StandardOutput.ReadLineAsync()
 if(-not $task.Wait(4000)){throw 'child-ready-timeout'}
 $child=$task.Result|ConvertFrom-Json
 if($child.pid -ne $c.Id -or $child.creation_filetime -ne $birth){throw 'child-self-identity-contradiction'}
 $p=[Diagnostics.Process]::GetCurrentProcess()
 $parent=[ordered]@{pid=$PID;creation_filetime=$p.StartTime.ToUniversalTime().ToFileTimeUtc();image=$p.MainModule.FileName;command_line=[Environment]::CommandLine}
 [Console]::Out.WriteLine((@{phase='ready';parent=$parent;child=$child}|ConvertTo-Json -Depth 5 -Compress));[Console]::Out.Flush()
 $gate=[Console]::In.ReadLineAsync()
 if(-not $gate.Wait(6000) -or $gate.Result -cne 'GO'){throw 'parent-gate-not-released'}
 $c.StandardInput.WriteLine('GO');$c.StandardInput.Flush();$c.StandardInput.Close()
 if(-not $c.WaitForExit(4000)){throw 'child-exit-timeout'}
 $stdout=$c.StandardOutput.ReadToEnd();$stderr=$c.StandardError.ReadToEnd()
 if($stdout.Length -gt 65536 -or $stderr.Length -gt 65536){throw 'output-limit-exceeded'}
 $cleanup=$true
 $result=@{phase='completed';child_exit_code=$c.ExitCode;stdout_base64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stdout));stderr_base64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($stderr));cleanup_confirmed=$true}
} catch {$result=@{phase='failed';error_type=$_.Exception.GetType().Name}}
finally {
 if($null -ne $c -and -not $c.HasExited){
  try{if($c.StartTime.ToUniversalTime().ToFileTimeUtc() -eq $birth){$c.Kill();$cleanup=$c.WaitForExit(2000)}}catch{$cleanup=$false}
 }
 if($null -ne $result){$result.cleanup_confirmed=$cleanup}
}
[Console]::Out.WriteLine(($result|ConvertTo-Json -Compress));[Console]::Out.Flush()
if($result.phase -ne 'completed' -or -not $cleanup){exit 124}
exit 0
'@
}

if ($Mode -eq 'Preflight') {
    foreach($assembly in @('System.ServiceProcess.ServiceController','System.ServiceProcess')){
        try{Add-Type -AssemblyName $assembly -ErrorAction Stop}catch{ }
    }
    $log = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational'
    $samples = foreach ($eid in @(1,11)) {
        $events = @(Get-WinEvent -FilterHashtable @{LogName=$log.LogName;Id=$eid} -MaxEvents 3 -ErrorAction SilentlyContinue)
        [ordered]@{event_id=$eid;sample_count=$events.Count;field_names=@($events | ForEach-Object {
            [xml]$xml=$_.ToXml(); @($xml.Event.EventData.Data | ForEach-Object {$_.Name})
        } | Sort-Object -Unique)}
    }
    # Le compte non administrateur peut lire un service nomme sans avoir le
    # droit d'enumerer tout le SCM. Un refus reste Unknown, jamais Stopped.
    $services=@(foreach($name in @('Wazuh','WazuhSvc','Sysmon','Sysmon64','WinRM')){
        $service=$null
        try{$service=[ServiceProcess.ServiceController]::new($name);$state=[string]$service.Status;if([string]::IsNullOrWhiteSpace($state)){throw 'service-status-not-readable'};@{name=$name;status=$state;source='named-service-query'}}
        catch{@{name=$name;status='Unknown';error_type=$_.Exception.GetType().Name;source='named-service-query'}}
        finally{if($null -ne $service){$service.Dispose()}}
    })
    $own=Identity-Of ([Diagnostics.Process]::GetCurrentProcess())
    $ownXPath="*[System[EventID=1] and EventData[Data[@Name='ProcessId']='$PID']]"
    $ownSources=@(Get-WinEvent -LogName $log.LogName -FilterXPath $ownXPath -MaxEvents 8 -ErrorAction SilentlyContinue)
    $ownMatches=@(foreach($event in $ownSources){
        [xml]$xml=$event.ToXml();$data=@{};foreach($d in $xml.Event.EventData.Data){$data[$d.Name]=[string]$d.'#text'}
        $birth=[DateTime]::ParseExact($data.UtcTime,'yyyy-MM-dd HH:mm:ss.fff',[Globalization.CultureInfo]::InvariantCulture,([Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal)).ToFileTimeUtc()
        if([long][Math]::Floor([decimal]$birth/10000) -eq [long][Math]::Floor([decimal]$own.creation_filetime/10000)){
            @{record_id=$event.RecordId;process_guid=$data.ProcessGuid;pid=$PID;kernel_birth_matches_at_source_precision=$true}
        }
    })
    [ordered]@{mode='read-only';computer=$env:COMPUTERNAME;is_64bit=[Environment]::Is64BitProcess;
        services=$services;sysmon_log_enabled=$log.IsEnabled;sysmon_record_count=$log.RecordCount;
        samples=@($samples);own_process=$own;sysmon_current_observer_process_sources=@($ownMatches);
        experimental_processes_started=0} | ConvertTo-Json -Depth 8 -Compress
    return
}

if (-not [Environment]::Is64BitProcess) { throw '64-bit-session-required' }
$parent=$null;$child=$null;$parentBirth=0;$childBirth=0;$observations=@();$receipt=$null;$childMayExist=$false
$started=[DateTime]::UtcNow.ToString('o')
try {
    $childCode=Get-ChildCode
    $parentCode=(Get-ParentCode).Replace('__CHILD_SOURCE_B64__',[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($childCode)))
    $psi=[Diagnostics.ProcessStartInfo]::new()
    $psi.FileName="$PSHOME\powershell.exe"
    $psi.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($parentCode))
    $psi.UseShellExecute=$false;$psi.CreateNoWindow=$true
    $psi.RedirectStandardInput=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
    $parent=[Diagnostics.Process]::Start($psi);$childMayExist=$true;$null=$parent.Handle
    $parentBirth=$parent.StartTime.ToUniversalTime().ToFileTimeUtc()
    $ready=(Read-LineBounded $parent.StandardOutput 8000)|ConvertFrom-Json
    if($ready.phase -cne 'ready' -or $ready.parent.pid -ne $parent.Id -or $ready.parent.creation_filetime -ne $parentBirth){throw 'parent-ready-invalid'}
    # Observation distincte : reouvrir les deux processus vivants depuis le wrapper.
    foreach($role in @('parent','child')) {
        $reported=$ready.$role
        $observedProcess=Get-Process -Id $reported.pid
        $observation=Identity-Of $observedProcess
        if($observation.creation_filetime -ne $reported.creation_filetime -or $observation.image -ine $reported.image -or -not $observation.live_handle_retained){throw 'independent-birth-identity-failed'}
        $observation.role=$role;$observations+=,$observation
        if($role -eq 'child'){$child=$observedProcess;$childBirth=$observation.creation_filetime}
    }
    $parent.StandardInput.WriteLine('GO');$parent.StandardInput.Flush();$parent.StandardInput.Close()
    $completed=(Read-LineBounded $parent.StandardOutput 6000)|ConvertFrom-Json
    if(-not $parent.WaitForExit(2000)){throw 'parent-exit-timeout'}
    $parentStdErr=$parent.StandardError.ReadToEnd()
    if($parentStdErr.Length -gt 65536){throw 'parent-output-limit-exceeded'}
    if($completed.phase -cne 'completed' -or -not $completed.cleanup_confirmed -or $completed.child_exit_code -ne 0 -or $parent.ExitCode -ne 0){throw 'controlled-process-failure'}
    $ready.parent|Add-Member -NotePropertyName exit_code -NotePropertyValue $parent.ExitCode
    $ready.child|Add-Member -NotePropertyName exit_code -NotePropertyValue $completed.child_exit_code
    $wrapper=Identity-Of ([Diagnostics.Process]::GetCurrentProcess())
    $receipt=[ordered]@{status='completed';computer=$env:COMPUTERNAME;started_at_utc=$started;
        ended_at_utc=[DateTime]::UtcNow.ToString('o');wrapper=$wrapper;parent=$ready.parent;child=$ready.child;
        gate=@{independent_identity_checked_before_release=$true};cleanup=@{confirmed_stopped=$true;scope='owned-parent-and-child-only'};
        outputs=$completed;parent_stderr_base64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($parentStdErr))}
} catch {
    $childStopped=Stop-Known $child $childBirth
    $parentStopped=Stop-Known $parent $parentBirth
    $receipt=[ordered]@{status='failed';error_type=$_.Exception.GetType().Name;
        started_at_utc=$started;ended_at_utc=[DateTime]::UtcNow.ToString('o');
        cleanup=@{confirmed_stopped=($childStopped -and $parentStopped -and (-not $childMayExist -or $null -ne $child));scope='observed-owned-identities-only';unobserved_descendants_not_proven=$true}}
}
[ordered]@{receipt=$receipt;kernel_observations=@($observations);training_ready=$false} | ConvertTo-Json -Depth 12 -Compress
