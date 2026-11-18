param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][string]$CredentialFile,
    [Parameter(Mandatory)][string]$RunId,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [switch]$ExecuteAuthorized
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not $ExecuteAuthorized){throw 'explicit-execution-authorization-required'}
if($ComputerName -cne '192.0.2.30'){throw 'target-outside-sealed-lab'}
if(Test-Path -LiteralPath $OutputDirectory){throw 'output-already-exists'}
New-Item -ItemType Directory -Path $OutputDirectory|Out-Null
function Save-NewJson($Name,$Value){
    $path=Join-Path $OutputDirectory $Name
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew)
    try{$bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 20 -Compress));$stream.Write($bytes,0,$bytes.Length);$stream.Flush()}finally{$stream.Dispose()}
}
$cred=Import-Clixml -LiteralPath $CredentialFile
$options=New-PSSessionOption -OpenTimeout 10000 -OperationTimeout 30000
$session=$null
try{
    $session=New-PSSession -ComputerName $ComputerName -UseSSL -Authentication Negotiate -Credential $cred -SessionOption $options
    # Aucun SkipCACheck/SkipCNCheck ; identite TLS deja configuree requise.
    $audit=(Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'target.ps1') -ArgumentList 'Preflight')|ConvertFrom-Json
    Save-NewJson 'read-only-preflight.json' $audit
    if(-not $audit.is_64bit -or -not $audit.sysmon_log_enabled){throw 'sysmon-or-bitness-precondition-failed'}
    # Manager active est controle par le runner Python ; cette connexion prouve
    # WinRM. L'E1 du processus technique courant prouve un Sysmon fonctionnel.
    # Une interrogation SCM interdite n'est jamais convertie en Stopped/Running.
    if(@($audit.sysmon_current_observer_process_sources).Count -ne 1){throw 'current-sysmon-observer-process-not-proven'}
    $bookmark=Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'collect-source.ps1') -ArgumentList 'Bookmark'
    Save-NewJson 'bookmark-before.json' ($bookmark|ConvertFrom-Json)
    $controllerStarted=[DateTime]::UtcNow.ToString('o')
    $activityJob=Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'target.ps1') -ArgumentList 'Execute' -AsJob
    try{
        $completedJob=Wait-Job -Job $activityJob -Timeout 20
        if($null -eq $completedJob -or $activityJob.State -ne 'Completed'){
            Stop-Job -Job $activityJob
            Save-NewJson 'activity-timeout.json' @{remote_cleanup_confirmed=$false;retry_allowed=$false;training_ready=$false}
            throw 'activity-deadline-exceeded-remote-cleanup-not-proven'
        }
        $targetJson=Receive-Job -Job $activityJob -ErrorAction Stop
    }finally{Remove-Job -Job $activityJob -Force}
    # Conserver le JSON recu sans Trim ni reserialisation avant son empreinte.
    [IO.File]::WriteAllBytes((Join-Path $OutputDirectory 'target-response.json'),[Text.Encoding]::UTF8.GetBytes([string]$targetJson))
    $target=$targetJson|ConvertFrom-Json
    Save-NewJson 'controller-receipt.json' @{started_at_utc=$controllerStarted;ended_at_utc=[DateTime]::UtcNow.ToString('o');source='winrm-https-launch-witness';training_ready=$false}
    if($target.receipt.status -cne 'completed' -or -not $target.receipt.cleanup.confirmed_stopped){throw 'activity-or-cleanup-failed-no-retry'}
    Start-Sleep -Seconds 10
    $source=(Invoke-Command -Session $session -FilePath (Join-Path $PSScriptRoot 'collect-source.ps1') -ArgumentList 'Export',$RunId,[string]$bookmark)|ConvertFrom-Json
    $localSource=Join-Path $OutputDirectory 'source'
    New-Item -ItemType Directory -Path $localSource|Out-Null
    foreach($entry in $source.files){
        if([IO.Path]::GetFileName($entry.path) -cne $entry.path){throw 'unsafe-source-name'}
        $local=Join-Path $localSource $entry.path
        Copy-Item -FromSession $session -LiteralPath (Join-Path $source.remote_directory $entry.path) -Destination $local
        if((Get-Item -LiteralPath $local).Length -ne $entry.bytes -or (Get-FileHash -LiteralPath $local -Algorithm SHA256).Hash.ToLowerInvariant() -cne $entry.sha256){throw 'source-transfer-integrity-failed'}
    }
    # Lier les rendus XML aux enregistrements de l'EVTX transfere, pas seulement
    # croire une declaration de fichier dans un manifeste.
    $exported=@(Get-WinEvent -Path (Join-Path $localSource 'events.evtx') -ErrorAction Stop)
    if($exported.Count -ne $source.source_record_count){throw 'evtx-xml-count-mismatch'}
    foreach($event in $exported){
        $xmlEntry=@($source.files|Where-Object {$_.kind -eq 'event-xml-rendering' -and $_.record_id -ceq ([string]$event.RecordId)})
        if($xmlEntry.Count -ne 1){throw 'evtx-xml-record-ambiguous'}
        $sha=[Security.Cryptography.SHA256]::Create()
        try{$digest=([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($event.ToXml())))).Replace('-','').ToLowerInvariant()}finally{$sha.Dispose()}
        if($digest -cne $xmlEntry[0].sha256){throw 'evtx-xml-rendering-mismatch'}
    }
    $source.PSObject.Properties.Remove('remote_directory')
    $source|Add-Member -NotePropertyName evtx_xml_verified_on_controller -NotePropertyValue $true
    $source|ConvertTo-Json -Depth 10 -Compress|ForEach-Object {[IO.File]::WriteAllBytes((Join-Path $localSource 'source-manifest.json'),[Text.Encoding]::UTF8.GetBytes($_))}
    Save-NewJson 'execution-manifest.json' @{status='completed';controller_started_at_utc=$controllerStarted;ended_at_utc=[DateTime]::UtcNow.ToString('o');training_ready=$false}
}catch{
    Save-NewJson 'execution-failure.json' @{error_type=$_.Exception.GetType().Name;reason=$_.Exception.Message;repeat_authorized=$false;remote_cleanup_confirmed=$false;training_ready=$false}
    throw
}finally{if($null -ne $session){Remove-PSSession $session};$cred=$null}
