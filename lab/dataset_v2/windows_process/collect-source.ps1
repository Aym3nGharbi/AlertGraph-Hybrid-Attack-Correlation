param(
    [ValidateSet('Bookmark','Export')][string]$Mode='Bookmark',
    [string]$RunId,
    [string]$BookmarkJson
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$channel='Microsoft-Windows-Sysmon/Operational'
$session=[Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession
$info=$session.GetLogInformation($channel,[Diagnostics.Eventing.Reader.PathType]::LogName)
$last=Get-WinEvent -LogName $channel -MaxEvents 1
$oldest=Get-WinEvent -LogName $channel -MaxEvents 1 -Oldest
$current=[ordered]@{computer=$env:COMPUTERNAME;channel=$channel;last_record_id=[long]$last.RecordId;
    oldest_record_id=[long]$oldest.RecordId;log_created_at_utc=$info.CreationTime.ToUniversalTime().ToString('o');
    measured_at_utc=[DateTime]::UtcNow.ToString('o')}
if($Mode -eq 'Bookmark'){$current|ConvertTo-Json -Compress;return}
if($RunId -notmatch '^dev-windows-process-parent-child-[0-9]{8}-[0-9]{3}-r01$'){throw 'run-id-outside-pilot-scope'}
$bookmark=$BookmarkJson|ConvertFrom-Json
if($bookmark.channel -cne $channel -or $bookmark.computer -ine $env:COMPUTERNAME -or
   $bookmark.log_created_at_utc -cne $current.log_created_at_utc -or
   $current.last_record_id -lt $bookmark.last_record_id -or
   $current.oldest_record_id -gt ([long]$bookmark.last_record_id+1)){throw 'log-reset-or-possible-record-loss'}
$begin=[long]$bookmark.last_record_id;$end=[long]$current.last_record_id
$query="*[System[(EventRecordID > $begin) and (EventRecordID <= $end) and (EventID=1 or EventID=11)]]"
$events=@(Get-WinEvent -LogName $channel -FilterXPath $query -MaxEvents 2001 -ErrorAction SilentlyContinue)
if($events.Count -gt 2000){throw 'source-volume-exceeds-preregistered-cap-no-truncation'}
if(@($events|Group-Object RecordId|Where-Object Count -gt 1).Count -ne 0){throw 'duplicate-source-record'}
$root='C:\AlertGraph-Lab\WindowsProcessPilot'
$destination=Join-Path $root $RunId
$resolved=[IO.Path]::GetFullPath($destination)
if(-not $resolved.StartsWith(([IO.Path]::GetFullPath($root)+'\'),[StringComparison]::OrdinalIgnoreCase)){throw 'export-outside-reserved-root'}
if(Test-Path -LiteralPath $resolved){throw 'export-already-exists'}
New-Item -ItemType Directory -Path $resolved | Out-Null
$entries=@()
foreach($event in $events){
    $path=Join-Path $resolved ('event-'+$event.RecordId+'.xml')
    [IO.File]::WriteAllBytes($path,[Text.Encoding]::UTF8.GetBytes($event.ToXml()))
    $entries+=,@{path=[IO.Path]::GetFileName($path);kind='event-xml-rendering';bytes=(Get-Item -LiteralPath $path).Length;
        sha256=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant();record_id=[string]$event.RecordId}
}
$evtx=Join-Path $resolved 'events.evtx'
& wevtutil.exe epl $channel $evtx "/q:$query" '/ow:false'
if($LASTEXITCODE -ne 0){throw 'event-export-failed'}
if((Get-Item -LiteralPath $evtx).Length -gt 10485760){throw 'evtx-export-exceeds-10-mib-no-transfer'}
$entries+=,@{path='events.evtx';kind='evtx-export';bytes=(Get-Item -LiteralPath $evtx).Length;
    sha256=(Get-FileHash -LiteralPath $evtx -Algorithm SHA256).Hash.ToLowerInvariant()}
[ordered]@{complete=$true;before=$bookmark;after=$current;source_record_count=$events.Count;
    remote_directory=$resolved;files=$entries;xml_is_rendering_not_original_evtx_bytes=$true;
    training_ready=$false}|ConvertTo-Json -Depth 8 -Compress
