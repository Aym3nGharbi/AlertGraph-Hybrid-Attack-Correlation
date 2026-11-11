param(
    [Parameter(Mandatory)]
    [string]$ComputerName,
    [Parameter(Mandatory)]
    [pscredential]$Credential,
    [Parameter(Mandatory)]
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (Test-Path -LiteralPath $OutputPath) {
    throw "Le fichier existe déjà : $OutputPath"
}

$started = [DateTimeOffset]::UtcNow
$remote = Invoke-Command `
    -ComputerName $ComputerName `
    -UseSSL `
    -Authentication Negotiate `
    -Credential $Credential `
    -ScriptBlock {
        $now = [DateTimeOffset]::UtcNow
        $status = & w32tm.exe /query /status 2>&1 | Out-String
        $ok = ($LASTEXITCODE -eq 0) -and
              ($status -notmatch 'unsynchronized|not synchronized|non synchronis')
        [pscustomobject]@{
            remote_time_utc = $now.ToString('o')
            synchronized    = [bool]$ok
            sync_source     = 'winrm-https:w32tm-status'
        }
    }
$ended = [DateTimeOffset]::UtcNow

$document = [ordered]@{
    'windows-target' = [ordered]@{
        request_started_at_utc = $started.ToString('o')
        request_ended_at_utc   = $ended.ToString('o')
        remote_time_utc        = [string]$remote.remote_time_utc
        synchronized           = [bool]$remote.synchronized
        sync_source            = [string]$remote.sync_source
    }
}

$parent = Split-Path -Parent $OutputPath
if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$document | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $OutputPath -Encoding UTF8 -NoNewline
Write-Output $OutputPath
