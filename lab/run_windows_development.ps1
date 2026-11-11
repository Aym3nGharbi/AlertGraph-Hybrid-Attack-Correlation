param(
    [Parameter(Mandatory)]
    [ValidatePattern('^dev-windows-[a-zA-Z0-9_-]+$')]
    [string]$RunId,
    [string]$ComputerName = '192.168.122.131',
    [string]$RunnerUser = 'WINDOWS-LAB\alertgraph_runner',
    [string]$OutputRoot = 'lab\runs',
    [pscredential]$Credential
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Set-Location -LiteralPath (Split-Path -Parent $PSScriptRoot)

if (-not $Credential) { $Credential = Get-Credential -UserName $RunnerUser }
$output = Join-Path $OutputRoot $RunId
if (Test-Path -LiteralPath $output) { throw "Le run existe déjà : $output" }
New-Item -ItemType Directory -Path $output | Out-Null

$document = [ordered]@{
    run_id              = $RunId
    partition           = 'development'
    attack_instance_id  = "attack:$RunId"
    target_agent        = 'windows-agent'
    target_host         = $ComputerName
    started_at          = [DateTime]::UtcNow.ToString('o')
    status              = 'running'
    steps               = @()
    benign_background   = @()
}

function Save-Truth {
    $document | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $output 'activity-truth.json') -Encoding UTF8
}

$session = New-PSSession -ComputerName $ComputerName -UseSSL -Authentication Negotiate -Credential $Credential
try {
    $remoteAudit = Invoke-Command -Session $session -FilePath 'lab\windows\audit-windows.ps1'
    $remoteAudit | Set-Content -LiteralPath (Join-Path $output 'windows-audit-before.json') -Encoding UTF8

    function Invoke-Step([string]$Name, [string]$Phase, [scriptblock]$Action) {
        $started = [DateTime]::UtcNow.ToString('o')
        $result = Invoke-Command -Session $session -ScriptBlock $Action -ArgumentList $RunId
        $ended = [DateTime]::UtcNow.ToString('o')
        $document.steps += [ordered]@{
            name               = $Name
            ground_truth_phase = $Phase
            started_at         = $started
            ended_at           = $ended
            result             = @($result)
        }
        Save-Truth
        Start-Sleep -Seconds 2
    }

    Invoke-Step 'powershell-script-staging' 'execution' {
        param($id)
        $runRoot = Join-Path 'C:\AlertGraph-Lab\runs' $id
        New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
        $script = Join-Path $env:TEMP "$id.ps1"
        @"
whoami | Set-Content -LiteralPath '$runRoot\identity.txt'
hostname | Set-Content -LiteralPath '$runRoot\hostname.txt'
(Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath '$runRoot\executed-at.txt'
"@ | Set-Content -LiteralPath $script -Encoding UTF8
        $script
    }

    Invoke-Step 'powershell-process-start' 'execution' {
        param($id)
        $script = Join-Path $env:TEMP "$id.ps1"
        $process = Start-Process powershell.exe -ArgumentList @('-NoProfile','-NonInteractive','-File',$script) -Wait -PassThru
        "exit_code=$($process.ExitCode)"
    }

    Invoke-Step 'host-and-user-discovery' 'discovery' {
        param($id)
        $ipv4 = [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
            ForEach-Object { $_.GetIPProperties().UnicastAddresses } |
            Where-Object {
                $_.Address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
                -not [Net.IPAddress]::IsLoopback($_.Address)
            } | ForEach-Object { $_.Address.IPAddressToString }
        [ordered]@{
            run      = $id
            user     = (& whoami.exe)
            hostname = (& hostname.exe)
            ipv4     = @($ipv4)
        } | ConvertTo-Json -Compress
    }

    $benignStarted = [DateTime]::UtcNow.ToString('o')
    $benignResult = Invoke-Command -Session $session -ScriptBlock {
        Get-Date | Out-Null
        Get-Process | Select-Object -First 5 -ExpandProperty ProcessName
    }
    $document.benign_background += [ordered]@{
        name       = 'normal-system-query'
        label      = 'benign'
        started_at = $benignStarted
        ended_at   = [DateTime]::UtcNow.ToString('o')
        result     = @($benignResult)
    }
    Save-Truth

    Invoke-Step 'harmless-network-connection' 'command_and_control_simulation' {
        param($id)
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $connected = $client.ConnectAsync('192.168.122.129', 443).Wait(3000) -and $client.Connected
            "run=$id connected=$connected destination=192.168.122.129:443"
        } finally { $client.Dispose() }
    }

    Invoke-Step 'canary-modify-and-cleanup' 'defense_evasion_simulation' {
        param($id)
        $runRoot = Join-Path 'C:\AlertGraph-Lab\runs' $id
        $canary = Join-Path $runRoot 'canary.txt'
        Set-Content -LiteralPath $canary -Value "run=$id"
        Add-Content -LiteralPath $canary -Value 'controlled-development-scenario'
        Start-Sleep -Seconds 2
        Remove-Item -LiteralPath $canary -Force
        Remove-Item -LiteralPath (Join-Path $env:TEMP "$id.ps1") -Force
        'cleanup-complete'
    }

    $document.status = 'completed'
    $document.ended_at = [DateTime]::UtcNow.ToString('o')
    $document.collection_not_before = [DateTime]::UtcNow.AddSeconds(25).ToString('o')
    Save-Truth
    $document | ConvertTo-Json -Depth 8
} catch {
    $document.status = 'failed'
    $document.ended_at = [DateTime]::UtcNow.ToString('o')
    $document.failure = [ordered]@{
        type    = $_.Exception.GetType().FullName
        message = $_.Exception.Message
    }
    Save-Truth
    throw
} finally {
    if ($session) { Remove-PSSession $session }
}
