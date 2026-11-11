param(
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

function Service-State([string[]]$Names) {
    foreach ($name in $Names) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($service) {
            $startMode = 'restricted'
            try {
                $cim = Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'" -ErrorAction Stop
                $startMode = $cim.StartMode
            } catch { }
            return [ordered]@{
                name       = $service.Name
                status     = [string]$service.Status
                start_mode = $startMode
            }
        }
    }
    return $null
}

$agentConfig = @(
    'C:\Program Files (x86)\ossec-agent\ossec.conf',
    'C:\Program Files\ossec-agent\ossec.conf'
) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

$configText = $null
$configReadError = $null
if ($agentConfig) {
    try { $configText = Get-Content -Raw -LiteralPath $agentConfig -ErrorAction Stop }
    catch { $configReadError = $_.Exception.Message }
}
$sysmonLog = Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue
$recentEvents = if ($sysmonLog) {
    @(Get-WinEvent -FilterHashtable @{
        LogName   = 'Microsoft-Windows-Sysmon/Operational'
        StartTime = (Get-Date).AddHours(-24)
    } -MaxEvents 5000 -ErrorAction SilentlyContinue)
} else { @() }

$operatingSystem = try {
    $value = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    [ordered]@{ caption = $value.Caption; version = $value.Version; source = 'cim' }
} catch {
    [ordered]@{
        caption = [Environment]::OSVersion.VersionString
        version = [Environment]::OSVersion.Version.ToString()
        source  = 'dotnet-limited-account'
    }
}

$network = try {
    @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.IPAddress -notlike '127.*' } |
        Select-Object InterfaceAlias, IPAddress, PrefixLength)
} catch { @() }

$listeners = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction SilentlyContinue | ForEach-Object {
    $listener = $_
    $properties = @(Get-ChildItem -LiteralPath $listener.PSPath)
    [ordered]@{
        keys                   = @($listener.Keys)
        certificate_thumbprint = [string](($properties | Where-Object Name -eq 'CertificateThumbprint').Value)
        enabled                = [string](($properties | Where-Object Name -eq 'Enabled').Value)
    }
})

$document = [ordered]@{
    audited_at_utc = [DateTime]::UtcNow.ToString('o')
    computer       = $env:COMPUTERNAME
    windows        = $operatingSystem
    network        = $network
    wazuh_agent    = [ordered]@{
        service                 = Service-State @('WazuhSvc', 'Wazuh')
        config_path             = $agentConfig
        config_readable         = [bool]($null -ne $configText)
        config_read_error       = $configReadError
        sysmon_channel_collected = if ($null -ne $configText) {
            [bool]($configText -match 'Microsoft-Windows-Sysmon/Operational')
        } else { $null }
    }
    sysmon         = [ordered]@{
        service          = Service-State @('Sysmon64', 'Sysmon')
        log_exists       = [bool]$sysmonLog
        log_enabled      = if ($sysmonLog) { [bool]$sysmonLog.IsEnabled } else { $false }
        record_count     = if ($sysmonLog) { [long]$sysmonLog.RecordCount } else { 0 }
        recent_24h_sample_count = $recentEvents.Count
        recent_24h_sample_limit = 5000
        recent_event_ids = @($recentEvents | Group-Object Id | Sort-Object Count -Descending |
            Select-Object @{n='event_id';e={[int]$_.Name}}, Count)
    }
    winrm          = [ordered]@{
        service   = Service-State @('WinRM')
        listeners = $listeners
    }
}

$json = $document | ConvertTo-Json -Depth 8
if ($OutputPath) {
    $parent = Split-Path -Parent $OutputPath
    if ($parent) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    Set-Content -LiteralPath $OutputPath -Value $json -Encoding UTF8
}
$json
