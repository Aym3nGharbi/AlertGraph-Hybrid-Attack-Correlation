#requires -RunAsAdministrator
param(
    [string]$ClientAddress = '192.168.122.1',
    [string]$ServerAddress = '192.168.122.131',
    [string]$RunnerUser = 'alertgraph_runner',
    [string]$LabRoot = 'C:\AlertGraph-Lab'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$serverInterface = Get-NetIPAddress -IPAddress $ServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue
if (-not $serverInterface) { throw "Adresse $ServerAddress absente de cette machine." }
$networkProfile = Get-NetConnectionProfile -InterfaceIndex $serverInterface.InterfaceIndex
if ($networkProfile.NetworkCategory -eq 'Public') {
    Write-Host "Le réseau VMware $ServerAddress est classé Public; passage à Private pour WinRM local." -ForegroundColor Yellow
    Set-NetConnectionProfile -InterfaceIndex $serverInterface.InterfaceIndex -NetworkCategory Private
}

if (-not (Get-LocalUser -Name $RunnerUser -ErrorAction SilentlyContinue)) {
    $password = Read-Host "Mot de passe du compte local $RunnerUser" -AsSecureString
    New-LocalUser -Name $RunnerUser -Password $password -Description 'AlertGraph controlled lab automation' | Out-Null
}

$remoteGroup = Get-LocalGroup -SID 'S-1-5-32-580'
$eventGroup = Get-LocalGroup -SID 'S-1-5-32-573'
foreach ($group in @($remoteGroup, $eventGroup)) {
    $isMember = Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "*\$RunnerUser" }
    if (-not $isMember) { Add-LocalGroupMember -Group $group.Name -Member $RunnerUser }
}

New-Item -ItemType Directory -Path $LabRoot -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $LabRoot 'runs') -Force | Out-Null
& icacls.exe $LabRoot /grant "${env:COMPUTERNAME}\${RunnerUser}:(OI)(CI)M" /T /C | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Impossible d'accorder les droits sur le répertoire de laboratoire." }

Enable-PSRemoting -SkipNetworkProfileCheck -Force

# Enable-PSRemoting peut lever le filtrage UAC des comptes administrateurs
# locaux. AlertGraph utilise un compte non administrateur dédié : cette
# exception plus large est donc supprimée immédiatement.
Remove-ItemProperty `
    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name 'LocalAccountTokenFilterPolicy' -ErrorAction SilentlyContinue

# Le listener HTTP créé par Enable-PSRemoting est retiré : le laboratoire utilise HTTPS uniquement.
Get-ChildItem WSMan:\localhost\Listener | Where-Object { $_.Keys -contains 'Transport=HTTP' } |
    Remove-Item -Recurse -Force

$friendlyName = 'AlertGraph WinRM HTTPS'
$certificate = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.FriendlyName -eq $friendlyName -and $_.NotAfter -gt (Get-Date).AddDays(30) } |
    Sort-Object NotAfter -Descending | Select-Object -First 1

if (-not $certificate) {
    $certificate = New-SelfSignedCertificate `
        -Type SSLServerAuthentication `
        -Subject "CN=$env:COMPUTERNAME" `
        -TextExtension @("2.5.29.17={text}DNS=$env:COMPUTERNAME&IPAddress=$ServerAddress") `
        -CertStoreLocation 'Cert:\LocalMachine\My' `
        -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2) `
        -FriendlyName $friendlyName
}

$httpsListeners = @(Get-ChildItem WSMan:\localhost\Listener |
    Where-Object { $_.Keys -contains 'Transport=HTTPS' })
if ($httpsListeners.Count -gt 1) { throw 'Plusieurs listeners HTTPS existent. Audit manuel requis.' }
if ($httpsListeners.Count -eq 1) {
    $thumbprintPath = Join-Path $httpsListeners[0].PSPath 'CertificateThumbprint'
    $listenerThumbprint = [string](Get-Item -LiteralPath $thumbprintPath).Value
    if ($listenerThumbprint -ne $certificate.Thumbprint) {
        throw 'Un listener HTTPS non géré par AlertGraph existe déjà. Aucun remplacement automatique.'
    }
}
if ($httpsListeners.Count -eq 0) {
    New-Item -Path WSMan:\localhost\Listener -Transport HTTPS -Address '*' `
        -CertificateThumbPrint $certificate.Thumbprint -Force | Out-Null
}

Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false
Set-Item WSMan:\localhost\Service\Auth\Negotiate -Value $true
Set-Service WinRM -StartupType Automatic
Start-Service WinRM

Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' -ErrorAction SilentlyContinue |
    Disable-NetFirewallRule
Remove-NetFirewallRule -Name 'AlertGraph-WinRM-HTTPS' -ErrorAction SilentlyContinue
New-NetFirewallRule -Name 'AlertGraph-WinRM-HTTPS' `
    -DisplayName 'AlertGraph WinRM HTTPS from VMware host' `
    -Direction Inbound -Action Allow -Enabled True -Profile Any `
    -Protocol TCP -LocalPort 5986 -RemoteAddress $ClientAddress | Out-Null

$exportPath = Join-Path $LabRoot 'alertgraph-winrm.cer'
Export-Certificate -Cert $certificate -FilePath $exportPath -Force | Out-Null

[ordered]@{
    configured_at_utc       = [DateTime]::UtcNow.ToString('o')
    computer                = $env:COMPUTERNAME
    server_address          = $ServerAddress
    allowed_client          = $ClientAddress
    transport               = 'HTTPS'
    port                    = 5986
    certificate_thumbprint  = $certificate.Thumbprint
    certificate_export     = $exportPath
    runner_user             = $RunnerUser
    basic_auth              = $false
    credssp                 = $false
    allow_unencrypted       = $false
} | ConvertTo-Json
