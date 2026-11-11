param(
    [Parameter(Mandatory)]
    [string]$CertificatePath,
    [string]$ComputerName = '192.168.122.131'
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $CertificatePath).Path
$certificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($resolved)

if (-not $certificate.Verify()) {
    Import-Certificate -FilePath $resolved -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
}

$result = Test-WSMan -ComputerName $ComputerName -UseSSL -Authentication Negotiate
[ordered]@{
    trusted_at_utc          = [DateTime]::UtcNow.ToString('o')
    computer_name           = $ComputerName
    certificate_subject     = $certificate.Subject
    certificate_thumbprint  = $certificate.Thumbprint
    wsman_protocol_version  = [string]$result.ProductVersion
} | ConvertTo-Json
