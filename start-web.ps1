$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw 'Node.js est introuvable. Réinstaller Node.js ou corriger le PATH.'
}

Write-Host 'AlertGraph sera disponible sur http://127.0.0.1:8080'
Write-Host 'Laisser cette fenêtre ouverte. Utiliser Ctrl+C pour arrêter le serveur.'
node src/server.js
