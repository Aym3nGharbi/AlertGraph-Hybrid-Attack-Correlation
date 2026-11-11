# Automatisation Windows du laboratoire

Cette intégration utilise WinRM HTTPS sur le réseau VMware isolé. Le port 5986
est limité au PC hôte `192.168.122.1`. Basic, CredSSP et le transport non
chiffré restent désactivés. Aucun mot de passe n'est écrit dans le projet.

## Amorçage unique par RDP

Dans Windows, ouvrir PowerShell **en administrateur**, copier le dossier
`lab/windows`, puis exécuter :

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\audit-windows.ps1 -OutputPath C:\AlertGraph-Lab\audit-before.json
.\setup-winrm-https.ps1
.\audit-windows.ps1 -OutputPath C:\AlertGraph-Lab\audit-after.json
```

Le script demande le mot de passe du compte local `alertgraph_runner`. Utiliser
un mot de passe réservé au laboratoire, différent des comptes personnels.

Copier ensuite `C:\AlertGraph-Lab\alertgraph-winrm.cer` vers le PC hôte, sans
copier de clé privée.

## Confiance du certificat sur le PC hôte

```powershell
powershell -ExecutionPolicy Bypass -File .\lab\windows\trust-winrm-certificate.ps1 `
  -CertificatePath .\alertgraph-winrm.cer
```

## Scénario de développement

```powershell
.\lab\run_windows_development.ps1 `
  -RunId dev-windows-powershell-YYYYMMDD-001
```

Le mot de passe est demandé à chaque lancement et n'est jamais sauvegardé. Le
script refuse les identifiants qui ne commencent pas par `dev-windows-`.

Après la latence Wazuh, utiliser `lab/collect_wazuh.py`, puis les constructeurs
de cache et d'inférence existants. Ne jamais utiliser ce lanceur pour les runs
réservés à l'évaluation finale.
