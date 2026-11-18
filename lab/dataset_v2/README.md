# Base supervisÃ©e Wazuh V2 â€” fondations

Ce package est indÃ©pendant de `lab/runs/` et du pipeline V1. Il ne collecte
rien et ne lance aucune simulation.

Contenu :

- `schemas/` : neuf JSON Schemas versionnÃ©s, Draft 2020-12 ;
- `validators.py` : rÃ¨gles inter-documents, confiance, partitions et hashes ;
- `marker_normalization.py` : neutralisation des marqueurs dans les textes
  dÃ©rivÃ©s et garde anti-fuite pour les caractÃ©ristiques ML ;
- `synthetic_fixture.py` : campagne fictive couvrant les cas de supervision ;
- `test_validators.py` : tests d'acceptation et de rejet.
- `prepare_campaign.py` : rÃ©servation append-only des campagnes et marqueurs ;
- `orchestrator_adapters.py` : conversion des reÃ§us V1 et mode dry-run ;
- `collect_campaign.py` : copie brute locale, index Parquet et SHA-256 ;
- `test_campaign_pipeline.py` : tests de la chaÃ®ne campagne â†’ activitÃ© â†’ collecte.

ExÃ©cuter uniquement les tests V2 :

```powershell
python -m unittest lab.dataset_v2.test_validators -v
```

Valider le fixture dans un interprÃ©teur :

```python
from lab.dataset_v2.synthetic_fixture import synthetic_bundle
from lab.dataset_v2.validators import validate_bundle

validate_bundle(synthetic_bundle())  # retourne []
```

Ou avec l'interface en lecture seule :

```powershell
python -m lab.dataset_v2.validate --synthetic
```

Un futur bundle matÃ©rialisÃ© pourra Ãªtre contrÃ´lÃ© avec :

```powershell
python -m lab.dataset_v2.validate --bundle .\bundle.json --base-dir .\racine-campagne
```

`release-manifest.schema.json` impose actuellement `training_ready: false`.
Cette contrainte est volontaire : le fixture synthÃ©tique valide les fondations,
pas la qualitÃ© d'une collecte Wazuh rÃ©elle.

## ChaÃ®ne dry-run complÃ¨te

Ces commandes travaillent uniquement sur les deux fixtures de `examples/` et
ne contactent aucune machine :

```powershell
$root = ".\output\wazuh-v2-dry-run-manual"

python -m lab.dataset_v2.prepare_campaign `
  $root dev-dry-manual-01 dev-dry-manual-01-r01 `
  --partition development `
  --scenario-plan .\lab\dataset_v2\examples\scenario-plan.json `
  --seed 42

$campaign = Join-Path $root "campaigns\dev-dry-manual-01\dev-dry-manual-01-r01"

python -m lab.dataset_v2.orchestrator_adapters `
  $campaign --platform all --dry-run

python -m lab.dataset_v2.clock_audit `
  $campaign `
  --responses .\lab\dataset_v2\examples\clock-responses.json

python -m lab.dataset_v2.collect_campaign `
  $campaign `
  --source-jsonl .\lab\dataset_v2\examples\wazuh-export.jsonl `
  --since "2026-11-10T09:00:00+00:00" `
  --until "2026-11-10T09:05:00+00:00" `
  --agents "synthetic-linux-agent,synthetic-windows-agent" `
  --dry-run
```

Chaque commande refuse d'Ã©craser une sortie existante. Les campagnes
`final-test` reÃ§oivent une sentinelle et sont refusÃ©es par les adaptateurs et la
collecte Ã  ce stade.

ExÃ©cuter tous les tests V2 :

```powershell
python -m unittest discover -s .\lab\dataset_v2 -p "test_*.py" -v
```

## Revue d'appartenance par graphe de preuves

La revue dÃ©rivÃ©e n'Ã©crase jamais `association/`. Elle distingue
`member-verified`, `independent-verified` et `unresolved`. Un Ã©vÃ©nement ne peut
Ãªtre membre vÃ©rifiÃ© que si un chemin exact contient un reÃ§u d'exÃ©cution et une
tÃ©lÃ©mÃ©trie de la cible. L'absence de chemin reste `unresolved`.

Pour SSH, capturer d'abord la chaÃ®ne journald historique du PID concernÃ© :

```powershell
python -m lab.dataset_v2.collect_journal_evidence `
  $campaign --host 192.0.2.20 --user labuser `
  --key $HOME\.ssh\wazuh_lab_ed25519 --pid PID `
  --since "DATE UTC" --until "DATE UTC" --allow-remote-read

python -m lab.dataset_v2.review_activity_membership $campaign --platform ssh
```

Pour Windows, la revue utilise les `ProcessGuid`, PID parent et `LogonId`
prÃ©sents dans le brut Wazuh :

```powershell
python -m lab.dataset_v2.review_activity_membership $campaign --platform windows
```

Les dÃ©cisions `unresolved`, `weak` et `conflict` sont exclues des labels ML
forts. Deux Ã©vÃ©nements d'une mÃªme activitÃ© bÃ©nigne ne deviennent jamais une
paire positive d'attaque.

## PrÃ©-vol rÃ©el en lecture seule â€” ne pas exÃ©cuter avant dÃ©marrage autorisÃ©

AprÃ¨s dÃ©marrage et vÃ©rification manuelle des VM, la rÃ©ponse Windows se prÃ©pare
avec WinRM HTTPS. Le credential reste en mÃ©moire PowerShell :

```powershell
$cred = Get-Credential -UserName 'WINDOWS-LAB\alertgraph_runner'
.\lab\dataset_v2\probe_windows_clock_v2.ps1 `
  -ComputerName 192.0.2.30 `
  -Credential $cred `
  -OutputPath .\output\windows-clock-response.json
```

Les mesures contrÃ´leur, manager et Ubuntu sont ensuite produites par deux
commandes SSH strictement en lecture :

```powershell
python -m lab.dataset_v2.probe_clocks_readonly `
  .\output\clock-responses-real.json `
  --manager-host 192.0.2.10 --manager-user labuser `
  --manager-key $HOME\.ssh\wazuh_lab_ed25519 `
  --ubuntu-host 192.0.2.20 --ubuntu-user labuser `
  --ubuntu-key $HOME\.ssh\wazuh_lab_ed25519 `
  --windows-response .\output\windows-clock-response.json

python -m lab.dataset_v2.clock_audit `
  $campaign --responses .\output\clock-responses-real.json
```

La collecte SSH V2 ne doit Ãªtre lancÃ©e qu'aprÃ¨s acceptation de cet audit :

```powershell
python -m lab.dataset_v2.ssh_collection `
  $campaign `
  --host 192.0.2.10 --user labuser `
  --key $HOME\.ssh\wazuh_lab_ed25519 `
  --since "DATE-UTC-DEBUT" --until "DATE-UTC-FIN" `
  --agents "ubuntu-agent,windows-agent" `
  --allow-remote-read
```

La commande distante autorisÃ©e est uniquement `cat --
/var/ossec/logs/alerts/alerts.json`. L'utilisateur, la clÃ© et les erreurs SSH
ne sont jamais enregistrÃ©s en clair dans les manifestes V2.


## Public V2 additions

See [the public implementation guide](../../docs/v2-public-implementation.md) for
strict provenance, compression/candidate experiments, sudo 2.1 and the prepared
Windows/Sysmon pilot. Real campaign plans, reports, events and proof bundles
remain private and are intentionally absent from this repository.
