# Supervision événement–activité V2 — expériences multi-activités

Date : 2026-11-11  
Périmètre : partition `development` uniquement  
État : expérimental, `training_ready: false`

## Conclusion

La méthode V2 distingue correctement deux activités produisant les mêmes types d'alertes, y compris lorsqu'elles sont simultanées. Elle sait maintenant produire une non-appartenance forte, mais uniquement lorsqu'un événement est d'abord prouvé membre d'une autre instance d'exécution techniquement exclusive.

Sur neuf campagnes réelles, 76 événements bruts ont produit 126 décisions événement × activité :

- 42 `member-verified` ;
- 27 `nonmember-verified` ;
- 57 `excluded` ;
- aucune association croisée A/B détectée ;
- aucune donnée V1, aucun modèle et aucun seuil modifiés.

Les résultats sont des résultats de développement. Ils ne constituent pas encore une validation indépendante ni une autorisation d'entraînement ML V2.

## Méthode de décision

### Ubuntu SSH

La chaîne de preuve est :

1. reçu indépendant du contrôleur ;
2. concordance exacte du tuple SSH, notamment le port source éphémère ;
3. alerte d'authentification Wazuh `5715` contenant ce port ;
4. PID `sshd` extrait de l'événement brut ;
5. événements PAM `5501` et `5502` portant exactement le même PID.

L'identité exclusive est `BootId + PID sshd + port source`. Une simple proximité temporelle n'est jamais utilisée comme preuve.

### Windows WinRM

La chaîne de preuve est :

1. reçu indépendant contenant le marqueur et le PID cible ;
2. événement Sysmon 1 ayant le même marqueur, PID, image et ligne de commande ;
3. `ProcessGuid` comme identité principale du processus ;
4. parent exact par `ParentProcessGuid + ParentProcessId` vers Sysmon 7 ;
5. session exacte par `LogonId` vers Windows Security 4624/4634 lorsqu'elle existe.

Le texte générique de la règle Wazuh n'est pas considéré comme une preuve de RDP ou d'attaque. Les champs techniques de l'événement Windows sont utilisés.

### Non-appartenance

`nonmember-verified(event, B)` est autorisé seulement si :

- l'événement est `member-verified` de A ;
- A et B sont deux activités préenregistrées distinctes ;
- leurs identités d'exécution sont mutuellement exclusives ;
- la matrice contient aussi la décision membre correspondante pour A.

Absence de correspondance, autre horaire ou autre LogonId non ancré ne suffisent pas. Ces cas restent `excluded`.

## Résultats comparatifs

Les colonnes `M`, `N` et `E` comptent les cellules de la matrice, pas seulement les événements. Pour deux activités, un événement membre de A produit une cellule membre pour A et une cellule non-membre pour B.

| Campagne | Événements | Activités | M | N | E | Événements avec provenance vérifiée | Croisements |
|---|---:|---:|---:|---:|---:|---:|---:|
| SSH historique contrôlé | 3 | 1 | 3 | 0 | 0 | 100 % | 0 |
| SSH historique répété | 3 | 1 | 3 | 0 | 0 | 100 % | 0 |
| WinRM historique | 8 | 1 | 3 | 0 | 5 | 37,5 % | 0 |
| Ubuntu A — isolée | 3 | 1 | 3 | 0 | 0 | 100 % | 0 |
| Ubuntu B — deux successives | 6 | 2 | 6 | 6 | 0 | 100 % | 0 |
| Ubuntu C — deux simultanées | 6 | 2 | 6 | 6 | 0 | 100 % | 0 |
| Windows A — isolée | 9 | 1 | 3 | 0 | 6 | 33,3 % | 0 |
| Windows B — deux successives | 18 | 2 | 7 | 7 | 22 | 38,9 % | 0 |
| Windows C — deux simultanées | 20 | 2 | 8 | 8 | 24 | 40,0 % | 0 |

L'ancien système et le nouveau donnent les mêmes appartenances sur les trois campagnes historiques : 3/3 pour chaque campagne SSH et 3/8 pour WinRM. Le gain nouveau n'est pas un gonflement artificiel de ces chiffres ; c'est la capacité testée sur des campagnes à deux activités de démontrer les non-appartenances croisées.

## Expériences Ubuntu

### Ubuntu A — activité isolée

- port source : `53247` ;
- PID Wazuh `sshd` : `4501` ;
- résultat : trois événements vérifiés (authentification, ouverture PAM, fermeture PAM).

### Ubuntu B — deux activités successives

- A : port `64255`, PID `4575`, trois événements ;
- B : port `56784`, PID `4637`, trois événements ;
- chaque groupe est membre de sa session et non-membre vérifié de l'autre ;
- aucune association croisée.

### Ubuntu C — deux activités simultanées

Les deux activités ont commencé à la même milliseconde côté contrôleur.

- A : port `62370`, PID `4690` ;
- B : port `62371`, PID `4691` ;
- six appartenances et six non-appartenances croisées vérifiées ;
- aucune dépendance à l'ordre ou à l'heure pour séparer les sessions.

Les identifiants exacts sont enregistrés dans les fichiers `decisions.jsonl` de chaque campagne.

## Expériences Windows

### Windows A — activité isolée

- PID reçu : `8212` ;
- trois événements reliés exactement : processus cmd, parent PowerShell/WinRM observé par Sysmon 7 et session 4624 ;
- six événements 4624/4634 de fond exclus.

### Windows B — deux activités successives

- A : PID `2356`, trois événements membres ;
- B : PID `8876`, quatre événements membres ;
- sept non-appartenances croisées vérifiées ;
- onze événements bruts sans provenance exclusive, donc 22 cellules exclues.

### Windows C — deux activités simultanées

Les deux commandes ont le même horodatage cible à la précision fournie, mais des PID et `ProcessGuid` différents.

- A : PID `7280`, quatre événements membres ;
- B : PID `3152`, quatre événements membres ;
- huit non-appartenances croisées vérifiées ;
- douze événements bruts non ancrés, donc 24 cellules exclues ;
- aucune attribution A vers B ou B vers A.

## Réexamen des cinq événements Windows historiques non résolus

Ils restent correctement exclus :

- un logoff `0x925d87` correspond à une session créée avant l'activité contrôlée, mais aucune autre activité V2 préenregistrée ne l'ancre ;
- les couples de LogonId `0xa64cb6` et `0xa66165` sont cohérents en interne, mais ne possèdent ni reçu indépendant, ni marqueur, ni chaîne exacte vers le processus contrôlé ;
- leur origine différente est plausible, mais pas suffisamment démontrée pour `nonmember-verified`.

Cette décision évite de transformer « non relié à notre activité » en faux négatif fort.

## Types d'événements

Correctement attribués :

- SSH authentication success ;
- ouverture et fermeture de session PAM ;
- Sysmon processus créé (événement 1) ;
- Sysmon image chargée du parent exact (événement 7) ;
- Windows Security 4624/4634 lorsque le `LogonId` est ancré.

Encore difficiles :

- 4624/4634 supplémentaires produits par l'infrastructure WinRM ;
- sessions sans reçu indépendant ni port contrôleur capturé ;
- événements Windows partagés par une infrastructure commune plutôt que par une commande précise.

## Améliorations implémentées

- schéma versionné `event-activity-decision.schema.json` ;
- validateur de matrice cartésienne complète ;
- obligation d'une appartenance alternative avant toute non-appartenance ;
- enrichissement des reçus SSH avec BootId, PID, PPID et start ticks ;
- enrichissement des reçus Windows avec session et tentative de capture Logon SID/LUID ;
- reçus séparés par activité, sans écrasement ;
- constructeur déterministe `build_event_activity_matrix.py` ;
- agrégateur `evaluate_event_activity_matrices.py` ;
- tests ciblant deux SSH identiques et deux commandes Windows concurrentes.

## Tests et intégrité

- 54/54 tests V2 réussis ;
- zéro ligne Wazuh malformée dans les six nouvelles collectes ;
- tous les fichiers bruts conservés ;
- transferts et artefacts scellés par SHA-256 ;
- aucun changement AlertGraph V1 ;
- aucun entraînement ML ;
- aucune donnée `validation` ou `final-test` utilisée ;
- `training_ready: false` partout.

Le rapport machine lisible est `output/wazuh-supervised-v2/reports/event-activity-matrix-comparison-20261111.json`.

## Limites et prochaine étape

Ubuntu est suffisamment instrumenté pour commencer de petites campagnes d'attaque contrôlées en développement.

Pour Windows, la séparation des commandes fonctionne, mais la couverture reste proche de 40 %. Avant de produire beaucoup de données offensives, il est recommandé d'améliorer sans changement de configuration système le reçu WinRM pour capturer aussi le port TCP contrôleur et une identité de session directement corrélable. Les événements non ancrés doivent continuer à être exclus.

La prochaine campagne d'attaque doit rester en `development`, contenir au moins deux instances distinctes du même scénario et une activité bénigne indépendante. Les labels de paires ML ne seront créés qu'après vérification de l'appartenance de chaque activité à son instance d'attaque. Ces données ne doivent pas encore servir à annoncer une performance V2.
