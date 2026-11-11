# AlertGraph V2 — investigation événement–activité et supervision forte

Date : 11 novembre 2026. Périmètre : campagnes `development` uniquement.
Les événements bruts, annotations et preuves historiques restent intacts.

## 1. Problème confirmé

L'ancien lieur savait identifier une alerte-ancre, mais ne représentait pas la
provenance sous forme de chaîne. Il laissait donc :

- les ouvertures/fermetures PAM en `weak` malgré le même processus `sshd` ;
- les événements Windows portant le même `LogonId` ou `ProcessGuid` en
  `unknown` ;
- aucune représentation explicite d'une non-appartenance vérifiée ;
- aucune règle centralisée « verified ou exclu » pour les paires ML.

Le temps, l'hôte, l'utilisateur et la règle Wazuh sont trop génériques pour
résoudre seuls ces événements.

## 2. Méthodes étudiées

### Fenêtre, hôte ou score

Rejetés comme preuve. Ils peuvent ordonner une investigation, mais pas établir
l'appartenance. Plusieurs sessions WinRM du même utilisateur apparaissent dans
la même seconde.

### Règles Wazuh ou signatures seules

Rejetées comme preuve d'identité. Les règles 92657 et 60137 se répètent pour
plusieurs sessions distinctes.

### Comparaison différentielle avec/sans activité

Retenue pour les futures campagnes comme aide à l'investigation. Une différence
de fréquence ne sera toutefois jamais une preuve suffisante pour un événement
individuel.

### Graphe de preuves déterministe

Retenu. Une activité possède un événement-ancre relié au reçu d'exécution. La
liaison se propage seulement par une identité exacte et correctement bornée :

- Linux : `machine + BootId + PID + curseur journald` ;
- Windows processus : `machine + ProcessGuid + PID` ;
- Windows session : `machine + LogonId` ;
- réseau : IP, port source, destination et port destination exacts.

Un chemin membre vérifié doit contenir au moins une preuve d'exécution et une
télémétrie de la cible. Wazuh et le journal source ne sont pas comptés comme
deux preuves indépendantes : Wazuh est le transport de cette télémétrie.

L'absence de chemin donne `unresolved`, jamais `independent-verified`.
L'indépendance exige un ancrage technique vers une autre activité connue.

## 3. Résultats événement par événement

### SSH Ubuntu

Pour les deux campagnes SSH, le reçu contrôleur/cible fixe le tuple exact. Les
trois lignes `journald` partagent le même `BootId`, PID et ordre monotone :

1. authentification SSH, règle 5715 : `member-verified` ;
2. session PAM ouverte, règle 5501 : révisée de `weak` vers
   `member-verified` ;
3. session PAM fermée, règle 5502 : révisée de `weak` vers
   `member-verified`.

Le PID seul n'aurait pas suffi ; le `BootId`, les curseurs et l'ancre réseau
éliminent le risque normal de réutilisation du PID.

### WinRM Windows

Événements désormais membres vérifiés :

- `1794408158.17730054`, Sysmon 1 / règle 92052 : marqueur, PID 4224,
  utilisateur et image exacts du reçu ;
- `1794408158.17712329`, Sysmon 7 / règle 92151 : `ProcessGuid` et PID 7080
  égaux au parent du processus ancré ;
- `1794408156.17694648`, Security 4624 / règle 92657 : `TargetLogonId
  0xa62bf8` égal au `LogonId` du processus Sysmon ancré.

Événements toujours non résolus :

- logoff `0x925d87` : sa session a commencé à 14:28, avant l'activité, mais
  aucune autre activité supervisée ne prouve son indépendance causale ;
- logon/logoff `0xa64cb6` ;
- logon/logoff `0xa66165`.

Les deux dernières paires sont cohérentes en interne, mais aucun port capturé,
reçu ou processus ancré ne les rattache avec certitude à l'invocation WinRM.
Elles restent exclues au lieu d'être transformées en négatifs.

## 4. Comparaison

Sur les deux campagnes de la situation initiale :

| Campagne | Ancien | Nouveau |
|---|---:|---:|
| SSH répété | 1 verified, 2 weak | 3 membres vérifiés |
| WinRM | 1 verified, 7 unknown | 3 membres vérifiés, 5 non résolus |

Sur les trois campagnes bénignes historiques :

- 14 événements ;
- 3 `verified` auparavant ;
- 9 `member-verified` maintenant ;
- 0 `independent-verified` ;
- 5 `unresolved` ;
- 0 association croisée ;
- diversité vérifiée : SSH, PAM ouverture/fermeture, Sysmon Process Create,
  Sysmon Image Load et Security Logon.

La couverture actuelle est de 100 % sur chaque campagne SSH et de 37,5 % sur
WinRM. Cette augmentation vient d'identifiants exacts, pas d'un relâchement des
critères.

## 5. Politique ML V2

- `member-verified` : utilisable selon la classe et l'instance supervisée ;
- `independent-verified` : négatif possible uniquement si l'autre activité est
  elle-même connue ;
- `weak`, `unknown`, `conflict`, `unresolved` : exclus ;
- même activité bénigne : jamais positive automatiquement ;
- même instance d'attaque vérifiée : positive ;
- attaques distinctes vérifiées : négative ;
- attaque vérifiée contre activité bénigne vérifiée : négative.

Les campagnes actuelles offrent au maximum 27 négatifs bénin–bénin potentiels
avant la génération normale des candidats. Elles n'offrent aucune paire
positive d'attaque. `training_ready` reste `false`.

## 6. Implémentation

- schéma `membership-decision.schema.json` ;
- validation des trois états et des familles de preuves ;
- politique de paires fortes ;
- collecteur journald borné et en lecture seule ;
- réviseur par graphe de preuves avec annotations dérivées et révisions ;
- évaluateur comparatif reproductible ;
- conservation des sorties V1/V2 et des tentatives remplacées.

## 7. Instrumentation nécessaire pour les futures campagnes

Avant les attaques, les orchestrateurs devront enregistrer :

1. tous les sockets contrôleur, notamment les ports éphémères WinRM ;
2. `BootId`, PID, temps de démarrage et ascendance des processus Linux ;
3. PID, PID parent, SessionId, LogonId et utilisateur du processus Windows ;
4. `ProcessGuid`, `ParentProcessGuid` et LogonId récupérés dans la télémétrie ;
5. curseurs journald et numéros d'enregistrement Windows ;
6. preuves avec et sans l'activité, isolées puis simultanées ;
7. un reçu distinct par étape et par instance d'attaque.

Les captures supplémentaires doivent être préenregistrées, bornées et
horodatées. Les marqueurs restent des preuves et sont neutralisés dans les
textes dérivés ML.

## 8. Limites

- les sessions WinRM auxiliaires ne sont pas toutes reliables avec les reçus
  historiques ;
- aucune non-appartenance vérifiée n'est disponible ;
- aucune attaque contrôlée V2 n'a encore été exécutée ;
- les résultats sont du développement, pas une validation indépendante ;
- une jointure exacte peut encore être erronée si son périmètre de réutilisation
  n'est pas borné par la machine, le démarrage ou la session.

## 9. Références techniques

- Microsoft documente le `Logon ID` de 4624 comme identifiant de corrélation
  sur la même machine : https://learn.microsoft.com/fr-fr/windows/security/threat-protection/auditing/event-4624
- Sysmon Event ID 1 fournit la ligne de commande, le parent et un ProcessGuid
  destiné à la corrélation : https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events
- Sysmon Event ID 7 décrit le chargement d'une image dans un processus :
  https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events
