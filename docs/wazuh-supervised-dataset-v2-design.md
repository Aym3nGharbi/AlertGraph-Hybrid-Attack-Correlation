# Conception de la base supervisée Wazuh V2

La feuille de route des caractéristiques et de la comparaison ML V1/V2 est
maintenue séparément dans `docs/alertgraph-v2-ml-roadmap.md`.

Date : 2026-11-10  
Statut : conception uniquement — aucune VM lancée, aucune simulation exécutée, aucun modèle réentraîné  
Décision scientifique : la base V1 et ses résultats restent intacts ; la V2 est un pipeline parallèle et versionné.

## 1. Conclusion de l'analyse existante

Le laboratoire possède déjà quatre fondations réutilisables :

1. `lab/collect_wazuh.py` exporte le JSON Wazuh original par intervalle UTC et agent ;
2. `ml/wazuh_dataset.py` normalise Wazuh vers le schéma observable d'AlertGraph sans injecter de vérité terrain ;
3. `ml/build_wazuh_lab_cache.py` produit les méta-alertes et les paires, conserve `member_alert_ids` et refuse une compression non réversible ;
4. les lanceurs Linux et Windows enregistrent les activités contrôlées, leur instance, leur phase et leurs horaires.

La faiblesse se situe entre l'activité exécutée et l'événement Wazuh. Le système actuel propose un label lorsque cible, intervalle et règle correspondent. Cette proposition est prudente puisque les événements non listés restent inconnus, mais elle ne conserve pas encore :

- une preuve structurée et référencée ;
- un niveau `verified/weak/unknown` par événement ;
- les conflits entre sources d'annotation ;
- un label bénin vérifié au niveau événement ;
- l'empreinte du fichier brut et de toutes les entrées ayant produit le cache ;
- une table de vérité séparée, versionnée et directement compatible avec `make_pair_supervision()`.

La V2 doit corriger ces limites sans remplacer immédiatement le pipeline opérationnel actuel.

## 2. Architecture proposée

```text
registre de campagnes figé
        |
        v
manifest campagne -> orchestrateur -> journal d'activités + preuves d'exécution
                                      |
Wazuh alerts.json -> export brut immuable + index d'événements
                                      |
                 association événement <-> activité
                                      |
              revue et résolution des conflits
                                      |
       event_truth_v2 (verified / weak / unknown)
                 |                    |
                 v                    v
        cache observable        meta_truth_v2
                 \                    /
                  -> pair_truth_v2 -> évaluation/retraining futur
```

La vérité terrain reste physiquement séparée des observations et des caractéristiques. Les identifiants de campagne, d'attaque et d'activité ne doivent jamais être ajoutés au vecteur ML.

### Unités d'identification

- `campaign_id` : unité indivisible de séparation développement/validation/test ;
- `run_id` : exécution technique d'une campagne ; une nouvelle tentative reçoit un nouveau `run_id` ;
- `attack_instance_id` : une attaque contrôlée précise à l'intérieur de la campagne ;
- `activity_id` : une action contrôlée précise ;
- `benign_activity_id` : action bénigne contrôlée et indépendante ;
- `evidence_id` : preuve technique immuable ;
- `wazuh_alert_id` : identifiant original Wazuh ;
- `meta_id` : méta-alerte dérivée, avec la liste exhaustive de ses événements membres.

Une campagne peut contenir plusieurs attaques et activités bénignes simultanées. Une campagne ne peut appartenir qu'à une partition.

## 3. Arborescence V2

La V2 sera créée dans un nouvel espace, sans modifier `lab/runs/` :

```text
lab/dataset-v2/
  campaign-registry.json
  schemas/
  campaigns/<campaign_id>/<run_id>/
    campaign-manifest.json
    execution/
      activities.jsonl
      evidence.jsonl
      stdout/
      host-audits/
    raw/
      alerts.jsonl
      alert-index.parquet
      collection-manifest.json
    annotations/
      proposals.jsonl
      reviews.jsonl
      conflicts.jsonl
      event-truth.parquet
    derived/
      meta-observable.parquet
      meta-truth.parquet
      pair-examples.parquet
      pair-truth.parquet
      manifest.json
  releases/<dataset_version>/
    release-manifest.json
    file-hashes.sha256
```

Les fichiers bruts, journaux d'exécution et revues sont immuables. Une correction produit une nouvelle révision d'annotation ou une nouvelle release ; elle n'écrase pas la précédente.

## 4. Formats de données

### 4.1 Registre des campagnes

Le registre doit être créé et figé avant l'exécution :

```json
{
  "schema_version": "alertgraph-campaign-registry/2.0",
  "dataset_version": "wazuh-supervised-v2",
  "frozen_at_utc": "...",
  "campaigns": [
    {
      "campaign_id": "dev-linux-overlap-01",
      "partition": "development",
      "scenario_template": "two-overlapping-attacks-linux",
      "parameter_seed": 1041,
      "status": "planned"
    }
  ]
}
```

Le seed fixe les délais, noms de canaris et ordre des actions. Le test final peut être préparé, mais ses alertes et métriques ne sont ouvertes qu'après le gel du modèle V2.

### 4.2 Manifeste de campagne

Champs obligatoires :

- versions du schéma, scripts et configurations ;
- `campaign_id`, `run_id`, partition et seed ;
- horodatage UTC, fuseau et mesure du décalage d'horloge de chaque machine ;
- manager Wazuh, agents et hôtes impliqués ;
- instances d'attaque et activités bénignes prévues ;
- marqueurs uniques attendus ;
- hashes du mapping, des scripts et de la configuration Sysmon/Wazuh ;
- statut `planned/running/completed/failed/invalidated/frozen`.

Un run échoué reste conservé, mais il est `invalidated` et exclu des ensembles supervisés.

### 4.3 Journal d'activités

Chaque ligne de `activities.jsonl` décrit une activité :

```json
{
  "schema_version": "alertgraph-activity/2.0",
  "campaign_id": "dev-linux-overlap-01",
  "run_id": "dev-linux-overlap-01-r01",
  "activity_id": "act-0007",
  "class": "attack",
  "attack_instance_id": "attack-alpha",
  "benign_activity_id": null,
  "activity_name": "canary-create",
  "true_activity_phase": "execution",
  "controller_started_at_utc": "...",
  "controller_ended_at_utc": "...",
  "target_started_at_utc": "...",
  "target_ended_at_utc": "...",
  "target_agents": ["ubuntu-agent"],
  "target_hosts": ["192.168.122.130"],
  "marker_id": "agv2-...",
  "command_spec_sha256": "...",
  "exit_code": 0,
  "evidence_ids": ["evd-001", "evd-002"]
}
```

`true_activity_phase` décrit l'action exécutée. Elle est distincte de `observed_stage`, qui reste une catégorie inférée depuis les métadonnées Wazuh.

### 4.4 Index des événements bruts

`alerts.jsonl` doit conserver chaque ligne Wazuh sans transformation. `alert-index.parquet` ajoute seulement un index externe :

- `wazuh_alert_id`, numéro de ligne et offsets octets ;
- SHA-256 de la ligne brute ;
- timestamp Wazuh, agent, règle et decoder ;
- SHA-256 du fichier `alerts.jsonl` dans `collection-manifest.json`.

Le manifeste de collecte conserve également source, intervalle demandé, agents, nombres lus/écrits/malformés, versions, latence d'attente et audits d'horloge.

### 4.5 Annotation événementielle

`event-truth.parquet` contient une ligne par événement annoté :

| Champ | Rôle |
|---|---|
| `wazuh_alert_id` | jointure vers le brut |
| `class` | `attack`, `benign`, `unknown` |
| `attack_instance_id` | renseigné uniquement pour une attaque |
| `benign_activity_id` | activité bénigne vérifiée |
| `activity_id` | action contrôlée associée |
| `true_activity_phase` | phase réelle de l'activité, si connue |
| `confidence` | `verified`, `weak`, `unknown`, `conflict` |
| `annotation_source` | `direct-marker`, `derived-telemetry`, `time-window`, `manual-review`, etc. |
| `evidence_ids` | références aux preuves |
| `review_status` | `unreviewed`, `accepted`, `rejected` |
| `reviewer_id`, `reviewed_at_utc` | traçabilité de la revue |
| `label_conflict` | booléen conservé jusqu'aux paires |
| `conflict_reasons` | sources en désaccord |
| `annotation_revision` | version de l'annotation |

Les événements sans ligne acceptée restent inconnus. Ils ne deviennent jamais bénins par défaut.

### 4.6 Vérité des méta-alertes et des paires

`meta-truth.parquet` est construit après la compression observable :

- `verified` seulement si tous les événements membres annotés sont vérifiés et désignent la même classe, la même instance et une phase compatible ;
- `weak` si l'ensemble est cohérent mais inclut une annotation faible ;
- `conflict` si des membres désignent des classes, instances ou phases incompatibles ;
- `unknown` si la preuve est insuffisante.

`pair-truth.parquet` contient `target`, `confidence`, `label_reason`, les révisions d'annotation et les références de preuves. Les règles restent :

- même instance d'attaque vérifiée : positive forte ;
- deux instances d'attaque vérifiées différentes : négative forte ;
- attaque vérifiée et activité bénigne vérifiée : négative forte ;
- deux activités bénignes explicitement indépendantes : négative forte ;
- fenêtre temporelle seule ou extrémité faible : paire faible ;
- conflit ou extrémité inconnue : paire exclue de l'apprentissage supervisé.

Deux alertes bénignes proches ne doivent pas être déclarées négatives fortes si elles appartiennent à la même activité opérationnelle. Cette précaution évite de créer artificiellement de faux négatifs.

## 5. Association fiable activité–événement

### Niveau vérifié

Une association peut être `verified` lorsqu'elle possède une preuve d'identité directe et une preuve de cohérence technique :

- marqueur unique présent dans un chemin, une commande, un message ou un champ de l'événement ;
- GUID de processus Sysmon, chemin de canari, utilisateur éphémère ou port réservé correspondant au journal d'exécution ;
- agent/hôte attendu et règle techniquement compatible ;
- activité confirmée par le journal de l'orchestrateur avec code de sortie et horaires cohérents.

Le temps et l'hôte renforcent une preuve, mais ne suffisent pas seuls pour obtenir `verified`.

Une chaîne dérivée peut être vérifiée, par exemple enfant Sysmon relié au processus marqué par `ProcessGuid`, à condition que chaque maillon soit conservé dans `evidence.jsonl`.

### Niveau faible

Une association est `weak` lorsque la règle et l'agent sont compatibles, mais que l'identité repose principalement sur une fenêtre temporelle, une signature générique ou une proximité avec l'activité.

### Inconnu ou conflit

- aucune preuve suffisante : `unknown` ;
- deux activités revendiquent le même événement, classe attaque/bénin contradictoire, instance divergente ou marqueur incompatible : `conflict` ;
- un conflit ne peut être résolu que par une revue enregistrée ; il n'est jamais écrasé silencieusement.

### Revue

Les propositions automatiques ne deviennent pas fortes par elles-mêmes. Une proposition directe peut être acceptée automatiquement uniquement si le validateur de schéma confirme les deux preuves préenregistrées. Les cas faibles, conflits, règles nouvelles et échantillons de contrôle passent en revue manuelle.

## 6. Scénarios à réaliser

Un minimum réaliste est de 16 campagnes indépendantes : 8 développement, 4 validation et 4 test final. Si le temps le permet, chaque modèle de scénario est répété avec un nouveau seed pour atteindre 24 campagnes.

| Modèle | Contenu | Paires principalement couvertes |
|---|---|---|
| S1 — attaque Linux unique | authentification, commande privilégiée, canari FIM, nettoyage | même attaque, plusieurs phases |
| S2 — attaque Windows unique | PowerShell marqué, processus Sysmon, découverte, connexion, FIM | même attaque Windows |
| S3 — deux attaques superposées même hôte | deux utilisateurs, canaris et marqueurs distincts, actions entremêlées | attaques différentes difficiles |
| S4 — attaque + bruit bénin simultané | attaque marquée et opérations administratives bénignes marquées sur les mêmes hôtes | attaque–bénin difficile |
| S5 — bénin contrôlé uniquement | connexions normales, requêtes système et FIM bénin avec identités distinctes | bénin–bénin vérifié |
| S6 — progression longue | même instance avec pauses préenregistrées de 2, 15 et 60 minutes | positives longues, couverture de candidats |
| S7 — progression multi-hôte | activité Windows puis Linux avec un pivot contrôlé et référencé | même attaque inter-hôtes |
| S8 — attaques simultanées multi-hôtes | deux instances indépendantes plus bruit bénin | fusions, A/B, attaque–bénin |

Répartition minimale :

- développement : S1 à S8, utilisé pour instrumentation, mapping et conception V2 ;
- validation : quatre nouvelles campagnes couvrant S3, S4, S6 et S7 avec seeds, identités et horaires différents ;
- test final : quatre campagnes réservées couvrant attaque unique, superposition, progression longue/multi-hôte et campagne mixte avec bénin.

Les délais, instances, activités et marqueurs du test final sont préenregistrés. Aucun résultat final ne sert à modifier mapping, caractéristiques, poids, seuil ou stratégie graphique.

## 7. Machines et rôles

| Machine | Rôle |
|---|---|
| PC hôte | contrôleur, registre, orchestrateur, horodatage, collecte et stockage V2 |
| Wazuh `192.168.122.129` | manager et source de `alerts.json`; aucune simulation exécutée dessus |
| Ubuntu `192.168.122.130` | cible Linux et producteur de télémétrie Wazuh/FIM/authentication |
| Windows `192.168.122.131` | cible Windows, agent Wazuh et Sysmon |

Avant chaque campagne, il faudra vérifier l'état des agents, Sysmon/FIM, l'espace disque et le décalage UTC. Ces vérifications deviennent des preuves du run, pas seulement des messages de console.

## 8. Composants existants à réutiliser

| Composant | Réutilisation |
|---|---|
| `lab/collect_wazuh.py` | moteur de lecture SSH et filtrage ; l'envelopper pour sauvegarder manifeste et hashes |
| `lab/run_linux_development.py` | modèle d'orchestration, marqueurs et journal UTC |
| `lab/run_windows_development.ps1` | modèle WinRM, activités Windows et sauvegarde après chaque étape |
| `lab/propose_annotations.py` | règles actuelles comme propositions faibles ou directes, jamais comme vérité finale implicite |
| `lab/merge_annotations.py` | principe de refus des conflits ; à généraliser à classe, activité, phase et preuves |
| `ml/wazuh_dataset.py` | normalisation observable et mapping `unknown-is-neutral` |
| `ml/build_wazuh_lab_cache.py` | compression, candidats et calcul des caractéristiques |
| `ml/traceability.py` | bijection événement brut–membre de méta-alerte |
| `ml/pair_features.py` | caractéristiques observables et logique de supervision à adapter au format V2 |
| `lab/evaluate_run.py` | base des métriques relationnelles et graphiques |
| `config/wazuh-stage-mapping.json` | mapping observable versionné et hashé par release |
| `lab/scenarios/*.json` | point de départ pour le registre figé des partitions |

## 9. Nouveaux composants à développer ultérieurement

1. `lab/dataset_v2/schemas/` : schémas JSON de registre, campagne, activité, preuve, annotation et release ;
2. `prepare_campaign.py` : réserve l'identifiant, vérifie la partition et matérialise le manifeste sans exécuter d'action ;
3. `collect_campaign.py` : enveloppe le collecteur actuel, crée l'index brut, les hashes et le manifeste ;
4. `link_activity_events.py` : produit des propositions structurées à partir des marqueurs, GUID, artefacts, règles et temps ;
5. `review_annotations.py` : applique des décisions append-only et conserve les conflits ;
6. `build_supervised_wazuh_cache.py` : joint la vérité après la compression et produit `meta-truth` et `pair-truth` séparément ;
7. `validate_dataset_release.py` : contrôle schémas, hashes, partitions, traçabilité, conflits, horloges et distributions ;
8. `freeze_dataset_release.py` : fige une release et refuse toute modification silencieuse ;
9. `compare_ml_v1_v2.py` : comparaison future sur les mêmes candidats, sans ouvrir le test pendant le développement.

Ces composants doivent être ajoutés dans un nouvel espace. Le constructeur de cache Wazuh actuel et l'interface continuent de fonctionner sans changement.

## 10. Compatibilité avec le ML actuel

La compatibilité syntaxique est confirmée. Les caches Wazuh actuels produisent l'union des 32 caractéristiques demandées par les huit modèles gelés : certains folds en utilisent 26, d'autres 28 ou 32.

La compatibilité statistique n'est pas acquise. Sur les caches actuels :

| Disponibilité sur les paires | Wazuh actuel | AIT-ADS |
|---|---:|---:|
| protocole connu aux deux extrémités | 0,00 % | 21,51 % |
| service connu aux deux extrémités | 0,00 % | 20,93 % |
| direction réseau connue | 6,01 % | 90,37 % |
| phase observable connue aux deux extrémités | 25,13 % | 4,42 % |
| tactique connue aux deux extrémités | 50,35 % | 2,67 % |
| sévérité connue aux deux extrémités | 100 % | 96,47 % |

Le validateur V2 doit donc publier, par campagne et partition : taux de valeurs connues, distributions, signatures inédites, entités, sources de candidats et couverture du mapping. Une colonne présente mais presque toujours nulle n'est pas une compatibilité suffisante.

Il faudra aussi mesurer le rappel de génération des candidats sur les relations fortes. Une relation correctement annotée mais absente de `pair-examples.parquet` ne peut être apprise ni retrouvée par le classificateur.

## 11. Contrôles qualité obligatoires

Une release est refusée si l'un de ces contrôles échoue :

1. campagne absente du registre ou partition modifiée après exécution ;
2. identifiant réutilisé entre campagnes ou partitions ;
3. fichier brut, script, mapping ou configuration dont le hash ne correspond pas au manifeste ;
4. timestamp sans fuseau, horloge non auditée ou décalage dépassant la tolérance préenregistrée ;
5. événement perdu, dupliqué ou ajouté pendant la compression ;
6. label fort sans preuve directe et cohérence technique ;
7. bénin déduit seulement par absence de label ;
8. conflit non résolu inclus dans l'apprentissage ;
9. méta-alerte forte contenant des membres de vérités différentes ;
10. identifiant de vérité présent dans les caractéristiques ML ;
11. campagne ou instance partagée entre partitions ;
12. couverture insuffisante d'une des quatre familles de paires fortes ;
13. ouverture des résultats finaux avant le gel du modèle et du protocole.

Audits publiés même si la release passe :

- nombres d'événements `verified/weak/unknown/conflict` ;
- nombres de paires par classe, raison et confiance ;
- sources et nombre de preuves ;
- taux de revue et accord inter-annotateurs sur un échantillon ;
- couverture de candidats, mapping et caractéristiques ;
- latence activité–événement ;
- distribution par campagne, hôte, règle et phase.

## 12. Comparaison future ML V1 / ML V2

### Comparaison relationnelle

- mêmes paires candidates et mêmes caractéristiques pour V1 et V2 ;
- AP, F1, MCC, précision et rappel, macro par campagne ;
- résultats séparés pour positif même attaque, attaques différentes, attaque–bénin et bénin–bénin ;
- résultats `verified` comme analyse principale ; labels faibles dans un tableau séparé ;
- rappel des transitions longues et pire campagne ;
- calibration et seuil choisis uniquement sur développement/validation.

### Comparaison graphique

Utiliser la baseline scientifique active, identique pour les deux modèles :

- B-cubed et ARI ;
- fragments par attaque et taille du fragment principal ;
- couverture/rappel des phases ;
- composantes fusionnant plusieurs attaques ;
- nombre de méta-alertes d'attaque dans les fusions ;
- faux liens attaque–bénin ;
- comportement sur attaques simultanées et transitions longues.

### Règle de décision

Un V2 ne remplace pas V1 parce qu'il améliore seulement une moyenne. Il doit :

1. améliorer ou préserver les métriques relationnelles vérifiées sur validation ;
2. ne pas augmenter matériellement les fusions ;
3. améliorer le pire cas ou réduire sa variance ;
4. conserver les relations longues vérifiées ;
5. confirmer le résultat une seule fois sur les campagnes finales scellées.

Les intervalles doivent être calculés par campagne ou instance, pas en considérant les millions de paires dépendantes comme des observations indépendantes.

## 13. Ordre de réalisation

1. Geler le vocabulaire, les schémas et les critères `verified/weak/conflict`.
2. Créer le registre et affecter définitivement les campagnes aux trois partitions.
3. Implémenter uniquement les validateurs de schéma, hashes et partitions.
4. Adapter les orchestrateurs pour produire activités, marqueurs et preuves structurées.
5. Envelopper la collecte existante avec index brut, manifeste, horloges et hashes.
6. Implémenter l'association événement–activité et la revue append-only.
7. Construire `meta-truth` et `pair-truth` séparément du cache observable.
8. Tester le pipeline avec données synthétiques locales, sans VM ni attaque.
9. Exécuter quelques campagnes de développement et corriger uniquement l'instrumentation.
10. Geler l'instrumentation, puis exécuter toutes les campagnes de développement.
11. Effectuer l'expérience de pondération/échantillonnage par validation, si la base contient assez de négatifs forts.
12. Figer modèle, mapping, seuils et stratégie graphique.
13. Exécuter les campagnes finales une seule fois et produire le rapport comparatif.

## 14. Décision immédiate

Ne pas réentraîner et ne pas exécuter de campagne maintenant. La prochaine intervention doit porter uniquement sur l'étape 1 : formaliser les schémas V2 et les règles de confiance, accompagnés de tests sur de petits événements fictifs. Cette étape est réversible et ne touche ni Wazuh, ni les modèles, ni les anciens runs.
