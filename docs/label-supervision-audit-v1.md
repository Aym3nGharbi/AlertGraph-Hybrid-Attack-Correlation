# Audit des annotations fortes/faibles d'AlertGraph V1

Date : 2026-11-09  
Statut : audit hors ligne, sans réentraînement et sans modification du pipeline Wazuh  
Résultats complets : `output/label-supervision-audit-v1/report.json`

## Résumé exécutif

La séparation par scénario et les prédictions strictement hors-fold sont correctement implémentées. La création des cibles exclut aussi les méta-alertes mixtes ou inconnues. En revanche, l'apprentissage actuel n'utilise pas le niveau de confiance des annotations : les exemples faibles reçoivent le même traitement que les exemples forts à l'intérieur de chaque cellule scénario/classe.

Le principal problème confirmé n'est pas que les labels faibles sont nécessairement faux, mais qu'ils dominent l'entraînement et l'évaluation alors que leur vérité repose surtout sur des fenêtres temporelles :

- 4 416 969 des 5 045 639 paires étiquetées sont faibles, soit 87,54 % ;
- les paires faibles représentent en moyenne 69,19 % du poids d'apprentissage ;
- elles concentrent 298 262 des 298 422 désaccords hors-fold, soit 99,95 % ;
- il n'existe que 54 négatifs forts, tous dans `harrison` ;
- lorsque `harrison` est le scénario de test, l'apprentissage ne contient donc aucun négatif fort.

La performance presque parfaite sur les paires fortes ne doit pas être interprétée comme une validation binaire suffisante : ce sous-ensemble contient 628 616 positifs mais seulement 54 négatifs. Il mesure surtout le rappel des positifs forts.

La première expérience recommandée est une ablation imbriquée de pondération par confiance, peu coûteuse et sans nouvelle caractéristique. Elle doit rester exploratoire. La correction scientifique durable consiste à collecter de nouveaux négatifs forts et des transitions interphases fortes dans des scénarios Wazuh contrôlés, en séparant dès le départ développement et test final.

## 1. Construction de la vérité terrain

### Alertes individuelles

La fonction `adapt_label()` applique les règles suivantes :

1. `event_label` reconnu : alerte d'attaque, confiance `high`, avec instance A/B et phase issue de l'événement ;
2. absence de `event_label`, mais fenêtre temporelle d'attaque reconnue : attaque `weak` ;
3. fenêtre `false_positive*` : bénin `weak` ;
4. événement ou fenêtre inconnus : vérité inconnue.

Ainsi, l'absence de `event_label` n'est pas assimilée automatiquement à « bénin certain ». Les alertes sans label événement sont exploitées seulement si la fenêtre temporelle est reconnue, et restent faibles.

Un conflit entre le label événement et la fenêtre temporelle est détecté dans `LabelDecision.label_conflict`. Cependant, cet indicateur n'est pas propagé dans les tables de méta-alertes et de paires. Il est donc impossible, avec les caches actuels, de mesurer séparément ces conflits dans les performances. C'est une limite de traçabilité confirmée, pas une preuve que les cibles correspondantes sont incorrectes.

### Méta-alertes

La compression groupe les événements avec des attributs observables et un intervalle maximal de deux secondes. Une méta-alerte est :

- `high` seulement si tous ses événements sont forts ;
- `weak` si sa vérité est cohérente mais contient au moins un événement faible ;
- `mixed` si plusieurs vérités incompatibles sont fusionnées.

Distribution des 425 777 méta-alertes :

| Confiance | Classe | Nombre |
|---|---:|---:|
| forte | attaque | 77 426 |
| faible | attaque | 7 110 |
| faible | bénigne | 341 239 |
| mixte | inconnue | 2 |

Les deux méta-alertes mixtes se trouvent dans `fox` et `santos`.

### Cibles des paires

Pour une paire candidate :

- même instance d'attaque : positive ;
- instances A et B différentes : négative ;
- attaque–bénin : négative ;
- bénin–bénin : négative ;
- au moins une méta-alerte mixte ou inconnue : cible absente et paire exclue.

Une paire est forte uniquement si ses deux extrémités sont fortes. Sur 5 045 713 candidates, 74 paires mixtes de `santos` sont exclues et 5 045 639 sont étiquetées.

| Cible et provenance | Forte | Faible | Total |
|---|---:|---:|---:|
| positive, même attaque | 628 616 | 91 687 | 720 303 |
| négative, attaques A/B différentes | 54 | 11 463 | 11 517 |
| négative, attaque–bénin | 0 | 842 033 | 842 033 |
| négative, bénin–bénin | 0 | 3 471 786 | 3 471 786 |

La faiblesse structurelle est claire : presque toute l'information négative est temporelle et faible.

## 2. Prédictions strictement hors-fold

L'audit utilise, pour chaque scénario, uniquement le modèle gelé qui n'a jamais été entraîné sur ce scénario. Les seuils propres aux huit folds sont conservés. Les métriques macro reproduites sont : AP 0,7073, F1 0,7330 et MCC 0,7275.

### Résultats selon la confiance

| Confiance | Paires | Positives | Négatives | Précision | Rappel | Spécificité | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| forte | 628 670 | 628 616 | 54 | 1,0000 | 0,9998 | 0,5556 | 0,9999 |
| faible | 4 416 969 | 91 687 | 4 325 282 | 0,0716 | 0,1884 | 0,9482 | 0,1038 |

Interprétation :

- les 160 erreurs fortes sont des erreurs confirmées relativement fiables : 136 faux négatifs et 24 faux positifs ;
- les 298 262 « erreurs » faibles sont d'abord des désaccords avec une annotation temporelle ; elles ne peuvent pas toutes être déclarées erreurs certaines du ML ;
- la F1 forte est artificiellement facile à lire favorablement parce que les négatifs forts sont presque absents.

### Résultats faibles par scénario

| Scénario | Paires faibles | F1 | MCC | Désaccords |
|---|---:|---:|---:|---:|
| fox | 184 498 | 0,368 | 0,389 | 5 018 |
| harrison | 1 099 295 | 0,038 | -0,019 | 237 908 |
| russellmitchell | 117 542 | 0,580 | 0,589 | 2 328 |
| santos | 638 503 | 0,228 | 0,250 | 5 756 |
| shaw | 269 926 | 0,009 | 0,010 | 4 221 |
| wardbeck | 444 081 | 0,310 | 0,312 | 2 616 |
| wheeler | 739 047 | 0,282 | 0,284 | 11 925 |
| wilson | 924 077 | 0,284 | 0,338 | 28 490 |

`harrison` domine les désaccords faibles. Cela explique une grande partie de l'écart entre ses résultats globaux acceptables et son comportement sur la vérité faible.

### Familles de relations

| Famille de vérité | Nombre | FP/FN | Lecture correcte |
|---|---:|---:|---|
| attaque–bénin, faible | 842 033 | 207 377 FP | difficulté majeure ; vérité temporelle incertaine |
| bénin–bénin, faible | 3 471 786 | 12 310 FP | taux de FP faible (0,355 %), mais volume très élevé |
| attaques A/B différentes | 11 517 | 4 183 FP | risque direct de fusion ; seulement 54 cas sont forts |
| même attaque | 720 303 | 74 552 FN | rappel 89,65 % ; la majorité des FN est faible |

Les principales signatures observées dans les désaccords faibles sont `W-All-Evt`, `2230003`, `2230010`, `W-Sys-Dov` et, dans les faux positifs attaque–bénin de `harrison`, les couples impliquant `2027863` et `W-All-Evt`. Ce sont des familles à examiner, mais pas des preuves automatiques d'une erreur de modèle.

Plusieurs diagnostics se recouvrent et ne constituent pas une attribution causale :

- les relations avec au moins une phase inconnue portent 220 195 FP et 74 425 FN faibles ;
- `A-All-Evt` a 2 714 FP sur 4 796 négatifs correspondants ;
- les transitions réseau dites `network_handoff` ont 34 219 FN sur 39 869 positifs ;
- les relations de 10 à 60 secondes concentrent 182 179 FP et 34 353 FN.

Ces chiffres localisent les désaccords. Ils ne permettent pas, à eux seuls, de choisir si le mapping, le modèle ou le label faible a tort.

## 3. Échantillonnage et pondération actuels

Le protocole limite chaque cellule `(scénario, classe)` à 50 000 exemples pour l'entraînement final, 20 000 dans les folds internes. Le tirage est déterministe et aléatoire à l'intérieur de la classe. Chaque cellule scénario/classe reçoit ensuite la même masse totale.

Conséquences confirmées :

1. la confiance et la raison du label ne participent ni au tirage ni au poids ;
2. les paires faibles représentent 65,95 % à 71,52 % du poids selon le fold, moyenne 69,19 % ;
3. les petites cellules obtiennent des poids individuels plus élevés ;
4. les sous-types négatifs ne sont pas équilibrés séparément ;
5. les négatifs forts sélectionnés par fold sont `[4, 0, 7, 7, 7, 7, 7, 7]` ;
6. quand `harrison` est réservé au test, aucun négatif fort n'est disponible pour apprendre la séparation A/B.

La validation interne équilibre aussi seulement les classes, sans tenir compte de la confiance. Le choix des hyperparamètres, des itérations et du seuil est donc fortement influencé par les labels faibles.

## 4. Conclusions classées par niveau de certitude

### Erreurs ou insuffisances confirmées

- aucune pondération par confiance dans l'entraînement ou la validation ;
- seulement 54 négatifs forts, tous dans un unique scénario ;
- le drapeau de conflit événement/temps n'est pas conservé dans les caches de paires ;
- la sélection aléatoire par classe ne garantit pas la conservation des sous-types rares ;
- les métriques globales mélangent vérité forte et vérité faible sans les présenter séparément dans le rapport historique principal.

### Risques méthodologiques vérifiables, mais non prouvés comme erreurs

- les fenêtres temporelles peuvent attribuer à tort des activités simultanées à l'attaque ou au bénin ;
- l'égalité de masse scénario/classe peut amplifier de petites cellules positives bruitées ;
- la quasi-absence de négatifs forts peut favoriser des fusions A/B ;
- les signatures très génériques peuvent être apprises comme raccourcis ;
- les bons scores forts peuvent surestimer la qualité binaire faute de négatifs forts.

### Composants techniquement fiables

- séparation externe et interne par scénario ;
- exclusion du scénario de test pendant l'entraînement et le réglage ;
- exclusion effective des paires mixtes/inconnues ;
- compression fondée sur les champs observables, sans identité d'attaque comme clé de groupe ;
- échantillonnage déterministe et reproductible ;
- prédictions hors-fold existantes suffisantes pour cet audit sans réentraînement.

## 5. Trois améliorations possibles

### A. Pondération explicite selon la confiance — première expérience recommandée

Comparer la baseline avec une petite grille préenregistrée, par exemple poids faible `1,0`, `0,5` et `0,25`, le poids fort restant `1,0`. Conserver la pondération scénario/classe, puis renormaliser sans donner une masse énorme aux 54 négatifs forts.

Avantages : modification simple, explicable, test direct de l'hypothèse principale.  
Limites : ne répare aucun label et ne crée aucun négatif fort.  
Risque : réduire trop fortement les faibles supprime presque toute l'information négative.

### B. Échantillonnage stratifié par confiance et raison, avec ablation forte

Conserver explicitement tous les négatifs forts, contrôler séparément attaque–bénin, bénin–bénin et A/B, puis comparer une ablation « cœur fort » à la baseline. L'ablation forte seule est un diagnostic, pas un modèle final, car elle ne contient pratiquement pas de classe négative.

Avantages : évite que les millions de bénin–bénin masquent les négatifs difficiles.  
Limites : les 54 négatifs forts viennent tous de `harrison`, donc leur généralisation reste inconnue.  
Risque : surpondérer ces 54 exemples ferait mémoriser un scénario ou une signature.

### C. Enrichissement par scénarios Wazuh contrôlés — priorité scientifique

Créer de nouvelles instances documentées contenant : attaques A/B simultanées, attaque–bénin, bénin–bénin, pauses interphases, machines bruyantes et transitions longues légitimes. Attribuer des identifiants de run, activité et instance avant l'exécution.

Avantages : apporte enfin des négatifs forts indépendants et des transitions fortes réalistes.  
Limites : coût de collecte et nécessité d'une annotation manuelle rigoureuse.  
Risque : suradapter les scénarios au système si les mêmes runs servent au développement et au test final.

## 6. Protocole expérimental proposé

1. Préenregistrer les trois variantes de poids et les strates avant d'observer de nouveaux résultats.
2. Conserver le LOSO externe par scénario. Pour chaque test externe, sélectionner poids, hyperparamètres et seuil uniquement dans les folds internes des six scénarios d'entraînement/validation.
3. Utiliser exactement les mêmes paires candidates, caractéristiques et graines pour les variantes comparées.
4. Rapporter séparément : rappel positif fort, spécificité négative forte, métriques faibles par raison, métriques globales, pire scénario et dispersion entre scénarios.
5. Ne jamais utiliser la confiance comme caractéristique d'entrée du modèle ; elle sert seulement à l'apprentissage et à l'analyse.
6. Évaluer ensuite les graphes avec la baseline scientifique figée : fusions A/B, fragmentation, B-cubed, ARI et couverture des phases.
7. Considérer AIT comme développement, puisque ses résultats ont déjà guidé les hypothèses.
8. Ne pas utiliser SOCBED, DARPA ni les anciens runs Wazuh pour sélectionner les paramètres.
9. Pour les futures données Wazuh, réserver à l'avance des attaques, hôtes et périodes au test final. Figer modèle, poids, seuils et mappings avant de les ouvrir.
10. Employer des intervalles par scénario ou bootstrap groupé par instance, jamais un bootstrap naïf sur les millions de paires dépendantes.

## 7. Décision recommandée

Ne pas réentraîner immédiatement un modèle destiné à la production. Réaliser d'abord l'expérience A, limitée et imbriquée, comme diagnostic. Si la réduction du poids faible n'améliore pas simultanément le pire scénario, les négatifs A/B et la reconstruction graphique, conserver la baseline.

En parallèle, préparer l'enrichissement C. Sans nouveaux négatifs forts, il restera impossible de conclure proprement si les faux positifs A/B proviennent surtout du ML ou de la faiblesse de la vérité terrain temporelle.

## Reproductibilité

Commande de l'audit actuel :

```powershell
python .\ml\audit_label_supervision.py `
  --cache-root .\data\processed\ait_pairs_v3 `
  --ensemble .\output\final-ensemble.joblib `
  --output-dir .\output\label-supervision-audit-v1
```

Le script refuse d'écrire dans un dossier déjà existant. Les empreintes SHA-256 des entrées sont inscrites dans le JSON.
