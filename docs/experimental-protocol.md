# Protocole expérimental de corrélation d'alertes

## 1. Cible du projet

Le système ne cherche pas seulement à classer une alerte comme malveillante ou
bénigne. Il estime une relation entre deux alertes :

```text
y(A, B) = 1  si A et B appartiennent à la même instance d'attaque
y(A, B) = 0  sinon
```

Les relations positives servent ensuite à regrouper les alertes. Chaque groupe
doit représenter une attaque distincte et permettre de construire un graphe de
sa progression.

La similarité et la compatibilité causale sont deux signaux d'entrée. La sortie
principale reste un score de corrélation.

## 2. Séparation entre observations et vérité terrain

### Champs observables, utilisables par un modèle

- identifiant et horodatage de l'alerte ;
- IDS, capteur et hôte d'origine ;
- IP, ports, protocole, service et utilisateur ;
- identifiant et texte de la signature IDS ;
- description et sévérité ;
- tactique ou technique MITRE fournie par la règle de détection ;
- écarts temporels et continuités d'entités calculés entre deux alertes.

### Champs de vérité terrain, interdits comme caractéristiques

- `scenario_id` ;
- `attack_instance_id` ;
- `ground_truth_phase` ;
- `is_attack` ;
- `label_source` et `label_confidence`.

Une phase annotée après l'exécution du scénario ne doit jamais être fournie au
score causal. Une tactique produite par une règle IDS au moment de la détection
peut être utilisée, car elle serait disponible en production.

## 3. Schéma canonique proposé

```text
alert_id
timestamp
sensor
host
src_ip
src_port
dst_ip
dst_port
protocol
service
signature_id
signature_text
severity
observed_tactic
scenario_id              # vérité terrain
attack_instance_id       # vérité terrain
ground_truth_phase       # vérité terrain
is_attack                # vérité terrain
label_source             # event, time, manual ou unknown
label_confidence         # high, weak ou unknown
```

Les champs de vérité terrain sont conservés dans une table séparée avant la
construction des caractéristiques.

## 4. Construction des paires

Les paires ne sont pas obtenues par produit cartésien. Un générateur de
candidats utilise une fenêtre temporelle et des index par IP, hôte, utilisateur,
service et signature.

L'analyse empirique d'AIT-ADS montre que 2 331 662 répétitions d'une même
signature sur un même hôte surviennent à deux secondes ou moins de la
précédente. Elles sont représentées par des méta-alertes réversibles qui
conservent les identifiants des alertes membres, le nombre d'occurrences et les
bornes temporelles ; les alertes brutes ne sont pas supprimées.

L'archive officielle concatène le flux Wazuh/Suricata puis le flux AMiner alors
que leurs plages temporelles se chevauchent. Les deux flux doivent donc être
fusionnés par timestamp avant toute génération de candidats. Après correction
de cet ordre et avec l'analyse compacte fondée sur l'hôte principal, une fenêtre
locale de 60 secondes contient en moyenne 5,899 candidats antérieurs et couvre
99,088 % des prédécesseurs de la même instance observés. Une fenêtre de 150
secondes monte à 14,205 candidats et 99,591 % de couverture. Ces moyennes
globales masquent toutefois une couverture à 60 secondes de seulement 79,661 à
81,765 % dans trois petits scénarios. Les paramètres 60 et 150 secondes doivent
donc être comparés sur la validation et rapportés par scénario, jamais optimisés
sur le test final.

Une voie causale séparée doit conserver le dernier événement observable de
chaque type compatible pour relier des étapes lentes au-delà de la fenêtre
locale, sans élargir toutes les comparaisons à 45 minutes.

Cette voie ne suppose pas que les tactiques MITRE ATT&CK forment une chaîne
linéaire : MITRE précise qu'elles sont non ordonnées. Elle utilise une table
explicite et auditable de compatibilités entre micro-étapes observables, issue du
mapping AIT/SAGE. Le terme « causal » désigne ici une compatibilité de
progression et non la preuve qu'une alerte a causé l'autre. L'index conserve au
plus le dernier événement de chaque type par entité et propose au maximum cinq
ponts par nouvelle méta-alerte.

Le mapping officiel AIT/SAGE ne couvre que 12 398 des 324 159 unités compactes
obtenues par l'audit léger fondé sur un hôte et une signature, soit 3,825 %.
Cette valeur n'est pas le nombre final de méta-alertes multi-entités. Parmi les unités liées
à une attaque selon la vérité terrain, 4 836 reçoivent une étape malveillante
observable et 77 362 restent sans étape. La causalité est donc un signal rare :
une étape non mappée doit produire une valeur « inconnue » et ne doit jamais être
interprétée comme une incompatibilité ou comme un exemple négatif.

Pour AIT-ADS, une convention provisoire est :

- attaque `A` : `network_scans`, `service_scans`, `wpscan`, `dirb`,
  `webshell`, `cracking`, `reverse_shell`, `privilege_escalation` ;
- attaque `B` : `service_stop`, `dnsteal` ;
- une instance est identifiée par `scenario:A` ou `scenario:B` ;
- deux exécutions situées dans des scénarios différents sont des instances
  différentes, même si elles suivent le même plan d'attaque.

Les exemples ambigus ou seulement faiblement labellisés ne doivent pas être
présentés comme une vérité certaine. Ils restent disponibles pour une analyse
semi-supervisée ou un test de robustesse.

## 5. Partitions et prévention des fuites

- le protocole principal est une validation imbriquée leave-one-scenario-out ;
- chaque boucle externe garde un des huit scénarios entièrement hors du
  développement, puis les sept scénarios restants servent tour à tour de
  validation interne ;
- une alerte ne peut apparaître dans plusieurs partitions par l'intermédiaire
  de paires différentes ;
- normalisation, vocabulaire, sélection de variables et équilibrage sont appris
  uniquement sur les six scénarios d'entraînement du fold interne ;
- les seuils et hyperparamètres sont choisis sur les validations internes ;
- le scénario de test externe n'est utilisé qu'après sélection de la
  configuration du fold ;
- les résultats sont publiés par scénario, puis agrégés avec moyenne et
  dispersion, afin que les gros scénarios ne masquent pas les petits.

Ce choix suit le principe des séparations à groupes non chevauchants : les
alertes d'un même scénario sont dépendantes et ne doivent pas être distribuées
aléatoirement entre train et test. Le manifeste déterministe est construit et
validé par `ml/split_protocol.py`.

## 6. Déséquilibre

Les données brutes restent immuables. L'équilibrage porte sur les paires
d'entraînement, avec des quotas ou poids par :

- classe de corrélation ;
- scénario et instance d'attaque ;
- phase et transition ;
- signature et IDS ;
- négatif facile ou négatif difficile.

Le test principal conserve une distribution réaliste. Un second test équilibré
par scénario et phase sert à vérifier que les classes majoritaires ne masquent
pas les échecs sur les étapes rares.

## 7. Modèles comparés

1. similarité seule ;
2. compatibilité causale seule ;
3. hybride manuel ;
4. hybride appris par Machine Learning.

Tous utilisent les mêmes paires candidates, partitions et métriques.

## 8. Évaluation

- relations : précision, rappel, F1, PR-AUC, MCC et faux positifs ;
- groupes : B-cubed précision/rappel/F1, ARI, fragmentation et fusion ;
- graphes : couverture des étapes, ordre retrouvé et arêtes incorrectes ;
- robustesse : résultats par scénario, phase, signature et IDS ;
- technique : temps, mémoire et nombre moyen de candidats par alerte.

L'Average Precision issue de la courbe précision-rappel est prioritaire pour le
classement des relations, car la proportion positive varie fortement entre
scénarios. Les seuils sont choisis sur les validations internes avec la F1 macro
par scénario. L'exactitude brute n'est jamais utilisée comme métrique principale.

## 9. Audit préliminaire d'AIT-ADS

Source : AIT-ADS version 1, Zenodo 8263181, et archive `alerts_csv.zip` du
dépôt officiel `ait-aecid/alert-data-set`.

Résultats vérifiés le 30 octobre 2026 :

- 2 655 821 alertes ;
- 1 817 250 alertes avec un `event_label` non vide, soit 68,425 % ;
- 838 571 alertes sans label événementiel ;
- 1 688 945 labels événementiels `dirb`, soit environ 93 % des labels
  événementiels disponibles ;
- 891 240 alertes marquées `false_positive` par le label temporel ;
- 73 526 différences textuelles entre `time_label` et `event_label` lorsque le
  second existe. Ce nombre inclut des alias différents et des divergences de
  fenêtre ; il ne constitue pas à lui seul un nombre d'erreurs de label.

Après normalisation des alias, 72 947 conflits de phase subsistent. Ils sont
presque entièrement expliqués par des événements `dnsteal` détectés hors de la
fenêtre temporelle correspondante : 46 482 dans `harrison` et 25 709 dans
`santos` sont temporellement marqués `false_positive`. Dans ces cas, le label
événementiel, lié au log ou au flux déclencheur, reste prioritaire.

La couche canonique obtient :

- 1 755 226 alertes rattachées à l'attaque multiétape A ;
- 81 567 rattachées à l'attaque d'exfiltration B ;
- 819 028 négatifs temporels faibles ;
- 1 817 250 décisions événementielles fortes et 838 571 décisions temporelles
  faibles.

La valeur `-` dans `event_label` signifie « non labellisé au niveau événement »
et ne doit pas être automatiquement transformée en « bénin ».

### Décision provisoire

AIT-ADS est adapté à une étude de corrélation et de graphes, mais ses labels
événementiels fiables sont extrêmement déséquilibrés et incomplets pour les
étapes rares. Il reste candidat principal sous réserve d'un protocole à niveaux
de confiance, d'un équilibrage des paires et d'une validation externe.

La vérité terrain d'une paire est positive uniquement si les deux alertes ont le
même `attack_instance_id`. Une paire issue de deux instances, scénarios ou
familles A/B différents est négative. Toute paire contenant un label inconnu est
exclue du supervisé ; une paire reposant sur au moins un label temporel reste
disponible mais avec une confiance faible.

### Audit des paires candidates avec les JSON bruts

Après fusion chronologique des capteurs, compression observable à deux secondes,
fenêtre locale de 60 secondes et plafond de 50 candidats par méta-alerte :

- les 2 655 821 alertes originales sont conservées dans 425 777 méta-alertes
  réversibles ;
- 2 méta-alertes seulement mélangent des vérités terrain différentes et sont
  exclues du supervisé ;
- 5 043 910 paires candidates sont générées ;
- 720 016 sont positives et 4 323 820 négatives, soit 14,275 % de positives ;
- les négatifs comprennent 3 470 569 paires bénin–bénin, 841 735 paires
  attaque–bénin et seulement 11 516 paires entre attaques différentes ;
- 628 410 paires ont deux labels événementiels forts, contre 4 415 426 paires
  contenant au moins un label temporel faible ;
- la proportion positive varie de 0,625 % dans `wardbeck` à 28,243 % dans
  `harrison`.

Le train ne doit donc pas reprendre cette distribution telle quelle. Il doit
appliquer des quotas ou poids à l'intérieur de chaque scénario, par classe,
niveau de confiance et type de négatif. Le test principal conserve sa
distribution réaliste. Le rapport reproductible local est
`output/ait-pair-audit-60s.json`.

### Cache de caractéristiques vérifié

Le cache Parquet `data/processed/ait_pairs_v1` sépare physiquement observations
et vérité terrain par scénario. Sa validation obtient :

- 2 655 821 identifiants d'alertes membres ;
- 425 777 méta-alertes observables et 425 777 lignes de vérité terrain ;
- 5 045 713 paires, dont 720 303 positives, 4 325 336 négatives et 74 ambiguës ;
- un schéma identique pour les huit scénarios ;
- aucune caractéristique manquante et aucune colonne de vérité terrain dans les
  tables observables ;
- 30,9 MB au total avec compression Zstandard.

### Premiers résultats sans ML

La sélection des seuils et du coefficient hybride est effectuée uniquement sur
les scénarios internes du protocole imbriqué. Moyennes macro des huit scénarios :

| Méthode | Average Precision | F1 | MCC |
|---|---:|---:|---:|
| Similarité seule | 0,128 | 0,171 | -0,071 |
| Causalité seule | 0,379 | 0,448 | 0,481 |
| Hybride manuel | 0,426 | 0,448 | 0,481 |

L'hybride manuel améliore le classement mais, avec la grille actuelle, son seuil
produit souvent les mêmes décisions binaires que la causalité seule. Les écarts
types élevés confirment une forte variation entre scénarios.

Un pilote technique du modèle hybride appris entraîne sur six scénarios,
sélectionne son seuil sur `wardbeck` et teste une seule fois sur
`russellmitchell`. Il obtient AP 0,394, F1 0,495 et MCC 0,504, contre AP 0,225 et
F1 0,400 pour la causalité seule sur ce scénario. Ce résultat valide le pipeline
mais ne constitue pas encore l'estimation finale imbriquée à huit folds.

### Évaluation ML groupée à huit folds

La configuration fixe de `HistGradientBoostingClassifier` utilise sept
validations internes pour sélectionner le seuil et le nombre d'itérations de
chaque fold externe. Elle obtient :

| Méthode | Average Precision | ROC-AUC | F1 | MCC | Balanced accuracy |
|---|---:|---:|---:|---:|---:|
| Hybride ML, configuration fixe | 0,647 | 0,816 | 0,500 | 0,476 | 0,731 |
| Ensemble ML calibré | 0,671 | 0,826 | 0,483 | 0,461 | 0,737 |

La calibration sigmoïde est ajustée uniquement sur des scénarios internes que
le modèle correspondant n'a pas utilisés pour apprendre. Elle améliore AP et
ROC-AUC mais pas la F1 macro. L'écart-type de F1 reste proche de 0,307 dans les
deux cas : la variation entre scénarios n'est donc pas résolue par une simple
calibration globale.

Le fold `santos` illustre ce problème : AP atteint 0,932 pour le modèle non
calibré, alors que la F1 au seuil transféré n'est que 0,037. Le classement est
bon, mais l'échelle de décision change fortement. À l'inverse, `shaw` reste
difficile même en classement (AP 0,168). Les diagnostics utilisant le meilleur
seuil du test sont explicitement considérés comme post-hoc et ne sont jamais
rapportés comme résultats ni réutilisés pour régler le modèle.

Ces résultats sont des estimations groupées valides pour la configuration
fixée, mais pas encore une optimisation complète des hyperparamètres structurels
(`learning_rate`, profondeur/nombre de feuilles et régularisation). Toute grille
ultérieure doit rester dans les folds internes.

## 10. Plan d'optimisation verrouillé

L'optimisation suivra cet ordre afin de limiter le surapprentissage :

1. comparer les fenêtres candidates de 60 et 150 secondes dans les validations
   internes, tout en conservant les ponts causaux pour les relations longues ;
2. ajouter des caractéristiques observables multi-échelles : volumes à 2, 10,
   60 et 150 secondes, temps depuis la signature précédente, direction réseau,
   rareté apprise sur le train et contexte local du graphe ;
3. conduire une ablation `similarité seule / causalité seule / hybride`, puis
   retirer séparément tactiques MITRE et texte de signature pour mesurer leur
   contribution et leur risque de surapprentissage ;
4. tester une petite grille d'hyperparamètres de gradient boosting ;
5. régler le seuil et, éventuellement, la calibration uniquement dans les
   validations internes ;
6. évaluer enfin les groupes et graphes avec B-cubed, ARI, fragmentation,
   fusion d'attaques, couverture des phases et arêtes incorrectes ;
7. confirmer la généralisation sur un autre dataset public compatible.

La grille autorisée est volontairement bornée :

- `learning_rate` dans `{0.03, 0.05, 0.08}` ;
- `max_leaf_nodes` dans `{7, 15, 31}` ;
- `min_samples_leaf` dans `{50, 200}` ;
- `l2_regularization` dans `{1, 5, 10}` ;
- `max_features` dans `{0.7, 1.0}`.

Il ne faut pas évaluer le produit cartésien complet. Dix à quinze configurations
représentatives seront comparées par validation groupée imbriquée. La sélection
considérera, dans cet ordre, l'Average Precision macro, la F1 macro, la
performance du pire scénario et l'écart-type entre scénarios. Aucun choix de
fenêtre, caractéristique, hyperparamètre, calibration ou seuil ne peut utiliser
les labels d'un fold externe.

Une amélioration de moyenne qui dégrade fortement le pire scénario ne sera pas
considérée comme une optimisation robuste. Les diagnostics post-hoc sur un test
servent uniquement à comprendre les erreurs et ne peuvent jamais être recyclés
dans la sélection du modèle.

### Comparaison verrouillée des fenêtres 60 et 150 secondes

Les deux caches ont été construits avec les mêmes 2 655 821 alertes, 425 777
méta-alertes, compression à deux secondes, plafond de 50 candidats et cinq
ponts causaux au maximum. Seule la fenêtre locale change.

| Mesure | 60 s | 150 s |
|---|---:|---:|
| Paires candidates | 5 045 713 | 9 202 237 |
| Paires positives | 720 303 | 1 432 641 |
| Paires négatives | 4 325 336 | 7 769 496 |
| Méta-alertes avec un prédécesseur positif candidat | 83 795 | 84 126 |
| Taille du cache | 30,9 MB | 41,3 MB |

Les 712 338 positives supplémentaires à 150 secondes sont principalement des
relations redondantes entre des méta-alertes déjà connectables : seules 331
méta-alertes supplémentaires obtiennent une première liaison positive.

Évaluation groupée à configuration ML identique :

| Mesure macro | 60 s | 150 s |
|---|---:|---:|
| Average Precision | **0,647** | 0,597 |
| ROC-AUC | **0,816** | 0,807 |
| F1 | **0,500** | 0,398 |
| MCC | **0,476** | 0,405 |
| Balanced accuracy | **0,731** | 0,701 |

La fenêtre locale retenue est donc **60 secondes**. Les relations plus longues
restent prises en charge par l'index des derniers événements causalement
compatibles. Le cache 150 secondes et ses rapports sont conservés comme preuve
expérimentale, mais ne sont pas utilisés pour choisir les étapes suivantes.

### Caractéristiques observables version 2

Sans modifier les candidats ni les labels, la version 2 ajoute :

- continuité directionnelle source–source et destination–destination ;
- passage de la destination d'une alerte vers la source de la suivante ;
- passage inverse source vers destination ;
- densités antérieures maximales par entité sur 2, 10, 60 et 150 secondes pour
  chacune des deux méta-alertes ;
- temps écoulé depuis la même signature sur une entité partagée.

La direction réseau est disponible pour 90,370 % des paires et un passage
destination–source pour 22,468 %. Les caractéristiques de contexte 150 secondes
et de signature précédente sont disponibles respectivement pour 99,987 % et
99,861 % des paires. Les 5 045 713 identifiants, sources candidates et labels de
v2 sont strictement identiques à v1.

Évaluation groupée avec la même configuration ML :

| Mesure macro | v1 | v2 |
|---|---:|---:|
| Average Precision | 0,647 | **0,710** |
| ROC-AUC | 0,816 | **0,849** |
| F1 | 0,500 | **0,698** |
| MCC | 0,476 | **0,696** |
| Balanced accuracy | 0,731 | **0,812** |
| Écart-type F1 | 0,307 | **0,249** |

La version 2 améliore donc à la fois la moyenne et la stabilité entre scénarios.
`shaw` reste le fold le plus faible, avec F1 0,254 et AP 0,177. L'ablation
suivante sépare la contribution de la direction réseau et du contexte temporel.

### Ablation des nouvelles caractéristiques

L'ablation utilise les mêmes folds, échantillons, hyperparamètres et procédures
de sélection de seuil que l'évaluation v2 complète.

| Profil | AP macro | F1 macro | MCC macro | Écart-type F1 |
|---|---:|---:|---:|---:|
| Legacy, sans les 15 nouvelles variables | 0,647 | 0,500 | 0,476 | 0,307 |
| Contexte sans direction | 0,652 | 0,494 | 0,501 | 0,278 |
| Direction et contexte | 0,710 | 0,698 | 0,696 | 0,249 |
| **Direction sans contexte** | **0,714** | **0,730** | **0,722** | **0,243** |

La direction réseau explique l'essentiel du gain. Les densités multi-échelles
seules ne dépassent pas la référence legacy et réduisent les performances
lorsqu'elles sont ajoutées à la direction. Elles sont conservées dans le cache
pour la traçabilité, mais exclues du profil de modèle actuellement retenu.

Le profil **`directional`** devient donc le profil par défaut pour la prochaine
recherche d'hyperparamètres. Il conserve les cinq variables directionnelles et
retire les dix variables de densité/gap. Les profils `all`, `context`,
`directional`, `directional_graph` et `legacy` sont définis explicitement dans
`ml/feature_sets.py`.

### Première recherche imbriquée de profils et d'hyperparamètres

Une première recherche bornée a comparé cinq configurations dans chaque boucle
interne : quatre variantes du profil `directional` et une variante du profil
`all`. Le profil, le seuil et le nombre d'itérations sont choisis sans consulter
le scénario externe. Cette recherche est une étape intermédiaire et ne remplace
pas encore les dix à quinze configurations représentatives prévues par le plan
verrouillé.

| Mesure externe macro | Moyenne | Écart-type | Pire scénario |
|---|---:|---:|---:|
| Average Precision | 0,694 | 0,279 | 0,171 |
| ROC-AUC | 0,849 | 0,159 | 0,480 |
| F1 | 0,715 | 0,251 | 0,259 |
| MCC | 0,706 | 0,235 | 0,306 |
| Balanced accuracy | 0,829 | 0,138 | 0,582 |

Les huit folds externes sont complets malgré l'interruption interactive survenue
à la fin de l'exécution. `shaw` reste le scénario limitant. Le rapport intégral
et les choix internes par fold sont conservés dans
`output/nested-optimized-ml.json`.

La prochaine expérience verrouillée est l'ablation scientifique des composantes
`similarité seule / causalité seule / hybride`, suivie du retrait séparé des
tactiques MITRE et du texte de signature. Elle utilise le profil directionnel,
les mêmes candidats, folds, quotas, poids et hyperparamètres fixes afin que la
seule variable expérimentale soit le groupe de caractéristiques disponible.

### Ablation scientifique des composantes hybrides

L'ablation verrouillée a été exécutée sur les mêmes 5 045 713 paires, les mêmes
folds groupés et la même configuration fixe. Le profil de référence exclut les
densités multi-échelles précédemment rejetées. La similarité regroupe le temps,
les entités, signatures, protocoles, services, sévérités et continuités réseau ;
la causalité regroupe les ponts, étapes observables, compatibilités de
progression et tactiques MITRE.

| Profil | AP macro | F1 macro | MCC macro | Écart-type F1 |
|---|---:|---:|---:|---:|
| Similarité seule | 0,677 | 0,721 | 0,715 | 0,271 |
| Causalité seule | 0,467 | 0,512 | 0,537 | 0,337 |
| Hybride complet | 0,714 | 0,730 | 0,722 | 0,243 |
| Hybride sans tactiques MITRE | **0,715** | **0,732** | **0,724** | 0,243 |
| Hybride sans texte/identité de signature | 0,710 | 0,725 | 0,716 | 0,250 |

L'hybride améliore le classement par rapport à la similarité seule et réduit la
variation entre scénarios. La causalité seule ne généralise pas suffisamment,
mais sa combinaison avec la similarité apporte donc un signal complémentaire.
Le retrait des tactiques MITRE produit une variation négligeable et légèrement
positive ; le retrait du texte et de l'identité de signature dégrade surtout
`russellmitchell`, `shaw` et `wardbeck`.

Ces résultats externes servent à comprendre les contributions, pas à choisir
post-hoc la variante qui sera ensuite présentée comme une nouvelle estimation
indépendante sur les mêmes folds. La prochaine recherche imbriquée pourra
comparer `hybride` et `hybride sans MITRE`, mais devra sélectionner ce choix
uniquement dans chaque boucle interne. Le rapport reproductible est
`output/scientific-feature-ablation.json`.

### Contexte local du graphe candidat

La littérature sur la corrélation recommande de représenter les alertes comme
des nœuds reliés par leurs indicateurs observables, tout en séparant ensuite les
communautés afin qu'une faible similarité ne fusionne pas deux attaques. Une
construction en flux peut relier chaque nouvelle alerte aux derniers nœuds
partageant un indicateur, ce qui évite d'utiliser des alertes futures. Ces
principes sont notamment décrits dans la thèse *Security Monitoring and Alert
Correlation for Network Intrusion Detection* et dans *A Graph-Based Approach to
Alert Contextualisation in Security Operations Centres*.

Le cache v3 ajoute donc uniquement quatre mesures calculées sur le DAG des
candidats observables : degré candidat antérieur de chaque extrémité, nombre de
prédécesseurs communs et Jaccard de ces prédécesseurs. Aucun label, score ML ou
successeur futur n'est utilisé. Le cache conserve exactement les 2 655 821
identifiants d'alertes membres, 425 777 méta-alertes et 5 045 713 paires de v2 ;
les identifiants de paires et cibles ont été comparés ligne par ligne, et les
tables de méta-alertes sont identiques bit à bit. Un voisin antérieur commun est
présent pour 91,524 % des paires.

| Profil fixe | AP macro | F1 macro | MCC macro | Écart-type F1 |
|---|---:|---:|---:|---:|
| Hybride directionnel | 0,714 | 0,730 | 0,722 | 0,243 |
| Hybride directionnel + graphe | **0,716** | **0,735** | **0,734** | 0,246 |

Le contexte graphique apporte un gain modeste. Il améliore surtout l'AP de
`wardbeck` de 0,438 à 0,471 et légèrement `shaw` de 0,171 à 0,177, mais il
dégrade certains autres folds. Il reste donc une configuration candidate à
sélectionner dans les validations internes, et non un choix post-hoc définitif.
Le cache est `data/processed/ait_pairs_v3` et le rapport est
`output/nested-graph-context-ml.json`.

La rareté des signatures ne doit pas être précalculée globalement dans ce
cache : sa fréquence sera apprise uniquement sur les scénarios d'entraînement
de chaque fold, puis appliquée à la validation ou au test. Une signature jamais
vue pendant l'entraînement recevra la rareté maximale. Cette séparation évite
de transmettre au modèle la distribution du scénario externe.

### Rareté de signature apprise sur le train

La rareté utilise une IDF lissée
`log((N_train + 1) / (fréquence_train + 1)) + 1`. Les fréquences sont comptées
sur les alertes originales membres, et non sur les seules méta-alertes, afin que
la compression réversible ne rende pas artificiellement rare une signature très
répétée. À chaque fold interne ou externe, `N_train` et les fréquences sont
recalculés exclusivement sur les scénarios d'entraînement. Une signature absente
du train reçoit la rareté maximale ; aucune distribution de validation ou de
test n'est utilisée.

| Profil fixe | AP macro | F1 macro | MCC macro | Pire AP |
|---|---:|---:|---:|---:|
| Hybride directionnel | 0,714 | 0,730 | 0,722 | 0,171 |
| Hybride + graphe | 0,716 | 0,735 | 0,734 | **0,177** |
| Hybride + rareté train-only | 0,727 | **0,760** | **0,761** | 0,173 |
| Hybride + rareté + graphe | **0,730** | 0,744 | 0,748 | 0,176 |

La rareté seule apporte le meilleur compromis diagnostique selon la règle
verrouillée : son AP se trouve à moins de 0,01 du meilleur profil, puis son F1
est supérieur et le modèle est plus simple que la combinaison avec le graphe.
Le graphe améliore toutefois le classement moyen et le pire AP, surtout dans
`wardbeck`, mais rend le transfert du seuil plus variable, notamment dans
`santos`. `shaw` reste le pire scénario pour les quatre profils.

Cette comparaison externe reste une ablation, pas une sélection finale. Les
profils avec rareté et avec graphe devront être comparés dans les validations
internes de la recherche imbriquée à dix–quinze configurations. Les rapports
reproductibles sont `output/nested-rarity-directional-ml.json` et
`output/nested-rarity-graph-ml.json`.

### Recherche finale imbriquée à treize configurations

La recherche finale bornée compare treize configurations représentatives de la
grille autorisée. Elle inclut les profils directionnel, sans MITRE, avec graphe,
avec rareté train-only et avec rareté + graphe. Dans chaque fold externe, les
sept validations internes choisissent la configuration, le seuil et le nombre
d'itérations avant toute consultation du scénario externe.

| Mesure externe macro | Première recherche stricte | Recherche finale stricte |
|---|---:|---:|
| Average Precision | 0,694 | **0,707** |
| F1 | 0,715 | **0,733** |
| MCC | 0,706 | **0,727** |
| Balanced accuracy | 0,829 | **0,839** |
| Écart-type F1 | 0,251 | **0,237** |
| Pire AP | 0,171 | **0,173** |
| Pire F1 | 0,259 | **0,268** |

| Scénario externe | Configuration choisie en interne | AP | F1 |
|---|---|---:|---:|
| `fox` | rareté régularisée | 0,957 | 0,955 |
| `harrison` | directionnel flexible | 0,801 | 0,768 |
| `russellmitchell` | rareté + graphe | 0,637 | 0,678 |
| `santos` | sans MITRE courant | 0,966 | 0,968 |
| `shaw` | rareté régularisée | 0,173 | 0,268 |
| `wardbeck` | rareté courante | 0,481 | 0,535 |
| `wheeler` | rareté + graphe | 0,901 | 0,892 |
| `wilson` | rareté + graphe | 0,742 | 0,801 |

Une variante avec rareté est choisie dans six folds sur huit ; trois d'entre eux
ajoutent le graphe. Le modèle ne force donc pas une architecture unique lorsque
les validations internes ne la soutiennent pas. La recherche améliore à la fois
la moyenne, la dispersion et le pire fold par rapport à la première optimisation
stricte. `shaw` demeure néanmoins un échec de généralisation important.

Ces valeurs, et non les meilleures ablations fixes choisies après observation,
constituent l'estimation principale de la performance relationnelle sur AIT-ADS.
Le rapport complet est `output/final-nested-optimization.json`. L'étape suivante
du protocole est l'évaluation des groupes et graphes à partir de prédictions
hors-fold, avec B-cubed, ARI, fragmentation, fusion, couverture des phases et
arêtes incorrectes.

### Première reconstruction hors-fold des graphes d'attaque

Les modèles sélectionnés dans chaque fold ont été réentraînés sur leurs sept
scénarios de développement, puis leurs probabilités ont été reproduites
exactement sur le scénario externe. Les arêtes dépassant le seuil choisi en
validation interne sont conservées avec leur direction chronologique. Tous les
nœuds, membres bruts, scores et affectations sont enregistrés en Parquet dans
`output/attack-graphs-final`.

Deux regroupements sans réglage sur les tests sont comparés : composantes
connexes et communautés Leiden par modularité pondérée. Les métriques sont
calculées d'une part avec un poids par méta-alerte, afin que les phases rares ne
disparaissent pas, et d'autre part avec le nombre de membres bruts, afin de
représenter les 2 655 821 alertes originales.

| Regroupement | B-cubed attaques, méta | ARI attaques, méta | B-cubed attaques, brut | ARI attaques, brut |
|---|---:|---:|---:|---:|
| Composantes connexes | **0,487** | **0,222** | **0,913** | **0,516** |
| Leiden pondéré | 0,100 | 0,024 | 0,837 | 0,269 |

Leiden fragmente excessivement les grandes attaques et est rejeté dans cette
configuration. Les composantes connexes restent la baseline de regroupement,
mais ne constituent pas encore une reconstruction satisfaisante : le nombre
moyen de fragments par attaque varie fortement et peut dépasser plusieurs
centaines. Le score brut élevé est dominé par les volumes `dirb` et `dnsteal` ;
la vue méta non pondérée expose les échecs sur les étapes rares.

Dans le fragment dominant de chaque attaque, la couverture macro des types de
phases atteint 0,890, alors que le rappel macro des alertes au sein de chaque
phase n'est que de 0,398. Le système retrouve donc généralement les différentes
sortes d'étapes, mais disperse une grande partie de leurs alertes. `harrison` et
`santos` présentent aussi une fusion d'instances dans au moins une composante.

Cette expérience confirme qu'un bon score relationnel ne garantit pas un bon
graphe. L'étape suivante est un réglage **graphique** dans les validations
internes : le seuil d'arête doit optimiser B-cubed non pondéré et la couverture
des phases tout en pénalisant fortement les fusions. Aucun seuil ne sera choisi
sur les huit graphes externes déjà observés. Le rapport complet est
`output/attack-graphs-final/report.json`.

### Ablation finale : accélération et historique causal

Le cache v4 conserve exactement les 5 045 713 paires, leurs cibles, les
425 777 méta-alertes et tous les identifiants membres de v3. Il ajoute six
différences de taux logarithmiques entre 2/10, 10/60 et 60/150 secondes, ainsi
que six variables décrivant l'historique d'étapes observables antérieures
compatibles sur la même entité. Les accélérations sont disponibles sur plus de
82 % des paires ; un historique compatible non vide n'existe que pour environ
1 %, conformément à la faible couverture du mapping causal.

L'ablation utilise la rareté train-only, les mêmes folds, poids, échantillons et
hyperparamètres fixes que sa référence.

| Profil | AP macro | F1 macro | MCC macro | Écart-type F1 | Pire AP | Pire F1 |
|---|---:|---:|---:|---:|---:|---:|
| Référence rareté | 0,727 | 0,760 | 0,761 | 0,249 | **0,173** | **0,265** |
| + accélération | 0,717 | 0,746 | 0,749 | 0,258 | 0,174 | 0,266 |
| + historique compatible | **0,732** | **0,761** | **0,765** | **0,244** | 0,167 | 0,254 |

L'accélération dégrade la moyenne, la stabilité, `russellmitchell` et
`wardbeck` ; elle est rejetée. L'historique améliore légèrement les moyennes et
aide `russellmitchell` et `wardbeck`, mais dégrade le pire scénario `shaw`. Le
gain moyen est trop faible pour compenser cette perte de robustesse ; il est
également rejeté selon la règle verrouillée qui interdit de sacrifier fortement
le pire fold pour une petite amélioration moyenne.

La combinaison accélération + historique n'est pas testée après ces rejets :
multiplier les essais en réaction aux résultats externes augmenterait le risque
de surapprentissage. Aucune nouvelle recherche d'hyperparamètres n'est lancée.
Les rapports sont `output/nested-rarity-acceleration-ml.json` et
`output/nested-rarity-history-ml.json`. Les caractéristiques relationnelles sont
désormais figées ; l'étape suivante est le réglage du seuil graphique uniquement
dans les validations internes.

### Réglage imbriqué du seuil graphique

Après gel des caractéristiques, dix seuils de 0,30 à 0,95 ont été comparés dans
les sept graphes de validation internes de chaque fold externe. La règle
minimise d'abord le nombre de scénarios et clusters fusionnant les attaques A/B,
puis maximise B-cubed méta non pondéré, le rappel des phases et la précision des
arêtes. Le scénario externe reste invisible jusqu'au choix du seuil.

| Mesure macro externe | Seuil relationnel interne | Seuil graphique interne |
|---|---:|---:|
| B-cubed attaques, méta | **0,487** | 0,472 |
| ARI attaques, méta | **0,222** | 0,185 |
| Rappel macro des phases dans le fragment dominant | **0,398** | 0,338 |
| Scénarios avec au moins une fusion | 2 | 2 |

Les seuils graphiques sélectionnés sont 0,95 pour `fox`, `santos` et `shaw`,
0,85 pour `harrison` et `wheeler`, 0,80 pour `russellmitchell`, 0,70 pour
`wardbeck` et 0,50 pour `wilson`. La règle supprime la fusion de `santos`, mais
en crée une nouvelle dans `wilson`. Les seuils élevés coupent des ponts utiles,
dégradent fortement `shaw` et réduisent le rappel des phases de `santos`.

Cette optimisation ne généralise donc pas et est rejetée. Les seuils
relationnels choisis dans les validations internes restent la baseline pour les
graphes AIT-ADS. Aucun autre réglage graphique n'est entrepris sur ces mêmes
scénarios, car adapter encore la méthode après observation des huit résultats
augmenterait le risque de surapprentissage. Le rapport négatif est conservé dans
`output/attack-graphs-threshold-optimized/report.json` pour la traçabilité.

L'optimisation sur AIT-ADS est désormais terminée. La prochaine étape du
protocole est la validation sur un autre dataset public compatible, qui devra
confirmer ou invalider la généralisation du modèle relationnel et des graphes.

### Validation externe stricte sur SOCBED ACSAC 2021

SOCBED a été retenu après comparaison avec DARPA 2000 LLDOS, CPTC-2018,
CICIDS2017, CSE-CIC-IDS2018 et LANL. CPTC-2018 fournit de vraies alertes mais
pas de vérité terrain suffisamment détaillée ; CIC fournit surtout des flux ;
LANL n'annotent pas les phases requises. DARPA possède une excellente vérité
terrain multiétape, mais exige de régénérer les alertes IDS depuis les PCAP.
SOCBED fournit directement des alertes Suricata et Sigma, du bruit bénin, les
journaux d'exécution et une attaque d'espionnage en neuf étapes.

L'archive officielle `dataset.zip` contient 40 exécutions : deux hôtes, deux
configurations de journalisation et dix répétitions. Sa taille est exactement
77 984 817 octets et son SHA-256 est
`7EDA65F08BBE6F274C1FEFF178AE132CFD0E8EDBDF0A10EF08321259B6FACC54`.
L'audit reproduit les prédicats `count_tps_sigma.py` et
`count_tps_suricata.py` publiés par les auteurs, puis attribue les vraies
alertes aux étapes décrites dans l'article et horodatées dans
`attackconsole_*.log`.

- 7 490 alertes IDS/Sigma au total ;
- 5 547 vraies alertes d'attaque selon les prédicats officiels ;
- 1 943 faux déclenchements utilisés comme négatifs ;
- étapes détectées : 1, 2, 3, 5, 7 et 8 ;
- étapes 4, 6 et 9 sans alerte, conformément aux résultats publiés ;
- 2 563 méta-alertes réversibles ;
- 14 020 paires candidates, dont 9 596 positives et 4 424 négatives.

Les caractéristiques sont calculées avec les paramètres AIT figés : compression
à deux secondes, fenêtre locale de 60 secondes, plafond de 50 candidats et au
plus cinq ponts causaux. Aucun seuil, profil, mapping ou hyperparamètre n'est
choisi à partir des performances SOCBED. Pour le ML, les huit modèles externes
AIT sont réentraînés avec leur configuration et leur nombre d'itérations déjà
sélectionnés. Chaque modèle applique son propre seuil AIT ; au moins quatre
votes sur huit sont requis pour créer une relation. Les baselines utilisent la
même procédure avec leurs seuils et coefficients AIT.

| Modèle | AP macro | F1 macro | MCC macro | Balanced accuracy | Précision | Rappel |
|---|---:|---:|---:|---:|---:|---:|
| Similarité seule | 0,840 | 0,867 | 0,357 | 0,677 | **0,853** | 0,884 |
| Causalité seule | 0,808 | **0,891** | **0,651** | **0,826** | 0,842 | 0,967 |
| Hybride manuel | 0,765 | **0,891** | **0,651** | **0,826** | 0,842 | 0,967 |
| Hybride ML | **0,969** | 0,837 | 0,121 | 0,524 | 0,731 | **1,000** |

Le ML hybride généralise très bien comme **fonction de classement** : son AP
est la meilleure dans les 40 runs, avec un pire run à 0,900, et son ROC-AUC
macro atteint 0,940. En revanche, ses seuils AIT ne sont pas transportables en
l'état. Le modèle accepte toutes les relations positives mais également trop de
négatifs. Ce résultat n'autorise pas une recalibration sur SOCBED : le faire
après observation des labels convertirait le test externe en validation.

Les composantes connexes des arêtes positives donnent :

| Modèle | B-cubed méta | ARI méta | B-cubed brut | Fragments/attaque | Couverture types de phases | Arêtes incorrectes |
|---|---:|---:|---:|---:|---:|---:|
| Similarité seule | 0,755 | 0,443 | 0,891 | 6,5 | 0,208 | **1 546** |
| Causalité seule | **0,873** | **0,733** | **0,936** | **1,5** | **0,833** | 2 276 |
| Hybride manuel | **0,873** | **0,733** | **0,936** | **1,5** | **0,833** | 2 276 |
| Hybride ML | 0,712 | 0,510 | 0,883 | **1,5** | **0,833** | 4 107 |

Le ML retrouve presque toute l'attaque et ses types de phases, mais ses 4 107
fausses arêtes absorbent davantage de faux déclenchements dans les composantes.
La causalité et l'hybride manuel produisent ici les meilleurs groupes. Leur
égalité vient des décisions binaires identiques aux seuils AIT, pas de scores
continus identiques : leur AP diffère.

SOCBED reste une validation externe limitée : les 40 runs répètent une même
attaque et ne contiennent pas plusieurs attaques concurrentes. Il permet de
tester le transfert des relations, la fragmentation et l'absorption de faux
positifs, mais pas la fusion de deux campagnes distinctes. La conclusion finale
est donc nuancée : l'hybride ML est le meilleur ranker externe, mais son seuil
et son graphe ne sont pas prêts pour un déploiement inter-dataset sans une
calibration de domaine effectuée sur un jeu de développement séparé. Les
rapports complets sont `output/socbed-audit.json`,
`output/socbed-external-validation/report.json` et
`output/socbed-external-graphs/report.json`.

Cette validation termine les grandes expériences prévues. Une éventuelle étude
DARPA LLDOS constituerait une extension future indépendante, et non une nouvelle
optimisation de la présente étude.

### Expérience ML pour les relations, manuel pour le graphe

L'hybride manuel avait déjà comparé `alpha` dans `{0,25, 0,50, 0,65, 0,75}`
et les seuils de 0,05 à 0,95 par pas de 0,05 dans les validations internes AIT.
Les huit folds ont indépendamment choisi `alpha = 0,25` et le seuil `0,50`.
Ces valeurs sont donc réutilisées sans réglage sur les tests.

Deux variantes sont testées : graphe construit directement avec les décisions
manuelles, et cascade dure exigeant simultanément une décision ML et une
décision manuelle positives. Sur SOCBED, les deux variantes produisent les
mêmes 11 552 arêtes, car toutes les arêtes manuelles retenues sont également
acceptées par l'ensemble ML.

| SOCBED macro | Graphe ML | Manuel / cascade |
|---|---:|---:|
| Précision des arêtes | 0,731 | **0,842** |
| Arêtes incorrectes | 4 107 | **2 276** |
| B-cubed méta, tous les nœuds | 0,712 | **0,873** |
| ARI méta, tous les nœuds | 0,510 | **0,733** |
| F1 des décisions d'arêtes | 0,837 | **0,891** |
| MCC des décisions d'arêtes | 0,121 | **0,651** |

Le score ML reste utilisé pour le classement et conserve donc son AP de 0,969.
Le filtre manuel améliore nettement ses décisions et son graphe sur SOCBED.
Ces deux lignes ne remplacent pas les métriques du classificateur ML : elles
mesurent uniquement les décisions binaires utilisées pour créer les arêtes.

Le transfert inverse sur AIT n'est toutefois pas satisfaisant :

| AIT macro, attaques seules | Graphe ML initial | Graphe manuel | Cascade dure |
|---|---:|---:|---:|
| B-cubed méta | **0,487** | 0,269 | 0,268 |
| ARI méta | **0,222** | 0,105 | 0,105 |
| Fragments moyens par attaque | **375** | 4 985 | 4 985 |
| Rappel macro des phases | **0,398** | 0,270 | 0,270 |
| Précision des arêtes | 0,823 | 0,829 | **0,877** |
| Arêtes incorrectes | 223 870 | 3 425 | **2 106** |

Le filtre supprime presque toutes les fausses arêtes AIT, mais aussi trop de
ponts vrais : les attaques sont fortement fragmentées. Il ne peut donc pas être
retenu comme règle graphique universelle malgré son excellent résultat SOCBED.
L'expérience montre plutôt que le score ML et le filtre manuel sont
complémentaires, mais qu'un filtre binaire dur n'est pas suffisamment robuste
entre domaines. Une future variante devrait employer le score manuel comme
poids ou contrainte souple et sélectionner sa règle sur un jeu de développement
graphique indépendant. Le rapport complet est
`output/cascade-graph-evaluation.json`.

### Fusion graphique souple et causalité inconnue neutre

Une dernière expérience corrige explicitement le défaut du filtre dur. Lorsque
les deux étapes causales sont connues, le score manuel reste
`0,25 × similarité + 0,75 × causalité`. Lorsque la causalité est inconnue, le
score manuel devient la similarité seule : l'inconnu n'est donc plus assimilé à
une incompatibilité. Le score de graphe est ensuite :

```text
score_graphe = lambda × probabilité_ML + (1 - lambda) × score_manuel
```

Les valeurs `lambda = {0,70, 0,85, 1,00}` et les seuils
`{0,40, 0,50, 0,60, 0,70, 0,80, 0,90, 0,95}` sont sélectionnés exclusivement
dans les validations internes de chaque fold. La règle de sélection minimise
les fusions, puis maximise B-cubed, le rappel des phases et la précision des
arêtes. Les configurations choisies sont :

- `fox` : lambda 0,85, seuil 0,95 ;
- `harrison` : lambda 1,00, seuil 0,90 ;
- `russellmitchell` : lambda 0,85, seuil 0,90 ;
- `santos` : lambda 1,00, seuil 0,95 ;
- `shaw` : lambda 0,85, seuil 0,95 ;
- `wardbeck`, `wheeler`, `wilson` : lambda 0,70, seuil 0,90.

| AIT macro, attaques seules | Graphe ML initial | Fusion souple |
|---|---:|---:|
| B-cubed méta | **0,487** | 0,365 |
| ARI méta | **0,222** | 0,110 |
| Fragments moyens par attaque | **375** | 406 |
| Couverture des types de phases | **0,890** | 0,710 |
| Rappel macro des phases | **0,398** | 0,231 |
| Arêtes incorrectes | 223 870 | **151 522** |

La fusion réduit les arêtes incorrectes, mais dégrade tous les critères de
reconstruction de l'attaque. Son transfert vers SOCBED est encore moins bon :
B-cubed méta 0,614, ARI 0,089, rappel des phases 0,071 et environ 21 fragments
par attaque. Les seuils 0,90–0,95 choisis pour éviter les fusions A/B dans AIT
ne sont pas calibrés pour les scores SOCBED.

Cette variante est donc rejetée. Les métriques de classification du ML restent
AP 0,707/F1 0,733/MCC 0,727 sur AIT et AP 0,969/F1 0,837/MCC 0,121 sur SOCBED ;
elles ne sont pas recalculées à partir du score graphique. La baseline graphique
reste constituée des arêtes ML avec les seuils relationnels internes. Le rapport
complet est `output/soft-graph-fusion.json`. Cette variante n'est pas utilisée
dans la suite.

### Cœur manuel et ponts ML par forêt couvrante maximale

Pour éviter à la fois les nombreuses fausses arêtes du graphe ML et la forte
fragmentation du filtre manuel, une variante en deux étapes est évaluée :

1. le cœur fiable conserve les arêtes qui passent simultanément le seuil ML du
   fold et le score manuel `alpha = 0,25`, seuil `0,50` ;
2. les autres relations ML sont triées par probabilité décroissante et servent
   uniquement de ponts entre deux composantes encore séparées. Une union-find
   interdit les cycles inutiles, et une incompatibilité causale connue interdit
   le pont.

Cette seconde étape est donc une forêt couvrante maximale contrainte. Elle ne
réintroduit pas toutes les arêtes ML : elle ajoute seulement les relations
nécessaires à la connectivité. Le seuil des ponts est choisi parmi
`{0,50, 0,60, 0,70, 0,80, 0,90, 0,95}` dans les validations internes de chaque
fold AIT. Les huit folds choisissent indépendamment `0,50`, ce qui indique un
choix stable ; aucun seuil n'est choisi sur les scénarios de test ni sur
SOCBED.

| AIT macro, attaques seules | Graphe ML initial | Cœur manuel + ponts ML |
|---|---:|---:|
| B-cubed méta | 0,487 | **0,492** |
| ARI méta | 0,222 | **0,224** |
| Fragments moyens par attaque | 375 | **355** |
| Plus grand fragment | 0,364 | **0,371** |
| Couverture des types de phases | 0,890 | **0,922** |
| Rappel macro des phases | 0,398 | **0,416** |
| Arêtes incorrectes | 223 870 | **55 794** |

L'amélioration AIT est modeste pour B-cubed et ARI, mais cohérente sur la
fragmentation et les phases, avec quatre fois moins d'arêtes incorrectes. Elle
ne provient pas d'un nouveau réglage sur le test : chaque scénario externe est
reconstruit avec le seuil choisi sans lui dans les folds internes.

| SOCBED macro, tous les nœuds | Graphe ML | Manuel seul | Cœur + ponts |
|---|---:|---:|---:|
| B-cubed méta | 0,712 | **0,873** | 0,745 |
| ARI méta | 0,510 | **0,733** | 0,609 |
| Arêtes incorrectes | 4 107 | **2 276** | 2 708 |
| Fragments moyens par attaque | 1,5 | 1,5 | 1,5 |
| Rappel macro des phases | 0,786 | 0,786 | 0,786 |

Sur SOCBED, cette méthode améliore le graphe ML, mais le manuel seul reste
meilleur. Le cœur manuel avec ponts ML est néanmoins le meilleur compromis
unique entre les deux domaines : contrairement au manuel seul, il ne détruit
pas la connectivité AIT, et contrairement au ML seul, il réduit fortement les
fausses arêtes. Il est donc retenu comme méthode graphique hybride principale,
tandis que le manuel seul demeure une baseline spécialisée SOCBED.

Ce post-traitement ne modifie ni l'entraînement ni les métriques de
classification relationnelle : AP/F1/MCC restent respectivement
0,707/0,733/0,727 sur AIT et 0,969/0,837/0,121 sur SOCBED. Le rapport complet,
incluant les sélections internes et les résultats par scénario, est
`output/manual-core-ml-bridges.json`.

### Troisième validation externe : DARPA 2000 LLDOS

Une troisième validation est effectuée sur les deux scénarios publics LLDOS
1.0 et 2.0.2 de DARPA 2000. Les captures réseau complètes sont analysées hors
ligne avec Suricata 7.0.17 et 51 153 règles ET Open/GPL. Neuf règles de 2025
utilisant le mot-clé Suricata 8 `file.magic` sont retirées pour compatibilité ;
elles concernent uniquement des archives ZIP/TAR et non le scénario LLDOS.

Les labels ne sont pas déduits des noms de signatures IDS. Chaque alerte est
appariée aux sessions XML officielles du MIT par timestamp, paire d'endpoints
et capteur. Les alertes ne correspondant à aucune session officielle sont
considérées comme bruit/bénignes. Le passage heure de l'Est vers UTC respecte
le changement EST/EDT entre mars et avril 2000.

| Scénario | Alertes brutes | Méta-alertes attaque | Méta-alertes bénignes | Phases IDS couvertes | Paires + / - |
|---|---:|---:|---:|---|---:|
| LLDOS 1.0 | 1 579 | 203 | 213 | 2, 3, 4 | 3 284 / 444 |
| LLDOS 2.0.2 | 2 755 | 6 | 447 | 2 seulement | 15 / 2 337 |

Cette dernière ligne est une limite réelle du capteur : les PCAP et XML
contiennent les cinq phases, mais le jeu de règles ne déclenche aucune alerte
IDS appariable sur les autres phases de LLDOS 2.0.2. Aucune pseudo-alerte n'est
créée pour combler cette absence.

Les huit modèles AIT sont ensuite réentraînés uniquement sur leurs sept
scénarios de développement respectifs. Leurs configurations, itérations et
seuils restent gelés. DARPA ne sert à choisir aucun paramètre.

| Graphe DARPA, macro 2 scénarios | ML seul | ML ET manuel | Cœur manuel + ponts ML |
|---|---:|---:|---:|
| B-cubed méta, tous les nœuds | 0,424 | **0,903** | 0,591 |
| ARI méta, tous les nœuds | 0,231 | **0,563** | 0,242 |
| Arêtes incorrectes, total | 2 781 | **17** | 461 |
| Précision macro des arêtes | 0,444 | **0,831** | 0,490 |
| Fragments moyens par attaque | **2,5** | 4,0 | **2,5** |
| Rappel macro des phases | 0,636 | 0,636 | 0,636 |

Le détail par scénario montre le même classement global :

| Scénario et métrique | ML seul | ML ET manuel | Cœur + ponts |
|---|---:|---:|---:|
| LLDOS 1.0 B-cubed tous nœuds | 0,647 | **0,812** | 0,664 |
| LLDOS 1.0 arêtes incorrectes | 444 | **11** | 156 |
| LLDOS 2.0.2 B-cubed tous nœuds | 0,202 | **0,993** | 0,519 |
| LLDOS 2.0.2 arêtes incorrectes | 2 337 | **6** | 305 |

Sur LLDOS 1.0, le classement ML est excellent (AP 0,997), mais les seuils AIT
acceptent toutes les paires et donnent MCC 0. Sur LLDOS 2.0.2, le transfert est
nettement mauvais (AP 0,0037) et toutes les paires sont également acceptées.
La bonne valeur du F1 ML sur LLDOS 1.0 (0,937) vient du fort déséquilibre en
faveur des positives et ne doit pas masquer ce défaut de seuil.

La cascade dure est donc la meilleure stratégie sur DARPA, comme sur SOCBED,
alors qu'elle fragmente trop fortement AIT. La nouvelle méthode reste un
compromis nettement meilleur que ML seul sur DARPA, mais ses ponts reconnectent
encore trop de composantes bénignes. Les trois datasets ne justifient donc pas
une règle graphique universelle unique : la disponibilité observable des
étapes causales doit être prise en compte. Un filtre dur convient lorsque les
étapes sont bien renseignées ; le cœur manuel avec ponts ML reste nécessaire
lorsqu'elles sont largement inconnues. Cette décision de domaine devra être
fondée sur la couverture observable, jamais sur les labels de test.

Le rapport complet est `output/darpa2000-external-comparison.json`. Les caches
reproductibles sont dans `data/processed/darpa2000_pairs_v2` et
`data/processed/darpa2000_pairs_v3`.

