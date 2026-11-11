# Expérience : consensus avec validation multi-preuves des unions

Date : 9 novembre 2026  
Statut : expérimentation AIT exploratoire, non activée dans Wazuh

## Décision

La politique supprime les trois fusions A/B et réduit la fragmentation moyenne,
mais le résultat n'est pas robuste : six scénarios sur huit deviennent plus
fragmentés que la baseline, B-cubed, ARI et la couverture des phases diminuent,
et aucune union réelle n'est finalement validée par deux paquets indépendants.

**Recommandation : conserver la baseline scientifique actuelle.**

La politique multi-preuves reste un résultat expérimental négatif utile. Elle
ne doit pas être activée dans Wazuh.

## Méthodes comparées

1. **Baseline** : huit forêts indépendantes puis vote `>= 4/8`.
2. **Consensus** : admissibilité consensuelle puis une forêt unique.
3. **Multi-preuves avec liens souples** : noyaux locaux prudents, puis deux
   paquets indépendants nécessaires pour toute autre union. Les relations
   refusées restent consultables comme liens souples.
4. **Ablation sans liens souples** : mêmes composantes dures, mais suppression
   des relations souples de la sortie probatoire.

Les composantes et les métriques de regroupement des méthodes 3 et 4 sont
identiques par définition. L'ablation mesure la perte de traçabilité et de
relations, pas une nouvelle partition.

## Politique expérimentale figée avant l'évaluation complète

### Noyau de démarrage

Une relation consensuelle peut réunir deux singletons ou petits composants si
elle est :

- locale selon la fenêtre existante ;
- fondée sur au moins une entité partagée ;
- associée à une signature non générique ;
- cohérente par signature ou progression d'étape ;
- sans étape `NON_MALICIOUS`.

Cette exception évite le blocage où aucun singleton ne pourrait former le
premier composant. Une transition longue unique ne satisfait pas cette
exception et reste souple.

### Paquets indépendants

Les relations admissibles d'une même frontière sont regroupées transitivement
si elles partagent :

- une méta-alerte pivot ;
- une entité normalisée, avec retrait des ports IPv4 ;
- une signature non générique.

Une union supplémentaire exige au moins deux paquets distincts. Les paquets
utilisés par une union sont consommés et ne peuvent pas être réutilisés.

La règle s'applique aux relations du cœur manuel comme aux ponts ML. La vérité
terrain, les identifiants A/B et la confiance des labels ne participent jamais
à la décision.

## Résultats moyens sur huit scénarios

| Mesure | Baseline | Consensus | Multi-preuves, composantes dures |
|---|---:|---:|---:|
| Arêtes/relations dures | 243 049 | 279 070 | 215 065 |
| Scénarios fusionnés | 3 | 3 | **0** |
| Composantes A/B fusionnées | 3 | 3 | **0** |
| Méta-alertes d'attaque dans les fusions | 1 273 | 12 776 | **0** |
| Fragments par attaque | 2 349,2 | **381,9** | 494,0 |
| B-cubed attaques | 0,289 | **0,468** | 0,270 |
| ARI attaques | 0,115 | **0,163** | 0,063 |
| Plus grand fragment | 0,253 | **0,356** | 0,225 |
| Couverture des types de phases | 0,852 | **0,891** | 0,661 |
| Rappel des alertes par phase | 0,294 | **0,376** | 0,206 |
| Positives fortes dans les relations dures | 214 963 | **245 967** | 201 359 |
| Négatives faibles dans les relations dures | 24 950 | 29 662 | **11 259** |

La fragmentation moyenne reste nettement inférieure à la baseline, mais ce
résultat est dominé par `harrison`. La qualité moyenne des groupes d'attaque est
plus faible que la baseline.

## Résultats par scénario

| Scénario | Fragments baseline | Fragments consensus | Fragments multi-preuves | B-cubed multi-preuves | Fusion multi-preuves |
|---|---:|---:|---:|---:|---:|
| `fox` | 253,0 | 246,0 | 389,0 | 0,455 | 0 |
| `harrison` | 16 129,5 | 1 148,0 | **1 404,5** | 0,328 | 0 |
| `russellmitchell` | 143,5 | 131,0 | 176,0 | 0,114 | 0 |
| `santos` | 944,0 | 291,0 | **327,5** | 0,422 | 0 |
| `shaw` | 96,5 | 78,5 | 105,0 | 0,085 | 0 |
| `wardbeck` | 121,0 | 116,5 | 149,5 | 0,038 | 0 |
| `wheeler` | 193,0 | 180,5 | 310,5 | 0,490 | 0 |
| `wilson` | 913,0 | 864,0 | 1 090,0 | 0,229 | 0 |

La méthode améliore la fragmentation par rapport à la baseline uniquement sur
`harrison` et `santos`. Elle la dégrade sur les six autres scénarios.

## Vérification des fusions connues

### `harrison`

Les trois nouvelles relations A–B du consensus, séparées de 9, 16 et 59
secondes, obtiennent chacune un seul paquet et deviennent des liens souples.
Elles ne fusionnent plus les attaques.

### `santos`

La relation locale et les deux vieux ponts de la chaîne
A→non-attaque→non-attaque→B restent tous visibles, mais chacun est refusé comme
union avec un seul paquet.

### `wilson`

Les deux vieux ponts du cœur, malgré quatre votes cœur chacun, sont soumis à la
même validation. Ils restent souples et ne fusionnent plus A et B.

La validation est donc effectivement appliquée au cœur et aux ponts.

## Rôle des liens souples et ablation

64 005 relations du consensus deviennent souples, soit 22,9 % :

| Type | Relations dures | Liens souples | Total conservé avec liens souples |
|---|---:|---:|---:|
| Positives fortes | 201 359 | 44 608 | 245 967 |
| Positives faibles | 2 447 | 994 | 3 441 |
| Négatives fortes | 0 | 0 | 0 |
| Négatives faibles | 11 259 | 18 403 | 29 662 |

L'ablation sans liens souples perdrait 44 608 positives fortes. Les conserver
préserve toute la couverture relationnelle du consensus, mais ne répare pas la
fragmentation des composantes dures.

Dans `wheeler`, 59 vieux ponts restent consultables comme liens souples : 17
positives fortes, une positive faible et 41 négatives faibles. Leur délai atteint
322 276 secondes, soit environ 89,5 heures.

## Unions acceptées et refusées

- 87 303 unions de noyau ont été acceptées ;
- 64 005 relations ont été refusées comme unions et conservées comme liens
  souples ;
- **aucune union supplémentaire n'a été acceptée par deux paquets indépendants**.

Les unions de noyau comprennent 76 281 positives fortes, 350 positives faibles
et 10 672 négatives faibles. Ces dernières n'ont créé aucune fusion A/B, mais
montrent que le noyau n'est pas une preuve de vérité individuelle.

L'absence totale d'union multi-paquets signifie que la définition est trop
stricte pour les structures observées. Les relations multiples réelles partagent
presque toujours un pivot, une entité ou une signature et sont regroupées dans
un seul paquet.

## Déterminisme et sensibilité à l'ordre

Les ordres d'application primaire et inversé produisent une partition identique
sur les huit scénarios : ARI entre partitions égal à 1,0 partout, mêmes nombres
de liens souples.

Ce résultat est rassurant pour la reproductibilité, mais il est en partie
trivial ici : aucune union dynamique multi-paquets n'a été déclenchée.

## Coût mesuré

Pour l'ordre primaire, hors inférence ML :

- temps mur cumulé : 117,6 secondes ;
- temps CPU cumulé : 109,4 secondes ;
- pic maximal `tracemalloc` : 216 102 463 octets, environ 206 Mio ;
- 29 179 frontières examinées ;
- 87 531 visites d'arêtes de preuve ;
- aucune ronde d'union multi-paquets.

Le test d'ordre inversé double approximativement le coût de reconstruction. Le
pic `tracemalloc` ne mesure pas nécessairement toute la mémoire native de NumPy,
Arrow ou igraph et constitue donc une borne instrumentale, pas le RSS total.

Ces mesures ne permettent pas d'affirmer une complexité `O(E log V)`. Avec des
unions dynamiques réelles, plusieurs rondes pourraient revisiter les mêmes
frontières et augmenter sensiblement le coût.

## Validité scientifique

Les références hors-fold gelées sont conservées dans le rapport, mais les trois
méthodes à huit modèles restent exploratoires : sept modèles peuvent avoir vu le
scénario évalué.

SOCBED, DARPA et Wazuh n'ont pas été utilisés pour concevoir, sélectionner ou
ajuster la politique. Le pilote `fox` a montré la sévérité de la règle ; celle-ci
n'a pas été assouplie avant l'exécution complète.

## Tests et non-régression

Les tests couvrent :

- singleton local légitime accepté comme noyau ;
- transition longue unique conservée comme lien souple ;
- trois relations répétitives de `harrison` regroupées en un paquet ;
- absence de fusion de leurs composants synthétiques ;
- chaînes avec pivot générique de type `santos`/`wilson` ;
- validation d'une relation du cœur au lieu de son acceptation automatique ;
- impossibilité de réutiliser une preuve consommée ;
- déterminisme des ordres primaire et inversé.

Résultat : 8/8 tests ciblés et 109/109 tests complets réussis.

## Conclusion et recommandation

Le critère de sécurité sur les fusions est satisfait : aucune attaque A/B n'est
fusionnée et aucune méta-alerte d'attaque n'appartient à une composante fusionnée.

Cependant, le compromis global n'est pas suffisamment bon :

- fragmentation aggravée dans six scénarios sur huit ;
- B-cubed, ARI et rappel des phases inférieurs à la baseline ;
- 44 608 positives fortes reléguées en liens souples ;
- aucune union réellement justifiée par deux paquets dans les données réelles.

**La baseline doit rester active.** Le consensus simple et la politique
multi-preuves doivent rester des références expérimentales séparées. Il serait
méthodologiquement risqué d'assouplir encore les paquets en observant les mêmes
scénarios AIT ; une nouvelle règle devrait être conçue puis validée sur de
nouveaux scénarios entièrement exclus de cette analyse.
