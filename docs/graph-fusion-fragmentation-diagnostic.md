# Diagnostic des fusions et de la fragmentation — AlertGraph V1

Date : 9 novembre 2026  
Statut : diagnostic de développement, pas un test final indépendant

## Périmètre et reproductibilité

Le diagnostic rejoue la baseline scientifique alignée avec :

- les huit modèles figés de `output/final-ensemble.joblib` ;
- leurs seuils relationnels et graphiques propres ;
- la stratégie cœur manuel + ponts ML ;
- le vote final `au moins 4 modèles sur 8` ;
- aucun retrait de cycle après le vote.

Aucun modèle n'a été réentraîné. Aucun seuil, mapping, cache ou composant de
production n'a été modifié. La vérité terrain intervient uniquement après la
reconstruction, pour le diagnostic.

Les nombres d'arêtes reproduisent exactement la baseline déjà enregistrée :
64 355 pour `harrison`, 27 072 pour `santos`, 49 586 pour `wilson`, 45 629
pour `fox` et 45 723 pour `wheeler`.

Artefacts :

- `ml/diagnose_graph_reconstruction_failures.py` : outil reproductible ;
- `output/graph-failure-diagnostic-v2/report.json` : résultats structurés ;
- `output/graph-failure-diagnostic-v2/fusion_edges.parquet` : six arêtes des
  chemins de fusion avec probabilités, votes et caractéristiques.

## Résumé comparatif

| Scénario | Composantes fusionnées | B-cubed attaques | Fragments/attaque | Plus grand fragment | Arêtes attaque–non-attaque |
|---|---:|---:|---:|---:|---:|
| `harrison` | 1 | 0,020 | 16 129,5 | 0,222 | 33 |
| `santos` | 1 | 0,007 | 944,0 | 0,099 | 27 |
| `wilson` | 1 | 0,367 | 913,0 | 0,302 | 31 |
| `fox` | 0 | 0,667 | 253,0 | 0,371 | 6 |
| `wheeler` | 0 | 0,690 | 193,0 | 0,391 | 6 |

`fox` et `wheeler` sont de meilleurs contrôles, mais ils ne constituent pas des
reconstructions parfaites : leurs petites attaques B restent elles aussi très
fragmentées.

Toutes les arêtes sélectionnées qui ont une cible négative portent une
annotation faible : 1 803 dans `harrison`, 1 720 dans `santos`, 5 801 dans
`wilson`, 2 027 dans `fox` et 5 653 dans `wheeler`. Aucune n'est une négative
forte. Les fusions sont donc certaines au regard des identifiants A/B utilisés
par l'évaluation, mais la qualification de chaque arête comme faux positif
réel reste moins certaine.

## 1. Fusion dans `harrison`

La seule composante fusionnée contient exactement deux méta-alertes : une de
`harrison:A` et une de `harrison:B`. Elle est créée par une unique arête directe :

- `meta-116925` (`harrison:B`, signature `2027863`) vers `meta-116947`
  (`harrison:A`, signature `2027865`) ;
- paire locale séparée de 59 secondes ;
- une entité partagée : `ip:192.168.128.1` ;
- annotation négative faible `different-attack-instances` ;
- similarité 0,586, causalité 0,050, score manuel 0,184 ;
- probabilités ML de 0,500 à 0,967, moyenne 0,813 ;
- seuil relationnel franchi par 6 modèles, admissible comme pont par 8 ;
- retenue comme pont par exactement 4 modèles, jamais comme cœur ;
- arête de coupure : son retrait supprime entièrement cette fusion.

Cause vérifiée : faux positif ML local retenu par la construction des ponts. Ce
n'est ni un pont causal ancien, ni une erreur du cœur manuel. La fusion est
réelle pour la métrique, mais très petite ; elle n'explique pas le très faible
B-cubed. Le problème dominant de `harrison` est la fragmentation.

## 2. Fragmentation dans `harrison`

| Étape | `harrison:A` | `harrison:B` |
|---|---:|---:|
| Nœuds | 2 618 | 48 257 |
| Composantes avec toutes les paires candidates internes | 55 | 142 |
| Composantes avec les positives fortes | 1 440 | 1 155 |
| Composantes après passage du seuil ML par au moins 4 modèles | 1 301 | 1 155 |
| Composantes du cœur manuel voté | 1 428 | 48 257 |
| Composantes avec toutes les relations admissibles comme pont par au moins 4 modèles | 1 255 | 1 045 |
| Composantes finales, vote des arêtes à 4/8 | 1 361 | 30 898 |

Les quelque 16 129 fragments rapportés sont la moyenne de 1 361 et 30 898.

Causes vérifiées :

1. **Absence de candidats, contribution limitée.** Même un oracle limité aux
   paires générées ne descendrait pas sous 55 et 142 composantes. Cela explique
   une base de 98,5 fragments en moyenne, pas 16 129,5.
2. **Annotations fortes incomplètes.** Les positives fortes seules laissent
   1 440 et 1 155 composantes. De nombreuses relations qui connectent les
   attaques sont seulement temporelles/faibles ; elles ne doivent pas être
   traitées comme vérité certaine.
3. **Filtre manuel très sévère sur B.** Le cœur ne contient aucune arête interne
   à `harrison:B`. La causalité/similarité manuelle ne fournit donc aucun socle
   stable pour ses 48 257 nœuds.
4. **Instabilité des arêtes de forêt entre modèles, cause principale.** Pour B,
   l'union des arêtes retenues par au moins un modèle donne 950 composantes ; le
   quorum 2 en donne 1 006, le quorum 3 en donne 8 779 et le quorum 4 en donne
   30 898. Les modèles choisissent des arêtes alternatives pour relier les mêmes
   zones. Le vote porte sur l'identité exacte de l'arête après huit forêts
   distinctes et élimine ces alternatives.
5. **ML relationnel.** Pour les positives fortes de tout `harrison`, seulement
   57 sur 389 418 ne franchissent pas le seuil relationnel dans au moins quatre
   modèles. Le ML brut n'est donc pas la cause majeure pour ces relations. En
   revanche, il rejette beaucoup de positives faibles ; leur statut est incertain.

## 3. `santos`

La composante fusionnée contient 89 nœuds : 87 d'attaque et deux non-attaque.
Il n'existe aucune arête directe A–B. Le chemin minimal comporte trois arêtes :

1. `santos:A` vers une méta-alerte faible/non-attaque, pont causal de 294 556 s
   (81,8 h), score manuel 0,884, 6 votes ;
2. cette méta-alerte vers une seconde non-attaque, pont causal de 103 965 s
   (28,9 h), score manuel 0,884, 6 votes ;
3. la seconde non-attaque vers `santos:B`, paire locale de 1 s, score manuel
   0,259, retenue uniquement comme pont par 4 modèles.

Les deux premières relations utilisent notamment les signatures `A-Dns-Chr` et
`A-All-Evt` et la même entité DNS. Les trois arêtes sont des arêtes de coupure.

Cause vérifiée : effet de transitivité passant par deux nœuds faiblement annotés,
avec combinaison de vieux ponts causalement compatibles et d'un faux positif ML
local. Ni le seul filtre des vieux ponts ni le seul filtre local ne décrit toute
la chaîne.

Fragmentation : les candidats permettraient 34 composantes pour A et 70 pour B,
contre 350 et 1 538 au final. Pour B, les relations admissibles au quorum 4
permettraient 253 composantes ; le vote après les forêts en produit 1 541 dans
le graphe restreint. Le même mécanisme que `harrison` existe, mais moins fortement.

## 4. `wilson`

La composante fusionnée contient 1 535 nœuds : 1 184 d'attaque et 351
non-attaque. Une même méta-alerte faible/non-attaque (`meta-17321`, signature
`2221004`) sert de pivot :

- vers `wilson:B` : pont causal de 176 162 s (48,9 h), score manuel 0,875,
  4 votes cœur et 2 votes pont ;
- vers `wilson:A` : pont causal de 261 741 s (72,7 h), score manuel 0,875,
  4 votes cœur, arête de coupure.

Les extrémités d'attaque ont la signature générique `A-All-Evt` et partagent
l'entité `host:vpn` avec le pivot.

Cause vérifiée : hub faiblement annoté + signature générique + vieux ponts
causaux. Contrairement à `harrison`, le cœur manuel participe directement ; une
correction limitée aux ponts ML serait contournée.

Fragmentation : `wilson:A` passe de 46 composantes possibles avec les candidats
à 805 ; `wilson:B` passe de 47 à 1 021. B ne possède aucune positive forte et
seulement deux relations franchissent le seuil ML à 4/8. Il est donc impossible
de qualifier cette perte de faux négatifs certains : elle dépend principalement
d'annotations faibles.

## 5. Pourquoi `fox` et `wheeler` ne fusionnent pas

Ils ont respectivement 6 arêtes attaque–non-attaque, contre 33, 27 et 31 dans
les trois scénarios fusionnés. Aucun n'a d'arête directe A–B ni de nœud faible
qui relie simultanément les deux attaques.

Leur attaque principale A possède aussi un cœur dense et stable. Entre le
quorum 1 et le quorum 4, le nombre de composantes de A n'augmente que de 351 à
392 dans `fox` et de 231 à 280 dans `wheeler`. Pour `harrison:B`, il augmente de
950 à 30 898.

La différence vérifiée n'est donc pas simplement la présence de faux positifs :
`fox` et `wheeler` en contiennent aussi. Une fusion apparaît lorsqu'une arête ou
un petit chemin de coupure relie effectivement les deux attaques, et la
fragmentation devient extrême lorsque le graphe dépend de ponts alternatifs sans
cœur stable.

## 6. Contribution des mécanismes

| Mécanisme | Conclusion |
|---|---|
| Absence de paires candidates | Réelle, mais minoritaire dans l'écart entre la baseline et le graphe candidat. |
| Faux négatifs ML | Peu nombreux sur les positives fortes de `harrison`, `santos`, `wilson`, `fox` et `wheeler`; nombreux sur les faibles, donc conclusion incertaine. |
| Faux positifs ML | Cause directe dans `harrison` et sur le lien local final de `santos`; toutes les cibles négatives concernées sont faibles. |
| Filtre manuel | Stabilise les attaques principales de `fox`/`wheeler`, mais élimine tout le cœur de `harrison:B`; participe à la fusion de `wilson`. |
| Construction des ponts | Cause majeure de fragmentation lorsque des forêts équivalentes choisissent des arêtes différentes. |
| Transitivité | Cause directe dans `santos` et `wilson`; une petite chaîne suffit à fusionner des ensembles plus grands. |
| Vérité terrain | Les identifiants A/B établissent les fusions pour l'évaluation, mais les arêtes négatives sont faibles et ne prouvent pas toutes une incompatibilité sémantique certaine. |

## 7. Trois stratégies ciblées à expérimenter

### Stratégie 1 — Consensus avant la forêt

Au lieu de construire huit forêts puis de voter sur leurs arêtes exactes :

1. conserver le cœur voté ;
2. agréger d'abord l'admissibilité des ponts et leurs scores issus des huit
   modèles ;
3. construire ensuite une seule forêt maximale sur les candidats consensuels.

Cette stratégie répond directement à la fragmentation observée dans
`harrison:B` et `santos:B`. Elle n'ajoute ni modèle ni caractéristique. Elle ne
résout toutefois pas seule les fusions : les mauvaises arêtes de `harrison`,
`santos` et `wilson` peuvent également obtenir un consensus.

### Stratégie 2 — Validation d'une fusion de composantes par preuves multiples

Une arête unique ne pourrait réunir deux composantes déjà formées que si elle
apporte plusieurs preuves observables réellement distinctes. Une composante
reliée uniquement par une signature générique ou un seul nœud pivot exigerait,
par exemple, une seconde relation indépendante utilisant une autre paire et une
autre famille de preuve (continuité technique, entité distincte, progression
observable). La règle doit s'appliquer au cœur comme aux ponts.

Cette stratégie cible l'unique arête de `harrison` et les chaînes à pivot de
`santos`/`wilson`. Elle ne doit utiliser ni identifiant A/B, ni annotation
bénigne. Son risque principal est de couper les vraies transitions longues qui
ne possèdent qu'une preuve ; la conservation des positives fortes doit être une
contrainte explicite.

### Stratégie 3 — Audit des articulations après reconstruction

Après le graphe, examiner seulement les arêtes de coupure et les nœuds
d'articulation qui constituent l'unique passage entre deux zones. Une liaison
serait retirée uniquement lorsque ce passage est faiblement corroboré ou repose
sur un pivot/signature générique, puis les composantes seraient recalculées.

Cette stratégie répond exactement aux chemins observés : l'arête de `harrison`,
les trois coupures de `santos` et une coupure de `wilson`. Elle est plus locale
que l'application d'un seuil temporel global. Son risque est le même que pour la
stratégie 2 : une vraie phase rare peut légitimement être une articulation.

## 8. Recommandation pour la prochaine expérimentation

Tester d'abord **la stratégie 1, consensus avant la forêt**, car la cause la plus
massive et la mieux vérifiée est le vote appliqué après huit choix de forêt
instables. L'expérience doit comparer, à paramètres figés :

1. baseline actuelle ;
2. cœur voté + forêt unique sur admissibilité consensuelle ;
3. même reconstruction avec la validation multi-preuves de la stratégie 2 ;
4. éventuellement audit d'articulation de la stratégie 3 comme ablation séparée.

La sélection doit se faire uniquement sur des scénarios de développement et
avec des contraintes préalables : aucune hausse du nombre de composantes
fusionnées, conservation élevée des positives fortes, baisse de la
fragmentation, stabilité par scénario et examen séparé des annotations faibles.
Les résultats AIT resteront exploratoires, puisque ces graphes ont déjà été
consultés. SOCBED, DARPA et Wazuh ne doivent pas servir au choix des règles.

La stratégie 1 ne doit pas être activée en production sur la seule base de ce
diagnostic : elle pourrait restaurer des ponts utiles tout en restaurant aussi
des ponts erronés. La stratégie 2 constitue le garde-fou causal à évaluer, pas
une conclusion déjà validée.
