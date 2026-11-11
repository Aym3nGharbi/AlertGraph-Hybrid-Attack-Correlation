# Conception : validation multi-preuves des unions de composantes

Date : 9 novembre 2026  
Statut : conception scientifique uniquement, aucune implémentation

## Décision actuelle

La baseline scientifique reste active dans Wazuh. Le consensus avant forêt
reste une référence expérimentale séparée.

La prochaine expérience devrait tester une reconstruction à deux niveaux :

- des **arêtes probatoires souples**, qui restent visibles mais ne fusionnent
  pas automatiquement les composantes ;
- des **unions fortes**, autorisées seulement quand la frontière entre deux
  composantes possède plusieurs preuves indépendantes.

Cette séparation est nécessaire parce que les caractéristiques actuelles ne
permettent pas toujours de distinguer une vraie transition longue unique d'une
mauvaise liaison causalement plausible.

## 1. Mécanismes exacts d'aggravation

### `harrison`

L'arête A–B de la baseline est retirée par la forêt consensuelle, mais trois
nouvelles arêtes A–B sont sélectionnées. Elles sont toutes locales et faiblement
annotées comme `different-attack-instances` :

| Délai | Votes cœur | Votes admissibles | Probabilité moyenne | Preuve dominante |
|---:|---:|---:|---:|---|
| 9 s | 0 | 8 | 0,886 | même IP `192.168.128.1` |
| 16 s | 0 | 4 | 0,547 | même IP `192.168.128.1` |
| 59 s | 0 | 8 | 0,839 | mêmes hôte/IP, protocole et service |

Les trois relations utilisent des extrémités différentes, mais ne constituent
pas trois preuves indépendantes : elles partagent la même infrastructure et la
signature `2027863` revient sur les trois relations. Une relation implique aussi
`A-All-Evt` et deux impliquent une étape `NON_MALICIOUS`.

Le consensus ajoute parallèlement 32 898 positives fortes internes et en retire
3 061. Les fragments A et B deviennent donc beaucoup plus grands, puis les
trois liaisons répétitives les réunissent. La composante fusionnée passe de 2 à
8 920 méta-alertes d'attaque.

### `santos`

Les trois relations de fusion de la baseline restent sélectionnées :

- A vers non-attaque, vieux pont de 81,8 h ;
- non-attaque vers non-attaque, vieux pont de 28,9 h ;
- non-attaque vers B, relation locale de 1 s.

Elles reposent sur la même infrastructure DNS, deux nœuds faibles et la
signature générique `A-All-Evt`. Le consensus reconnecte davantage l'attaque B
autour de cette chaîne. La composante fusionnée passe de 87 à 2 581
méta-alertes d'attaque.

### `wilson`

Les deux vieux ponts de 48,9 h et 72,7 h restent sélectionnés dans le cœur
consensuel. Ils partagent le même pivot `meta-17321`, le même hôte VPN et des
extrémités `A-All-Evt`. Le consensus ajoute surtout des relations internes et
non-attaque–non-attaque autour du composant. La fusion passe de 1 184 à 1 275
méta-alertes d'attaque.

### Conclusion commune

L'aggravation suit deux étapes :

1. le consensus reconnecte correctement de nombreux fragments internes ;
2. une petite frontière erronée, déjà présente ou nouvellement sélectionnée,
   propage alors la fusion à ces fragments agrandis.

Le nombre de clusters fusionnés reste constant et masque cette propagation.

## 2. Familles de preuves observables

| Informations disponibles | Famille de preuve | Règle d'indépendance |
|---|---|---|
| Entités partagées, hôtes, IP, Jaccard d'entités | Continuité d'identité | Tous les dérivés du même hôte/IP comptent comme une seule famille. |
| Handoff destination→source, sens réseau | Continuité technique directionnelle | Peut être distincte de l'identité si un vrai handoff directionnel est observé. |
| Protocoles et services | Contexte réseau | Protocole et service du même flux ne sont pas deux preuves indépendantes. |
| Signature, texte, étape, tactique | Comportement/progression | Étape et tactique dérivées de la signature appartiennent à la même famille. |
| Délai, fenêtre locale, gap de signature, densités | Temporalité/activité | Ce sont des représentations corrélées du temps; elles renforcent mais ne prouvent pas seules. |
| Capteurs distincts | Provenance | Renforcement utile, mais parfois corrélé à la signature ou au type de journal. |
| Plusieurs paires entre composantes | Redondance structurelle | Indépendantes seulement avec extrémités et ancres causales distinctes. |
| Votes et probabilités des huit modèles | Stabilité ML | Une seule famille : les modèles partagent données, variables et architecture. |
| Répétition d'une même alerte/signature | Volume | Ne crée aucune preuve supplémentaire. |

Les nombres `shared_entity_count`, `shared_host_count`, `shared_ip_count` et
`entity_jaccard` ne doivent donc jamais être additionnés comme quatre preuves.
De même, huit votes ML ne sont pas huit observations indépendantes.

## 3. Calcul proposé de la corroboration

Pour une union envisagée entre composantes `C1` et `C2` :

1. collecter toutes les relations consensuellement admissibles qui traversent
   actuellement la frontière `C1–C2`, pas seulement la prochaine arête triée ;
2. produire pour chaque relation un enregistrement observable : extrémités,
   entités normalisées, signature/étape, handoff, protocole/service, capteur et
   contexte temporel ;
3. dédupliquer les relations qui reposent sur la même paire d'extrémités, la
   même entité dominante et le même motif de signature/progression ;
4. regrouper les relations restantes en **paquets de preuve** ;
5. considérer deux paquets comme indépendants seulement s'ils n'utilisent pas
   le même pivot et ne répètent pas simultanément la même ancre d'identité et le
   même motif comportemental.

Exemples :

- trois relations utilisant des méta-alertes différentes mais toujours
  `192.168.128.1` et `2027863` forment un seul paquet ;
- deux relations passant par le même nœud DNS ou VPN forment un seul paquet ;
- deux relations avec extrémités disjointes, entités distinctes et transitions
  comportementales différentes peuvent former deux paquets.

La vérité terrain A/B n'intervient jamais dans ce calcul. Elle sert seulement à
évaluer ultérieurement les unions produites.

## 4. Cas des relations légitimes uniques

Une obligation absolue de deux arêtes supprimerait des transitions réelles.
Dans AIT, 260 vieux ponts sont des positives fortes :

- 260/260 ont une progression de phase compatible et une entité partagée ;
- 201/260 impliquent `A-All-Evt` ;
- 0/260 possèdent un handoff réseau, protocole ou service comme preuve
  technique supplémentaire.

Ainsi, une règle exigeant une preuve technique indépendante éliminerait au
moins une grande partie de ces relations fortes. Inversement, autoriser une
seule relation `progression compatible + entité partagée` laisserait passer les
mauvaises liaisons de `santos` et `wilson`.

Conclusion : avec les variables actuelles, certaines relations uniques sont
intrinsèquement ambiguës. Elles doivent être conservées comme arêtes souples,
mais ne devraient pas suffire seules à fusionner deux groupes. Cette décision
préserve leur traçabilité sans affirmer une appartenance commune non démontrée.

## 5. Trois mécanismes possibles

### Mécanisme 1 — Paquets indépendants avant union

Chaque relation du cœur et chaque pont ML reste candidat, dans l'ordre du
consensus. Une union forte exige au moins deux paquets indépendants à la
frontière. Les relations ne satisfaisant pas la condition restent souples.

Avantages :

- répond directement aux trois fusions observées ;
- traite le cœur et les ponts avec la même règle ;
- conserve toutes les relations comme preuves consultables ;
- ne nécessite ni modèle ni nouvelle caractéristique.

Risques :

- davantage de fragmentation dans les attaques contenant une transition unique ;
- définition trop stricte ou trop permissive de l'indépendance ;
- mise à jour dynamique des frontières après chaque union.

Coût : pré-calcul des clés de preuve en `O(E)`, puis DSU avec index de frontières
fusionné selon une stratégie small-to-large, approximativement `O(E log V)` et
mémoire `O(E)`. Une recherche naïve de toutes les arêtes après chaque union
serait trop coûteuse et doit être exclue.

### Mécanisme 2 — Audit des coupures probatoires après consensus

Construire le graphe consensuel, puis rechercher ses arêtes de coupure, nœuds
d'articulation et petits ensembles de coupure. Une coupure reposant sur un seul
paquet d'identité/comportement devient souple au lieu de déterminer la
composante connexe.

Avantages :

- traitement local après la forte reconnexion ;
- coût `O(V+E)` pour les ponts et articulations simples ;
- explique clairement pourquoi une composante est séparée.

Risques :

- les trois relations parallèles de `harrison` peuvent masquer les ponts
  individuels et nécessiter l'analyse d'un petit cut-set ;
- le calcul général de coupes multiples coûte plus cher ;
- une vraie transition unique peut être une articulation légitime.

### Mécanisme 3 — Quarantaine des connecteurs ambigus

Un nœud ou petit sous-graphe répétitif qui relie plusieurs régions uniquement
par une même entité, signature ou étape générique ne propage pas la composante
connexe. Ses arêtes sont conservées comme liens souples vers les régions.

Avantages :

- cible les pivots DNS/VPN de `santos` et `wilson` ;
- limite l'effet des alertes génériques et des infrastructures partagées ;
- modèle compréhensible pour un analyste SOC.

Risques :

- `A-All-Evt` apparaît aussi dans 201 positives fortes anciennes ;
- une quarantaine fondée uniquement sur une liste de signatures serait trop
  agressive ;
- nécessite de distinguer ambiguïté structurelle et simple fréquence élevée.

Coût : degré et diversité des voisinages calculables en `O(E)`, mais la
réévaluation après union ajoute une gestion d'état.

## 6. Stratégie recommandée

La première expérience hors ligne devrait porter sur le **mécanisme 1 : paquets
indépendants avant union, avec conservation des relations insuffisantes comme
arêtes souples**.

Raisons :

1. il traite exactement la cause commune aux trois fusions ;
2. il ne supprime pas les transitions longues ambiguës ;
3. il s'applique au cœur manuel et aux ponts ML ;
4. il préserve les gains du consensus là où plusieurs preuves indépendantes
   existent ;
5. ses décisions peuvent être expliquées et auditées relation par relation.

L'expérience devra comparer au minimum :

- baseline actuelle ;
- consensus avant forêt ;
- consensus avec deux paquets indépendants ;
- ablation où les arêtes souples sont supprimées, afin de mesurer leur utilité.

Les métriques doivent inclure la taille des fusions, pas seulement leur nombre,
la fragmentation, B-cubed, ARI, couverture des phases, conservation des
positives fortes, erreurs faibles et proportion d'arêtes devenues souples.

## 7. Validation scientifique future

AIT restera un jeu de développement exploratoire. Les paramètres et la
définition des paquets devront être figés avant toute validation indépendante.

La validation finale doit utiliser de nouveaux scénarios entièrement exclus de
l'entraînement et de la conception, comprenant :

- deux attaques simultanées partageant une infrastructure ;
- des alertes génériques et répétitives ;
- une vraie attaque avec transition unique séparée de plusieurs heures ;
- du bruit bénin sur les mêmes hôtes/IP ;
- plusieurs instances temporellement séparées.

SOCBED, DARPA et les anciens runs Wazuh ne doivent pas servir au choix de la
règle. Ils pourront seulement être utilisés après gel complet, selon un
protocole décidé séparément.
