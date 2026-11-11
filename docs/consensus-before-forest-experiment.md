# Expérience : consensus avant la forêt

Date : 9 novembre 2026  
Statut : expérience AIT de développement, non activée dans Wazuh

## Décision

La variante réduit fortement la fragmentation, conserve davantage de relations
positives fortes et améliore les métriques moyennes de regroupement. Cependant,
elle agrandit fortement les trois fusions déjà présentes. Elle ne satisfait donc
pas la contrainte « réduire la fragmentation sans faciliter les fusions ».

**Décision recommandée : conserver la baseline scientifique actuelle.**

## Méthodes comparées

### Baseline inchangée

Chaque modèle figé construit son propre graphe : cœur manuel, puis ponts ML
ordonnés par sa probabilité. Les huit décisions graphiques sont ensuite agrégées
par vote `>= 4/8`, sans suppression de cycle après le vote.

### Variante expérimentale

1. Une relation appartient au cœur consensuel si elle appartient au cœur dans
   au moins quatre modèles.
2. Une relation devient candidate comme pont si elle est admissible, comme cœur
   ou comme pont causalement compatible, dans au moins quatre modèles.
3. Les ponts sont ordonnés par :
   - nombre de votes d'admissibilité décroissant ;
   - probabilité moyenne des huit modèles décroissante ;
   - position originale de la paire croissante, pour les égalités.
4. Une seule forêt de ponts est construite au-dessus de toutes les composantes
   du cœur consensuel.

Le nombre de votes est prioritaire parce qu'il représente l'accord entre les
modèles. La probabilité moyenne sert uniquement à ordonner les candidats déjà
admissibles. Aucun nouveau seuil n'est introduit.

Les seuils relationnels, seuils de pont, règles manuelles, compatibilités
causales, modèles, caractéristiques et mappings restent inchangés.

## Statut méthodologique

Deux résultats doivent être séparés :

- **référence réellement hors-fold** : pour chaque scénario, le seul modèle
  dont l'entraînement excluait ce scénario ;
- **comparaison exploratoire à huit modèles** : baseline contre consensus, avec
  sept modèles susceptibles d'avoir déjà vu le scénario.

Le consensus à huit modèles ne peut pas être évalué réellement hors-fold avec
les artefacts actuels sans réentraîner d'autres ensembles, ce qui était interdit.
Les résultats du consensus ne sont donc pas des performances indépendantes de
généralisation.

SOCBED, DARPA et Wazuh n'ont été ni consultés ni utilisés pour choisir la règle.
Aucun paramètre n'a été sélectionné après observation des résultats.

## Résultats exploratoires sur les huit scénarios

| Mesure | Baseline 8 forêts puis vote | Consensus puis forêt | Écart |
|---|---:|---:|---:|
| Arêtes sélectionnées | 243 049 | 279 070 | +36 021 |
| Positives fortes conservées | 214 963 | 245 967 | +31 004 |
| Négatives faibles sélectionnées | 24 950 | 29 662 | +4 712 |
| Scénarios avec fusion | 3 | 3 | 0 |
| B-cubed attaques | 0,289 | 0,468 | +0,179 |
| ARI attaques | 0,115 | 0,163 | +0,048 |
| Fragments par attaque | 2 349,2 | 381,9 | -1 967,3 |
| Couverture du plus grand fragment | 0,253 | 0,356 | +0,103 |
| Couverture des types de phases | 0,852 | 0,891 | +0,039 |
| Rappel des alertes par phase | 0,294 | 0,376 | +0,081 |

La fragmentation moyenne baisse de 83,7 %. Aucune des 54 négatives fortes
disponibles n'est sélectionnée par la variante. L'augmentation des erreurs
mesurées concerne uniquement des annotations négatives faibles.

## Résultats détaillés des cinq scénarios

| Scénario | Fragments baseline → consensus | B-cubed attaques | ARI attaques | Rappel phases | Positives fortes | Négatives faibles |
|---|---:|---:|---:|---:|---:|---:|
| `harrison` | 16 129,5 → 1 148,0 | 0,020 → 0,615 | 0,000 → 0,140 | 0,131 → 0,285 | 62 158 → 91 995 | 1 803 → 3 034 |
| `santos` | 944,0 → 291,0 | 0,007 → 0,434 | 0,000 → 0,025 | 0,271 → 0,664 | 25 122 → 26 256 | 1 720 → 2 030 |
| `wilson` | 913,0 → 864,0 | 0,367 → 0,414 | 0,248 → 0,289 | 0,232 → 0,245 | 43 026 → 43 036 | 5 801 → 6 952 |
| `fox` | 253,0 → 246,0 | 0,667 → 0,681 | 0,227 → 0,240 | 0,384 → 0,392 | 43 161 → 43 166 | 2 027 → 2 381 |
| `wheeler` | 193,0 → 180,5 | 0,690 → 0,726 | 0,267 → 0,306 | 0,317 → 0,338 | 39 628 → 39 636 | 5 653 → 6 009 |

La stratégie atteint son objectif de reconnexion, surtout sur `harrison` et
`santos`. Elle améliore également les cinq B-cubed et ne crée aucun nouveau
scénario fusionné.

## Sévérité des fusions

Le seul comptage des composantes fusionnées masque un effet dangereux : les
liaisons erronées déjà présentes rejoignent maintenant des fragments beaucoup
plus grands.

| Scénario | Composantes fusionnées | Méta-alertes d'attaque fusionnées, baseline → consensus | Non-attaque absorbées |
|---|---:|---:|---:|
| `harrison` | 1 → 1 | 2 → 8 920 | 0 → 79 |
| `santos` | 1 → 1 | 87 → 2 581 | 2 → 150 |
| `wilson` | 1 → 1 | 1 184 → 1 275 | 351 → 360 |
| `fox` | 0 → 0 | 0 → 0 | 0 → 0 |
| `wheeler` | 0 → 0 | 0 → 0 | 0 → 0 |

Dans `harrison`, la composante fusionnée passe de `{1 A, 1 B}` à `{60 A,
8 860 B}`. Dans `santos`, elle passe de `{3 A, 84 B}` à `{3 A, 2 578 B}`.

Conclusion vérifiée : le consensus ne crée pas une nouvelle fusion au sens du
compteur, mais facilite considérablement la propagation des fusions existantes.
L'amélioration de B-cubed ne suffit pas à rendre ce risque acceptable.

## Référence hors-fold

| Scénario | B-cubed attaques hors-fold | Fragments hors-fold | Fusions |
|---|---:|---:|---:|
| `harrison` | 0,947 | 896,0 | 1 |
| `santos` | 0,440 | 293,5 | 1 |
| `wilson` | 0,414 | 851,5 | 1 |
| `fox` | 0,681 | 238,0 | 0 |
| `wheeler` | 0,725 | 180,5 | 0 |

Ces valeurs reproduisent exactement les résultats AIT hors-fold déjà enregistrés
dans `output/manual-core-ml-bridges.json`. Elles sont fournies comme référence,
pas comme comparaison statistiquement équitable avec le consensus exploratoire.

## Tests synthétiques et non-régression

Les tests vérifient que :

- des ponts alternatifs éliminés par le vote après forêt sont récupérés ;
- toutes les arêtes du cœur consensuel sont conservées ;
- la forêt n'ajoute pas de cycle entre composantes du cœur ;
- le nombre de votes précède la probabilité moyenne dans l'ordre ;
- une relation sous le quorum est rejetée ;
- une mauvaise relation atteignant le quorum peut encore être retenue, limite
  explicitement documentée.

Résultat : 6/6 tests ciblés et 101/101 tests complets réussis.

## Conclusion

1. **Réduction de la fragmentation : oui, très forte.**
2. **Conservation des positives fortes : oui.**
3. **Amélioration des métriques de reconstruction : oui, exploratoire.**
4. **Absence d'aggravation des fusions : non.** Leur nombre reste stable, mais
   leur taille augmente fortement.

La variante ne doit pas être intégrée à Wazuh. La baseline reste la méthode
active. Si les recherches continuent, l'étape logique suivante serait de tester
le consensus avec une validation observable des fusions de composantes par
preuves multiples, comme expérience séparée et sans modifier la baseline.
