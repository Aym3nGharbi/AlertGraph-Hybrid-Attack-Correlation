# Feuille de route ML AlertGraph V2

Statut au 11 novembre 2026 : feuille de route scientifique uniquement. Aucun
réentraînement, aucun changement de V1 et aucune activation en production.

## Objectif

Le futur ML V2 continuera de prédire si deux alertes appartiennent à la même
instance d'attaque. L'association événement–activité sert à construire une
supervision fiable ; elle ne crée pas automatiquement une paire positive,
notamment entre événements bénins.

## Axes d'enrichissement à étudier

1. Améliorer la similarité entre les **messages** d'alertes avec :
   - une représentation TF-IDF renforcée ;
   - des Sentence Transformers ;
   - des embeddings comparés par similarité cosinus.
2. Étudier une normalisation textuelle plus robuste : valeurs volatiles,
   marqueurs d'instrumentation, identifiants, chemins, adresses et ports.
   Les événements Wazuh bruts restent intacts ; seule la vue dérivée destinée
   aux caractéristiques est normalisée.
3. Étudier séparément l'enrichissement des entités et du contexte MITRE
   ATT&CK.
4. Étudier des caractéristiques de compatibilité technique entre services,
   processus, authentifications, flux et comportements observés.

Les embeddings améliorent uniquement la composante textuelle de similarité.
Ils ne décident jamais seuls qu'une paire est corrélée et ne remplacent ni les
autres similarités, ni la compatibilité causale.

## Protocole d'ablation futur

Chaque famille sera comparée séparément puis par combinaisons :

- baseline V1 ;
- TF-IDF amélioré seul ;
- embeddings seuls pour le message ;
- normalisation textuelle seule ;
- entités/contexte MITRE seuls ;
- compatibilité technique seule ;
- combinaisons présélectionnées sur développement et validation.

Les modèles, seuils et mappings seront gelés avant les campagnes de test
indépendantes. Aucune donnée `final-test` ne servira au choix des paramètres.

## Données et comparaison V1/V2

Le futur entraînement utilisera AIT-ADS enrichi uniquement par des campagnes
Wazuh suffisamment supervisées. Les campagnes sont séparées avant exécution
en développement, validation et test. V1 et V2 seront comparés sur les mêmes
campagnes indépendantes avec : métriques relationnelles, B-cubed, ARI,
fragmentation, fusions et couverture des phases.

## Conditions avant entraînement

- plusieurs instances d'une même attaque réellement contrôlées ;
- attaques distinctes, attaque–bénin et bénin–bénin vérifiés ;
- transitions longues, activités simultanées et bruit bénin ;
- couverture suffisante des alertes Windows et Linux ;
- conflits et inconnus conservés ;
- audit des fuites de supervision réussi ;
- `training_ready` reste `false` jusqu'à une décision scientifique explicite.
