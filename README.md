# AlertGraph — Hybrid Attack Correlation

AlertGraph est un projet académique de corrélation d'alertes de cybersécurité.
Il combine la **similarité observable** entre alertes et leur **compatibilité
causale** afin d'identifier les événements susceptibles d'appartenir à une même
attaque et de reconstruire leur progression sous forme de graphe explicable.

Le dépôt contient le moteur déterministe V1, le pipeline Machine Learning
évalué, les stratégies de reconstruction graphique, l'intégration Wazuh et les
fondations du dataset supervisé V2. Les datasets publics, modèles générés,
événements Wazuh réels et preuves du laboratoire ne sont pas publiés.

## Objectif scientifique

Une alerte isolée décrit rarement toute une attaque. AlertGraph cherche à :

1. normaliser des alertes hétérogènes ;
2. compresser les répétitions en méta-alertes sans perdre leur provenance ;
3. générer un ensemble borné de relations candidates ;
4. estimer leur corrélation par similarité, causalité ou approche hybride ;
5. regrouper les alertes corrélées et reconstruire un graphe d'incident ;
6. conserver une explication et une traçabilité jusqu'aux événements bruts.

Une relation de corrélation ne constitue pas automatiquement une preuve de
causalité directe. Le projet distingue les événements observés, les catégories
inférées et les relations prédites.

## Architecture

```text
Alertes IDS / Wazuh
        │
        ▼
Normalisation observable
        │
        ▼
Compression réversible en méta-alertes
        │
        ▼
Génération de candidats bornée
        │
        ├── Similarité : entités, texte, temps, contexte
        └── Causalité  : étapes observables et compatibilité technique
        │
        ▼
Score manuel ou classificateur hybride ML
        │
        ▼
Reconstruction du graphe et évaluation
        │
        ▼
Interface d'investigation locale
```

## État du projet

### AlertGraph V1

- moteur JavaScript déterministe de normalisation, scoring et regroupement ;
- fonction hybride manuelle `α × similarité + (1 − α) × causalité` ;
- `HistGradientBoostingClassifier` pour la classification hybride apprise ;
- validation imbriquée par scénario sur les huit scénarios AIT-ADS ;
- évaluations de développement sur AIT-ADS et analyses externes sur SOCBED et
  DARPA 2000 ;
- quatre stratégies de reconstruction graphique, avec conservation de la
  baseline scientifique dans le pipeline Wazuh ;
- interface locale de consultation progressive des incidents et événements.

Le protocole détaillé, les résultats et leurs limites sont documentés dans
[`docs/experimental-protocol.md`](docs/experimental-protocol.md).

### AlertGraph V2 — en développement

V2 vise une supervision plus fiable à partir d'activités contrôlées dans un
laboratoire Wazuh :

- schémas JSON versionnés et validateurs stricts ;
- séparation `development` / `validation` / `final-test` ;
- preuves d'exécution, provenance et empreintes SHA-256 ;
- décisions `member-verified`, `nonmember-verified` ou exclusion ;
- aucune utilisation des labels faibles pour l'apprentissage V2 ;
- audit temporel multi-échantillons avec incertitude mesurée ;
- capture TCP persistante et association déterministe événement–activité ;
- jointure de la vérité terrain après les transformations observables.

**ML V2 n'est pas entraîné et le dataset V2 n'est pas encore déclaré prêt pour
l'apprentissage (`training_ready: false`).**

Voir :

- [`docs/wazuh-supervised-dataset-v2-design.md`](docs/wazuh-supervised-dataset-v2-design.md) ;
- [`docs/alertgraph-v2-ml-roadmap.md`](docs/alertgraph-v2-ml-roadmap.md) ;
- [`docs/label-supervision-audit-v1.md`](docs/label-supervision-audit-v1.md).

## Organisation du dépôt

```text
config/             configuration non sensible et mapping Wazuh
data/               petit exemple synthétique uniquement
docs/               protocole et rapports scientifiques
lab/                orchestration du laboratoire et pipeline dataset V2
lab/dataset_v2/     schémas, validateurs, collecte et tests V2
ml/                 datasets, caractéristiques, modèles et graphes
public/             interface Web locale
src/                moteur déterministe et serveur Node.js
test/               tests du moteur JavaScript
```

Les répertoires `output/`, `data/external/`, `data/processed/` et `lab/runs/`
sont volontairement exclus de Git : ils peuvent contenir des datasets soumis à
leurs licences, des modèles générés ou des preuves réelles du laboratoire.

## Installation

### Prérequis

- Node.js 18 ou plus récent ;
- Python 3.10 ou plus récent ;
- PowerShell pour les exemples Windows du laboratoire.

### Environnement Python

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-ml.txt
python -m pip install -r lab/dataset_v2/requirements.txt
```

Les scripts utilisant AIT-ADS, SOCBED ou DARPA nécessitent que l'utilisateur
télécharge lui-même les datasets depuis leurs sources officielles et respecte
leurs licences.

## Démonstration locale

Exécuter le moteur déterministe sur l'exemple synthétique :

```powershell
node src/cli.js --input data/demo-alerts.json --output output/demo-report.json
```

Lancer l'interface Web :

```powershell
node src/server.js
```

Puis ouvrir <http://127.0.0.1:8080>.

Les runs réels ne sont pas fournis. L'interface les charge depuis `lab/runs/`
lorsqu'ils sont produits localement.

## Pipeline scientifique AIT-ADS

Après avoir placé les archives officielles dans `data/external/ait_ads/` :

```powershell
python ml/build_pair_dataset.py `
  data/external/ait_ads/ait_ads.zip `
  data/external/ait_ads/alerts_csv.zip `
  data/processed/ait_pairs_v1

python ml/evaluate_nested_baselines.py `
  data/processed/ait_pairs_v1 `
  --output output/nested-baselines.json

python ml/evaluate_nested_ml.py `
  data/processed/ait_pairs_v2 `
  --feature-profile directional `
  --output output/nested-ml.json
```

Les champs de vérité terrain sont séparés des caractéristiques observables et
ne participent pas à la génération des candidats ou au calcul des scores.

## Tests

```powershell
# Moteur JavaScript
node --test

# Pipeline ML
python -m unittest discover -s ml -p "test_*.py"

# Dataset supervisé V2
python -m unittest discover -s lab/dataset_v2 -p "test_*.py"
```

## Sécurité et données

- N'exécutez les scénarios de laboratoire que sur une infrastructure isolée et
  autorisée.
- Ne versionnez jamais de clé, mot de passe, token, événement Wazuh réel ou
  reçu d'exécution.
- Les identifiants de campagne, marqueurs et labels de supervision ne doivent
  jamais devenir des caractéristiques ML.
- Les annotations incertaines restent exclues au lieu d'être transformées en
  vérités artificielles.

## Limites actuelles

- La qualité des graphes dépend de la couverture des relations candidates et du
  mapping causal disponible.
- Une bonne classification pair-à-pair ne garantit pas une reconstruction
  parfaite : une arête incorrecte peut fusionner deux incidents et une arête
  manquante peut fragmenter une attaque.
- Les résultats AIT-ADS déjà consultés pendant la conception sont des résultats
  de développement, pas un test final totalement indépendant.
- La généralisation des seuils varie selon les environnements.
- V2 doit encore collecter suffisamment de négatifs forts et être validé sur
  des campagnes entièrement réservées avant tout réentraînement.

## Documentation scientifique

- [Protocole expérimental](docs/experimental-protocol.md)
- [Diagnostic des fusions et fragmentations](docs/graph-fusion-fragmentation-diagnostic.md)
- [Consensus avant forêt](docs/consensus-before-forest-experiment.md)
- [Conception multi-preuves](docs/multi-proof-component-union-design.md)
- [Audit de supervision V1](docs/label-supervision-audit-v1.md)
- [Conception du dataset Wazuh V2](docs/wazuh-supervised-dataset-v2-design.md)

## Utilisation responsable

Ce projet est destiné à la recherche, à l'enseignement et aux laboratoires de
cybersécurité autorisés. Les scripts de simulation ne doivent pas être utilisés
contre des systèmes tiers ou sans permission explicite.
