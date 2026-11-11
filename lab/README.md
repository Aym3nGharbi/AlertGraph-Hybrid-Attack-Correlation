# Laboratoire Wazuh

Ce dossier contient uniquement l'orchestration et les manifestes du laboratoire.
Les identifiants et mots de passe ne doivent jamais être écrits dans le dépôt.

## Flux d'un run

1. créer un identifiant de run et enregistrer les horodatages UTC de chaque étape ;
2. exécuter le scénario contrôlé ;
3. attendre la latence Wazuh déclarée dans le manifeste ;
4. exporter `alerts.json` avec `collect_wazuh.py` ;
5. construire le cache avec `ml/build_wazuh_lab_cache.py` ;
6. appliquer l'ensemble gelé avec `ml/predict_wazuh_lab.py` ;
7. annoter les alertes réellement dues aux actions à partir des marqueurs, hôtes et temps ;
8. évaluer les trois graphes sans modifier le test final.

Le mapping causal utilise la politique `unknown-is-neutral`. Une règle Wazuh non
reconnue n'est donc jamais transformée en incompatibilité causale.
