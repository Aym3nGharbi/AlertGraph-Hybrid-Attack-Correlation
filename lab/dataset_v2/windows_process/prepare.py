"""Reservation et protocole Windows ; aucune connexion distante."""
from pathlib import Path
from ..io_utils import load_json, sha256_file
from ..prepare_campaign import verify_campaign_reservation


def validate(campaign):
    campaign = Path(campaign)
    manifest = verify_campaign_reservation(campaign)
    plan = load_json(campaign / 'campaign-plan.json')
    protocol = load_json(campaign / 'windows-protocol.json')
    seal = load_json(campaign / 'windows-protocol-seal.json')
    if manifest['partition'] != 'development' or plan['scenario_template'] != 'windows-parent-child-observability-v2':
        raise PermissionError('pilote development uniquement')
    if sha256_file(campaign / 'windows-protocol.json') != seal['sha256']:
        raise ValueError('protocole Windows altere')
    if protocol['plan_sha256'] != sha256_file(campaign / 'campaign-plan.json'):
        raise ValueError('plan Windows non conforme')
    for filename, digest in protocol['source_sha256'].items():
        if sha256_file(filename) != digest:
            raise ValueError('source Windows figee alteree: ' + filename)
    return plan, manifest, protocol
