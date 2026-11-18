"""Post-traitement local strict du pilote parent-enfant, jamais de label faible."""
from collections import Counter
from pathlib import Path
import json

from .events import associate, verify_evidence
from .prepare import validate
from ..collect_campaign import verify_collection
from ..io_utils import load_json, write_new_json, write_new_bytes, sha256_file, utc_now
from ..build_normalized_wazuh_cache import _normalize, supervision_markers
from ..evaluate_fim_compression import construct, assess_variant
from ..evaluate_experimental_compression import candidates, measure
from ..experimental_compression import observable_rows
from wazuh_dataset import load_stage_mapping, normalize_wazuh_alert


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_bytes().splitlines() if line]


def analyze(campaign):
    campaign = Path(campaign); plan, _, protocol = validate(campaign)
    verify_collection(campaign)
    execution = campaign / 'windows-execution'
    for name, digest in load_json(execution / 'execution-seal.json')['files_sha256'].items():
        path = (execution / name).resolve()
        if not path.is_relative_to(execution.resolve()) or sha256_file(path) != digest:
            raise ValueError('preuve execution Windows alteree')
    source = verify_evidence(execution / 'source')
    target = load_json(execution / 'target-response.json')
    receipt = dict(target['receipt'])
    # Attribution d'identite apres capture, jamais dans la commande ni les features.
    receipt['activity_id'] = plan['activities'][0]['activity_id']
    raw = jsonl(campaign / 'raw/alerts.jsonl')
    decisions = [{'wazuh_alert_id': e['id'], **associate(e, source, receipt,
        target['kernel_observations'], agent=protocol['agent_name'],
        profile=protocol['wazuh_string_profile'])} for e in raw]
    def original_key(event):
        s=((event.get('data') or {}).get('win') or {}).get('system') or {}
        return tuple(str(s.get(k,'')) for k in ('providerGuid','computer','channel','eventRecordID','eventID','systemTime'))
    duplicates=Counter(original_key(e) for e in raw)
    for event,decision in zip(raw,decisions):
        if decision['decision']=='member-verified' and duplicates[original_key(event)]>1:
            decision.update(decision='excluded',activity_id=None,confidence=None,reason='duplicate-Wazuh-original-record')
    output = campaign / 'windows-analysis'
    write_new_bytes(output / 'event-decisions.jsonl', b''.join((json.dumps(d) + '\n').encode() for d in decisions))
    roles = {d.get('process_role') for d in decisions if d['decision'] == 'member-verified'}
    report = {'created_at_utc': utc_now(), 'events': len(raw), 'decisions': dict(Counter(d['decision'] for d in decisions)),
        'both_parent_child_Wazuh_proven': roles == {'parent', 'child'},
        'original_xml_sources': len(source), 'training_pairs_exported': 0,
        'weak_labels_used': False, 'execution_authorized': False, 'training_ready': False}
    write_new_json(output / 'report.json', report)
    if not report['both_parent_child_Wazuh_proven']:
        return report
    sanitized = [_normalize(e, supervision_markers(plan)) for e in raw]
    mapping = load_stage_mapping('config/wazuh-stage-mapping.json')
    records = [normalize_wazuh_alert(e, mapping, run_id='observable-only') for e in sanitized]
    if 58 * len(raw) > 200000:
        raise ValueError('budget de candidats depasse; differer sans tronquer')
    variants = {}
    for name in ('C0', 'C1', 'C2', 'U'):
        metas, compression_cost = measure(lambda: construct(name, records, raw, sanitized))
        generated, generation_cost = measure(lambda: candidates(metas))
        scored = assess_variant(plan, raw, decisions, metas, generated)
        rows = observable_rows(metas)
        if any(marker.casefold() in json.dumps(rows).casefold() for marker in supervision_markers(plan)):
            raise ValueError('fuite de marqueur dans les observables')
        value = {k: scored[k] for k in ('meta_count','verified_meta_count','excluded_meta_count','mixed_meta_count','verified_events_retained','raw_events_lost')}
        value.update(compression_cost=compression_cost, generation_both_cost=generation_cost, generators={})
        for gen, edges in generated.items():
            metrics = scored['generators'][gen]
            if metrics['positive'] or metrics['negative']:
                raise ValueError('supervision attaque interdite dans ce pilote benin')
            value['generators'][gen] = {k: metrics[k] for k in ('candidates','unknown','benign_benign_not_supervised','training_pairs_exported')}
            write_new_json(output / (name + '-' + gen + '-candidates.json'), [e.__dict__ for e in edges])
        write_new_json(output / (name + '-metas.json'), rows)
        variants[name] = value
    write_new_json(output / 'comparison.json', {'variants': variants,
        'raw_sha256': sha256_file(campaign / 'raw/alerts.jsonl'),
        'annotation_sha256': sha256_file(output / 'event-decisions.jsonl'),
        'attack_metrics_computed': False, 'training_pairs_exported': 0, 'training_ready': False})
    return report
