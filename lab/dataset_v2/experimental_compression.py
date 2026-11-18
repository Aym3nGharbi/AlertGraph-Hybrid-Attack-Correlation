"""Variantes de compression hors ligne ; aucune vérité n'entre dans la partition."""
import re
from collections import defaultdict
from dataclasses import asdict, replace

from .build_normalized_wazuh_cache import ML_ROOT  # rend les modules historiques importables
from audit_pair_candidates import collapse_labeled_records, add_observable_context

VARIANTS = ('A-historical-2s', 'B-observable-context-2s', 'C-conservative-2s', 'D-uncompressed')
PID = re.compile(r'\bsshd\[(\d+)\]')


def observable_context(raw):
    """Uniquement des champs d'alerte ; jamais reçus, marqueurs ou annotations."""
    data=raw.get('data') or {}
    event=(data.get('win') or {}).get('eventdata') or {}
    pids=set(PID.findall(str(raw.get('full_log') or '')))
    family=str((raw.get('decoder') or {}).get('name') or '')
    host=str((raw.get('agent') or {}).get('id') or (raw.get('agent') or {}).get('name') or '')
    if len(pids)>1:
        return ('contradictory-pids',), 'conflict'
    if str((raw.get('rule') or {}).get('id')) in {'5712','40112'}:
        return ('aggregate-rule',), 'aggregate'
    protocol=str(data.get('protocol') or data.get('proto') or '')
    service=str(data.get('service') or data.get('app_proto') or '')
    if len(pids)==1:
        return ('sshd-pid',host,next(iter(pids)),family,protocol,service), 'process'
    if event.get('processGuid'):
        return ('observed-guid',host,str(event['processGuid']).casefold(),family), 'process'
    if data.get('srcip') and data.get('srcport') and host:
        return ('observed-source-endpoint',host,str(data['srcip']),str(data['srcport']),
                str(data.get('dstip') or ''),str(data.get('dstport') or ''),protocol,service), 'network'
    return (), 'missing'


def compress(records, raw_by_id, variant):
    if variant not in VARIANTS: raise ValueError('variante inconnue')
    records=sorted(records,key=lambda r:(r.timestamp,r.alert_id))
    if variant==VARIANTS[0]:
        return add_observable_context(collapse_labeled_records(records,2.))
    partitions=defaultdict(list)
    for record in records:
        context,quality=observable_context(raw_by_id[record.alert_id])
        if variant==VARIANTS[3] or quality in {'conflict','aggregate'} or (variant==VARIANTS[2] and quality=='missing'):
            key=('single-event',record.alert_id)
        else:
            key=context
        partitions[key].append(record)
    metas=[]
    for values in partitions.values():
        metas.extend(collapse_labeled_records(values,2.))
    metas.sort(key=lambda m:(m.first_timestamp,m.member_alert_ids))
    return add_observable_context([replace(meta,meta_id=f'meta-{i}') for i,meta in enumerate(metas,1)])


def observable_rows(metas):
    fields=('meta_id','first_timestamp','last_timestamp','sensor','signature','signature_text','entities',
            'member_alert_ids','observed_stage','protocols','services','observed_tactics','src_ips','dst_ips',
            'min_severity','max_severity','prior_entity_density_2s','prior_entity_density_10s',
            'prior_entity_density_60s','prior_entity_density_150s','seconds_since_same_signature_entity')
    return [{name:getattr(meta,name) for name in fields} for meta in metas]
