"""C2 hors ligne : identité de fichier observée, sans identité d'activité.

Les records dérivés restent neutralisés pour les features. L'égalité du chemin
brut sert seulement de frontière de compression, sans exporter la clé. Elle ne
prouve ni une attaque commune ni l'identité d'un processus écrivain.
"""
import ntpath
from collections import defaultdict
from dataclasses import replace

from .experimental_compression import observable_context
from .build_normalized_wazuh_cache import ML_ROOT
from audit_pair_candidates import collapse_labeled_records,add_observable_context

NAME='C2-fim-path-operation-2s'
RULE_OPERATIONS={'554':'added','550':'modified','553':'deleted'}


def is_fim(raw):
    rule=raw.get('rule')
    return 'syscheck' in raw or (isinstance(rule,dict) and str(rule.get('id')) in RULE_OPERATIONS)


def file_context(raw):
    """Identité exacte et conservatrice ; pas de résolution de chemin hors ligne."""
    sc=raw.get('syscheck');agent=raw.get('agent');rule=raw.get('rule')
    if not isinstance(sc,dict) or not isinstance(agent,dict) or not isinstance(rule,dict):
        return None,'missing-or-invalid-structure'
    path=sc.get('path');operation=sc.get('event');mode=sc.get('mode');rid=str(rule.get('id'))
    if not isinstance(path,str) or not path or '\x00' in path or not (path.startswith('/') or ntpath.isabs(path)):
        return None,'missing-or-ambiguous-path'
    if rid not in RULE_OPERATIONS or operation!=RULE_OPERATIONS[rid]:
        return None,'missing-or-conflicting-rule-operation'
    if not isinstance(mode,str) or mode not in {'realtime','scheduled','whodata'}:
        return None,'missing-or-unknown-observation-mode'
    aid=agent.get('id');host=agent.get('name')
    if any(v is not None and not isinstance(v,str) for v in (aid,host)) or not (aid or host):
        return None,'missing-or-ambiguous-agent'
    # Casse, liens et '..' conservés : aucune équivalence de fichiers supposée.
    # Aucun contenu/hash, PID extrait de diff, annotation ou token interprété.
    manager_raw=raw.get('manager')
    if manager_raw is not None and not isinstance(manager_raw,dict):return None,'ambiguous-manager'
    manager=(manager_raw or {}).get('name') or ''
    if not isinstance(manager,str):return None,'ambiguous-manager'
    return ('fim-file',manager,aid or '',host or '',path,operation,rid,mode),'observed-file-operation'


def compress_c2(records,raw_by_id):
    records=sorted(records,key=lambda r:(r.timestamp,r.alert_id))
    if len({r.alert_id for r in records})!=len(records):raise ValueError('identifiants dupliqués')
    partitions=defaultdict(list)
    for record in records:
        raw=raw_by_id[record.alert_id]
        if is_fim(raw):
            context,quality=file_context(raw)
            key=context if context is not None else ('single-event',record.alert_id)
        else:
            context,quality=observable_context(raw)
            key=('single-event',record.alert_id) if quality in {'conflict','aggregate'} else ('c1',context)
        partitions[key].append(record)
    metas=[]
    for values in partitions.values():metas.extend(collapse_labeled_records(values,2.0))
    metas.sort(key=lambda m:(m.first_timestamp,m.member_alert_ids))
    return add_observable_context([replace(m,meta_id=f'meta-{i}') for i,m in enumerate(metas,1)])
