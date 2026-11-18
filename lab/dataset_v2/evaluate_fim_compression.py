"""Comparaison C0/C1/C2/U sur copies locales des campagnes de développement."""
import argparse
import csv
import io
import json
from collections import Counter
from itertools import combinations
from pathlib import Path

from .experimental_fim_compression import compress_c2,file_context,is_fim
from .experimental_compression import compress,observable_rows
from .evaluate_experimental_compression import candidates,measure
from .build_normalized_wazuh_cache import _normalize,supervision_markers
from .compressed_provenance import audit_members
from .long_transition_audit import connected_components
from .io_utils import load_json,sha256_file,sha256_bytes,canonical_json_bytes,utc_now,write_new_json,write_new_bytes
from wazuh_dataset import normalize_wazuh_alert,load_stage_mapping

PREFIXES=('dev-benign-fim-concurrent-pilot-','dev-benign-concurrent-ssh-pilot-',
          'dev-prod-d1-','dev-prod-d2-','dev-prod-d3-','dev-prospective-l1-',
          'dev-attack-ssh-fim-multiphase-')
VARIANTS={'C0':'A-historical-2s','C1':'B-observable-context-2s','C2':None,'U':'D-uncompressed'}


def jsonl(path):return [json.loads(line) for line in Path(path).read_bytes().splitlines() if line]


def load_inputs(run):
    plan=load_json(run/'campaign-plan.json')
    if plan['partition']!='development':raise ValueError('development uniquement')
    raw=jsonl(run/'raw/alerts.jsonl')
    if len({str(e['id']) for e in raw})!=len(raw):raise ValueError('événements dupliqués')
    options=[run/'supervision-concurrent-fim-pilot-v2/report.json',
             run/'derived-revisions/bootid-uuid-20261115-001/event-decisions.jsonl',
             run/'supervision-input-multiphase-v2/event-decisions.jsonl']
    annotation=next((p for p in options if p.exists()),None)
    if annotation is None:raise FileNotFoundError('annotations strictes absentes')
    decisions=load_json(annotation)['event_decisions'] if annotation.suffix=='.json' else jsonl(annotation)
    if {str(d['wazuh_alert_id']) for d in decisions}!={str(e['id']) for e in raw}:
        raise ValueError('annotations ne couvrant pas exactement le brut')
    sanitized=[_normalize(row,supervision_markers(plan)) for row in raw]
    mapping=load_stage_mapping('config/wazuh-stage-mapping.json')
    records=[normalize_wazuh_alert(row,mapping,run_id='observable-only') for row in sanitized]
    return plan,raw,sanitized,records,decisions,annotation


def construct(name,records,raw,sanitized):
    if name=='C2':return compress_c2(records,{str(e['id']):e for e in raw})
    return compress(records,{str(e['id']):e for e in sanitized},VARIANTS[name])


def assess_variant(plan,raw,decisions,metas,generated):
    rows=observable_rows(metas);acts={a['activity_id']:a for a in plan['activities']}
    truth,excluded=audit_members(rows,decisions,acts)
    by_id={str(d['wazuh_alert_id']):d for d in decisions}
    # Vérifiés par l'audit existant ; une annotation faible ne devient pas forte.
    verified={eid:d['activity_id'] for eid,d in by_id.items() if d.get('decision')=='member-verified'
        and d.get('confidence','verified')=='verified' and d.get('activity_id') in acts
        and len((d.get('correlated_rule_context') or {}).get('context_identities') or [])<=1}
    fim_ids={str(e['id']) for e in raw if is_fim(e)}
    retained={e for m in metas if m.meta_id in truth for e in m.member_alert_ids}
    assert len([e for m in metas for e in m.member_alert_ids])==len(raw)
    assert {e for m in metas for e in m.member_alert_ids}==set(by_id)
    mixed=sum(len({acts[verified[e]]['attack_instance_id'] or acts[verified[e]]['benign_activity_id'] for e in m.member_alert_ids if e in verified})>1 for m in metas)
    positive_events=[(a,b) for a,b in combinations(sorted(verified),2)
        if acts[verified[a]]['class']==acts[verified[b]]['class']=='attack'
        and acts[verified[a]]['attack_instance_id']==acts[verified[b]]['attack_instance_id']]
    meta_by_event={e:m.meta_id for m in metas for e in m.member_alert_ids}
    positive_meta_reference=sum(1 for a,b in combinations(truth.values(),2)
        if a['class']==b['class']=='attack' and a['attack_instance_id']==b['attack_instance_id'])
    metrics={}
    for gen,edges in generated.items():
        pos=neg=unknown=benign=0;categories=Counter();positive_edges=[]
        for edge in edges:
            a,b=truth.get(edge.earlier_meta_id),truth.get(edge.later_meta_id)
            if not a or not b:unknown+=1
            elif a['class']==b['class']=='benign':benign+=1
            elif a['class']==b['class']=='attack' and a['attack_instance_id']==b['attack_instance_id']:
                pos+=1;positive_edges.append((edge.earlier_meta_id,edge.later_meta_id))
            else:
                neg+=1;categories['attack-attack' if a['class']==b['class']=='attack' else 'attack-benign']+=1
        keys={frozenset((e.earlier_meta_id,e.later_meta_id)) for e in edges}
        exposed=internal=0
        for a,b in positive_events:
            ma,mb=meta_by_event[a],meta_by_event[b]
            if ma not in truth or mb not in truth:continue
            if ma==mb:internal+=1
            elif frozenset((ma,mb)) in keys:exposed+=1
        fragments={}
        for attack in sorted({a['attack_instance_id'] for a in acts.values() if a['class']=='attack'}):
            nodes=[m for m,v in truth.items() if v['attack_instance_id']==attack]
            components=connected_components(nodes,positive_edges)
            fragments[attack]={'retained_nodes':len(nodes),'candidate_components':len(components),
                'isolated_nodes':sum(len(c)==1 for c in components),'retained_nodes_connected':len(components)==1,
                'verified_attack_events':sum(acts[a]['attack_instance_id']==attack for a in verified.values())}
        metrics[gen]={'candidates':len(edges),'positive':pos,'negative':neg,'negative_categories':dict(categories),
            'unknown':unknown,'benign_benign_not_supervised':benign,'training_pairs_exported':0,
            'positive_meta_reference':positive_meta_reference,'positive_meta_recall':pos/positive_meta_reference if positive_meta_reference else None,
            'fixed_positive_event_reference':len(positive_events),'positive_event_pairs_exposed':exposed,
            'positive_event_pairs_internal_to_verified_meta':internal,
            'fixed_event_pair_candidate_coverage':exposed/len(positive_events) if positive_events else None,
            'fixed_event_pair_represented_fraction':(exposed+internal)/len(positive_events) if positive_events else None,
            'candidate_connectivity_not_predicted_graph':fragments}
    return {'meta_count':len(metas),'verified_meta_count':len(truth),'mixed_meta_count':mixed,
        'excluded_meta_count':len(excluded),'verified_events':len(verified),'verified_events_retained':len(retained),
        'verified_fim_events':len(set(verified)&fim_ids),'verified_fim_events_retained':len(retained&fim_ids),
        'verified_fim_meta_count':sum(any(e in fim_ids for e in m.member_alert_ids) for m in metas if m.meta_id in truth),
        'meta_exclusions':excluded,'generators':metrics,'raw_events_lost':0}


def evaluate(run,output):
    plan,raw,sanitized,records,decisions,annotation=load_inputs(run)
    output.mkdir(parents=True,exist_ok=False)
    variants={}
    for name in VARIANTS:
        metas,cost=measure(lambda:construct(name,records,raw,sanitized))
        generated,gcost=measure(lambda:candidates(metas))
        value=assess_variant(plan,raw,decisions,metas,generated)
        value.update(compression_cost=cost,generation_both_cost=gcost,
                     same_meta_input_for_generators=True)
        rows=observable_rows(metas)
        for marker in supervision_markers(plan):
            if marker.casefold() in json.dumps(rows).casefold():raise ValueError('fuite instrumentale dans les métas')
        write_new_json(output/(name+'-metas.json'),rows)
        for gen,edges in generated.items():
            write_new_json(output/(name+'-'+gen+'-candidates.json'),[e.__dict__ for e in edges])
        variants[name]=value
    # C0/C1 du dernier pilote doivent être reproduites exactement.
    previous=run/'supervision-concurrent-fim-pilot-v2/report.json'
    if previous.exists():
        old=load_json(previous)['compression_comparison']
        for name in ('C0','C1'):
            assert canonical_json_bytes(load_json(output/(name+'-metas.json')))==canonical_json_bytes(old[name]['metas'])
            for gen in ('v2-0','v2-3'):
                assert canonical_json_bytes(load_json(output/(name+'-'+gen+'-candidates.json')))==canonical_json_bytes(old[name]['generators'][gen]['candidates'])
    return {'campaign':plan['campaign_id'],'run':str(run),'raw_events':len(raw),'raw_sha256':sha256_file(run/'raw/alerts.jsonl'),
        'annotation_source':str(annotation),'annotation_sha256':sha256_file(annotation),'variants':variants,
        'file_context_quality':dict(Counter(file_context(e)[1] for e in raw if is_fim(e))),
        'development_exploratory_only':True,'execution_authorized':False,'training_ready':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    args.output.mkdir(parents=True,exist_ok=False)
    root=Path('output/wazuh-supervised-v2/campaigns')
    runs=[r for c in sorted(root.iterdir()) if c.name.startswith(PREFIXES) for r in sorted(c.iterdir()) if (r/'raw/alerts.jsonl').exists()]
    # Empreintes antérieures à l'expérience, y compris résultats et plans scellés.
    immutable=[p for run in runs for p in run.rglob('*') if p.is_file()]
    immutable+=list(Path('lab/dataset_v2/plans').glob('*.json'))
    immutable+=[Path('lab/dataset_v2')/n for n in ('experimental_compression.py','experimental_candidate_generators.py','evaluate_experimental_compression.py')]
    before={str(p):sha256_file(p) for p in immutable}
    write_new_json(args.output/'source-integrity-before.json',before)
    results=[]
    for run in runs:
        value=evaluate(run,args.output/run.parent.name);results.append(value)
        print(json.dumps({'campaign':value['campaign'],'variants':{n:{k:v[k] for k in ('meta_count','verified_meta_count','mixed_meta_count','verified_fim_events_retained')} for n,v in value['variants'].items()}}),flush=True)
    assert all(sha256_file(path)==digest for path,digest in before.items())
    write_new_json(args.output/'comparison.json',{'created_at_utc':utc_now(),'campaigns':results,'source_files_unchanged':len(before),
        'model_trained':False,'deployed':False,'execution_authorized':False,'training_ready':False})
    buffer=io.StringIO(newline='');fields=['campaign','compression','generator','metas','verified_metas','mixed_metas','fim_retained','candidates','positive','negative','unknown','positive_meta_recall','fixed_event_pair_candidate_coverage'];writer=csv.DictWriter(buffer,fieldnames=fields);writer.writeheader()
    for r in results:
        for name,v in r['variants'].items():
            for g,m in v['generators'].items():writer.writerow({'campaign':r['campaign'],'compression':name,'generator':g,'metas':v['meta_count'],'verified_metas':v['verified_meta_count'],'mixed_metas':v['mixed_meta_count'],'fim_retained':v['verified_fim_events_retained'],**{k:m[k] for k in fields if k in m}})
    write_new_bytes(args.output/'comparison.csv',buffer.getvalue().encode())


if __name__=='__main__':main()
