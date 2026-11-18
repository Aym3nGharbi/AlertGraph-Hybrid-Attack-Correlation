"""Comparaison exploratoire de compressions, sans mutation d'une campagne."""
import argparse
import json
import time
import tracemalloc
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

import pyarrow.parquet as pq

from .experimental_compression import VARIANTS, compress, observable_context, observable_rows
from .build_normalized_wazuh_cache import _normalize, supervision_markers
from .compressed_provenance import audit_members
from .experimental_candidate_generators import ExperimentalCandidate, merge_candidates, corroborated_long_candidates
from .io_utils import load_json, sha256_file, utc_now, write_new_json, write_new_bytes
from .long_transition_audit import connected_components
from wazuh_dataset import normalize_wazuh_alert, load_stage_mapping
from candidates import iter_local_candidates
from causal_bridges import generate_causal_bridges


def jsonl(path):
    return [json.loads(line) for line in Path(path).read_bytes().splitlines() if line]


def candidates(metas):
    projected=[m.to_meta_alert() for m in metas]
    base=merge_candidates(*[[ExperimentalCandidate(c.earlier_meta_id,c.later_meta_id,c.delta_seconds,
          (c.source,),()) for c in rows] for rows in (
          list(iter_local_candidates(projected,60.,50)),generate_causal_bridges(projected,5))])
    rows=observable_rows(metas)
    v3=merge_candidates(base,corroborated_long_candidates(rows,max_age=180,min_bundles=4,per_alert_cap=3))
    return {'v2-0':base,'v2-3':v3}


def measure(factory):
    tracemalloc.start(); start=time.perf_counter(); cpu=time.process_time()
    value=factory()
    elapsed=time.perf_counter()-start; cpu=time.process_time()-cpu
    _,peak=tracemalloc.get_traced_memory(); tracemalloc.stop()
    return value,{'elapsed_ms':elapsed*1000,'cpu_ms':cpu*1000,'peak_python_kib':peak/1024}


def evaluate(run, output):
    plan=load_json(run/'campaign-plan.json')
    raw=jsonl(run/'raw/alerts.jsonl')
    # Ces copies observables neutralisées sont formées avant toute jointure GT.
    markers=supervision_markers(plan)
    sanitized=[_normalize(row,markers) for row in raw]
    raw_by_id={str(row['id']):row for row in sanitized}
    mapping=load_stage_mapping(Path('config/wazuh-stage-mapping.json'))
    records=[normalize_wazuh_alert(row,mapping,run_id='observable-only') for row in sanitized]
    records.sort(key=lambda r:(r.timestamp,r.alert_id))
    decisions_path=(run/'derived-revisions/bootid-uuid-20261115-001/event-decisions.jsonl'
        if 'benign-concurrent-ssh-pilot' in run.name else run/'supervision-input-multiphase-v2/event-decisions.jsonl')
    decisions=jsonl(decisions_path); decisions_by_id={d['wazuh_alert_id']:d for d in decisions}
    activities={a['activity_id']:a for a in plan['activities']}
    def identity(d):
        a=activities.get(d.get('activity_id'))
        if d.get('decision')!='member-verified' or not a: return None
        return (a['class'],a.get('attack_instance_id') or a.get('benign_activity_id'))
    verified_events={eid:identity(d) for eid,d in decisions_by_id.items() if identity(d)}
    positive_event_pairs=[(a,b) for a,b in combinations(sorted(verified_events),2)
        if verified_events[a]==verified_events[b] and verified_events[a][0]=='attack']
    variants={}; baseline_composition=None
    for variant in VARIANTS:
        metas,cost=measure(lambda:compress(records,raw_by_id,variant))
        rows=observable_rows(metas)
        member_ids=[eid for m in metas for eid in m.member_alert_ids]
        if len(member_ids)!=len(set(member_ids)) or set(member_ids)!=set(raw_by_id):
            raise ValueError('perte ou duplication de membre')
        truth,excluded=audit_members(rows,decisions,activities)
        retained={eid for m in metas if m.meta_id in truth for eid in m.member_alert_ids}
        mixed_instances=[]; mixed_activities=[]
        for m in metas:
            keys={verified_events[e] for e in m.member_alert_ids if e in verified_events}
            acts={decisions_by_id[e].get('activity_id') for e in m.member_alert_ids if e in verified_events}
            if len(keys)>1: mixed_instances.append(m.meta_id)
            if len(acts)>1: mixed_activities.append(m.meta_id)
        generated,gcost=measure(lambda:candidates(metas))
        meta_by_event={eid:m.meta_id for m in metas for eid in m.member_alert_ids}
        output.mkdir(parents=True,exist_ok=True)
        write_new_json(output/(variant+'-metas.json'),rows)
        generation={}
        for name,edges in generated.items():
            keys={frozenset((e.earlier_meta_id,e.later_meta_id)) for e in edges}
            pos=neg=unknown=benign=0; negatives=Counter(); positive_edges=[]
            for e in edges:
                left,right=truth.get(e.earlier_meta_id),truth.get(e.later_meta_id)
                if not left or not right: unknown+=1; continue
                if left['class']==right['class']=='benign': benign+=1; continue
                if left['class']==right['class']=='attack' and left['attack_instance_id']==right['attack_instance_id']:
                    pos+=1; positive_edges.append((e.earlier_meta_id,e.later_meta_id))
                else:
                    neg+=1
                    negatives['attack-attack' if left['class']==right['class']=='attack' else 'attack-benign']+=1
            positive_meta_reference=sum(1 for a,b in combinations(truth,2)
                if truth[a]['class']==truth[b]['class']=='attack' and truth[a]['attack_instance_id']==truth[b]['attack_instance_id'])
            covered=internal=0
            for a,b in positive_event_pairs:
                ma,mb=meta_by_event[a],meta_by_event[b]
                if ma not in truth or mb not in truth: continue
                if ma==mb: internal+=1
                elif frozenset((ma,mb)) in keys: covered+=1
            fragment={}
            for attack in sorted({t['attack_instance_id'] for t in truth.values() if t['class']=='attack'}):
                nodes=[key for key,t in truth.items() if t.get('attack_instance_id')==attack]
                comps=connected_components(nodes,positive_edges)
                fragment[attack]={'nodes':len(nodes),'candidate_components':len(comps),'isolated':sum(len(c)==1 for c in comps)}
            generation[name]={'candidates':len(edges),'positive_candidates':pos,'negative_candidates':neg,
                'negative_categories':dict(negatives),'unknown_candidates':unknown,
                'benign_benign_candidates_not_supervised':benign,
                'positive_meta_reference':positive_meta_reference,
                'positive_meta_recall':pos/positive_meta_reference if positive_meta_reference else None,
                'fixed_positive_event_reference':len(positive_event_pairs),
                'positive_event_relations_exposed_by_candidates':covered,
                'positive_event_relations_internal_to_verified_meta':internal,
                'fixed_event_pair_candidate_coverage':covered/len(positive_event_pairs) if positive_event_pairs else None,
                'candidate_connectivity_not_predicted_attack_graph':fragment}
            write_new_json(output/(variant+'-'+name+'-candidates.json'),[e.__dict__ for e in edges])
        per_activity=Counter()
        for m in metas:
            for act in {decisions_by_id[e].get('activity_id') for e in m.member_alert_ids if e in verified_events}:
                per_activity[act]+=1
        membership=[{'meta_id':m.meta_id,'members':list(m.member_alert_ids),
            'sensor':m.sensor,'signature':m.signature,'entities':m.entities,'stage':m.observed_stage,
            'eligible':m.meta_id in truth,'exclusion_reason':excluded.get(m.meta_id),
            'observable_details':[{'id':e,'context':observable_context(raw_by_id[e]),
                'fields_available':sorted(raw_by_id[e].get('data',{}))} for e in m.member_alert_ids]} for m in metas]
        write_new_json(output/(variant+'-provenance.json'),membership)
        if variant==VARIANTS[0]:
            baseline_composition=[sorted(m.member_alert_ids) for m in metas]
        variants[variant]={'meta_alerts':len(metas),'verified_meta_alerts':len(truth),
            'mixed_inter_identity_metas':len(mixed_instances),'mixed_activity_metas':len(mixed_activities),
            'verified_events_retained':len(retained),'verified_events_lost_for_supervision':len(verified_events)-len(retained),
            'raw_events_lost':0,'singleton_metas':sum(len(m.member_alert_ids)==1 for m in metas),
            'nodes_per_verified_activity':dict(per_activity),'compression_cost':cost,
            'both_generators_cost':gcost,'generators':generation,
            'same_metas_for_v2_0_and_v2_3':True}
    historical_cache=next((run/'derived-cache').glob('*/meta_observable.parquet'))
    existing=pq.read_table(historical_cache).to_pylist()
    parity=sorted(baseline_composition)==sorted(sorted(r['member_alert_ids']) for r in existing)
    if not parity: raise ValueError('baseline compressée différente du cache historique')
    return {'campaign':plan['campaign_id'],'raw_events':len(raw),'verified_events':len(verified_events),
        'annotation_source':str(decisions_path),'annotation_sha256':sha256_file(decisions_path),
        'raw_sha256':sha256_file(run/'raw/alerts.jsonl'),'historical_baseline_membership_parity':parity,
        'field_availability':dict(Counter(quality for row in sanitized for _,quality in [observable_context(row)])),
        'variants':variants,'truth_used_only_after_compression':True,'training_ready':False}


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(); args.output.mkdir(parents=True,exist_ok=False)
    root=Path('output/wazuh-supervised-v2/campaigns')
    prefixes=('dev-benign-concurrent-ssh-pilot-','dev-prod-d1-','dev-prod-d2-','dev-prod-d3-','dev-prospective-l1-')
    runs=[r for c in sorted(root.iterdir()) if c.name.startswith(prefixes) for r in sorted(c.iterdir()) if (r/'raw/alerts.jsonl').exists()]
    results=[evaluate(run,args.output/run.parent.name) for run in runs]
    write_new_json(args.output/'comparison.json',{'created_at_utc':utc_now(),'campaigns':results,
        'exploratory_development_only':True,'model_retrained':False,'deployed':False,
        'execution_authorized':False,'training_ready':False})
    print(json.dumps([{'campaign':r['campaign'],'variants':{v:{k:x[k] for k in ('meta_alerts','verified_meta_alerts','mixed_inter_identity_metas','verified_events_retained')} for v,x in r['variants'].items()}} for r in results],indent=2))


if __name__=='__main__': main()
