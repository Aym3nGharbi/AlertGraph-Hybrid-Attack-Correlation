"""Charge FIM synthétique locale ; aucune VM, vérité terrain ou donnée ML."""
import argparse
import json
from datetime import datetime,timezone
from pathlib import Path
from .evaluate_fim_compression import construct
from .evaluate_experimental_compression import measure,candidates
from .build_normalized_wazuh_cache import _normalize
from .io_utils import write_new_json,utc_now
from wazuh_dataset import normalize_wazuh_alert,load_stage_mapping


def synthetic_events(size,regime):
    if size<=0 or regime not in ('distinct-files','hot-file','instrumented-distinct-files'):
        raise ValueError('taille ou régime synthétique invalide')
    events=[]
    for i in range(size):
        rule,operation=(('554','added'),('550','modified'),('553','deleted'))[i%3]
        path='/srv/app/frequent.log' if regime=='hot-file' else (
            f'/srv/app/agv2-{i:024x}.txt' if regime=='instrumented-distinct-files' else f'/srv/app/file-{i:06d}.txt')
        events.append({'id':f'synthetic-{i:07d}','timestamp':datetime.fromtimestamp(1767225600+i*.001,timezone.utc).isoformat(),
            'agent':{'id':'synthetic-agent','name':'synthetic-host'},'rule':{'id':rule,'description':'Synthetic FIM operation'},
            'decoder':{'name':'syscheck'},'syscheck':{'path':path,'event':operation,'mode':'realtime'}})
    return events


def benchmark(sizes,emit=None):
    mapping=load_stage_mapping('config/wazuh-stage-mapping.json');results=[]
    for regime in ('distinct-files','hot-file','instrumented-distinct-files'):
        for size in sizes:
            raw=synthetic_events(size,regime);sanitized=[_normalize(e,[]) for e in raw]
            records=[normalize_wazuh_alert(e,mapping,run_id='synthetic-observable') for e in sanitized]
            for variant in ('C0','C1','C2','U'):
                metas,ccost=measure(lambda:construct(variant,records,raw,sanitized))
                generated,gcost=measure(lambda:candidates(metas))
                row={'regime':regime,'events':size,'compression':variant,'meta_count':len(metas),
                     'candidates':{g:len(edges) for g,edges in generated.items()},
                     'compression_cost':ccost,'generation_both_cost':gcost}
                assert sum(len(m.member_alert_ids) for m in metas)==size
                results.append(row)
                if emit:emit(row)
    return {'created_at_utc':utc_now(),'synthetic_only':True,'real_experimental_performance':False,
        'sizes':sizes,'rows':results,'time_layout':'dense 1 ms between events; same host',
        'resource_warning':'Output caps do not bound scanning/sorting time; ubiquitous entities can cause quadratic work.',
        'labels_used':False,'execution_authorized':False,'training_ready':False}


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--sizes',default='100,500,1500');args=p.parse_args()
    report=benchmark([int(n) for n in args.sizes.split(',')],emit=lambda r:print(json.dumps({'regime':r['regime'],'n':r['events'],'compression':r['compression'],'metas':r['meta_count'],'candidates':r['candidates'],'generation_ms':r['generation_both_cost']['elapsed_ms']}),flush=True))
    write_new_json(args.output,report)
