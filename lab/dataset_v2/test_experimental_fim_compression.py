import copy
import unittest
from lab.dataset_v2.experimental_fim_compression import compress_c2,file_context
from lab.dataset_v2.experimental_compression import compress,observable_rows
from lab.dataset_v2.build_normalized_wazuh_cache import _normalize
from lab.dataset_v2.compressed_provenance import audit_members
from lab.dataset_v2.strict_verified_pairs import label_verified_candidates
from lab.dataset_v2.evaluate_experimental_compression import candidates
from wazuh_dataset import normalize_wazuh_alert,load_stage_mapping


class FimCompressionTests(unittest.TestCase):
    def event(self,eid,path='/srv/app/report.txt',rule='550',op='modified',time='00.000'):
        return {'id':eid,'timestamp':'2026-11-16T00:00:'+time+'+00:00',
            'agent':{'id':'002','name':'host'},'manager':{'name':'manager'},
            'rule':{'id':rule,'description':'File integrity event'},'decoder':{'name':'syscheck'},
            'syscheck':{'path':path,'event':op,'mode':'realtime'},'full_log':'File integrity event'}

    def run_c2(self,events,markers=()):
        mapping=load_stage_mapping('config/wazuh-stage-mapping.json')
        records=[normalize_wazuh_alert(_normalize(e,list(markers)),mapping,run_id='observable-only') for e in events]
        return compress_c2(records,{str(e['id']):e for e in events})

    def test_distinct_arbitrary_files_simultaneously(self):
        events=[self.event('a','/var/app/a.cfg'),self.event('b','/srv/data/b.csv')]
        self.assertEqual(len(self.run_c2(events)),2)

    def test_same_file_repeats_and_rolling_gap(self):
        events=[self.event('a'),self.event('b',time='01.900'),self.event('c',time='03.800')]
        self.assertEqual(self.run_c2(events)[0].member_alert_ids,('a','b','c'))
        events.append(self.event('d',time='07.000'))
        self.assertEqual(len(self.run_c2(events)),2)

    def test_operations_and_agents_are_distinct(self):
        events=[self.event('a',rule='554',op='added'),self.event('b'),self.event('c',rule='553',op='deleted')]
        other=self.event('d');other['agent']['id']='003';events.append(other)
        self.assertEqual(len(self.run_c2(events)),4)

    def test_two_independent_activities_same_path_remain_excluded(self):
        events=[self.event('a'),self.event('b')];metas=self.run_c2(events)
        self.assertEqual(len(metas),1)
        decisions=[{'wazuh_alert_id':e,'activity_id':a,'decision':'member-verified','confidence':'verified'} for e,a in [('a','act:a'),('b','act:b')]]
        acts={'act:a':{'class':'attack','attack_instance_id':'attack:a'},'act:b':{'class':'benign','benign_activity_id':'benign:b'}}
        truth,excluded=audit_members(observable_rows(metas),decisions,acts)
        self.assertFalse(truth);self.assertEqual(list(excluded.values()),['mixed-or-invalid-provenance'])
        labelled,_=label_verified_candidates([{'earlier_meta_id':'meta-1','later_meta_id':'meta-1'}],truth)
        self.assertFalse(labelled)
        acts['act:b']={'class':'attack','attack_instance_id':'attack:b'}
        self.assertFalse(audit_members(observable_rows(metas),decisions,acts)[0])
        acts={'act:a':{'class':'benign','benign_activity_id':'benign:a'},'act:b':{'class':'benign','benign_activity_id':'benign:b'}}
        self.assertFalse(audit_members(observable_rows(metas),decisions,acts)[0])

    def test_missing_fields_are_singletons(self):
        for field in ('path','event','mode'):
            events=[self.event('a'),self.event('b')]
            for e in events:del e['syscheck'][field]
            self.assertEqual(len(self.run_c2(events)),2)
        events=[self.event('a'),self.event('b')]
        for e in events:e['agent']={}
        self.assertEqual(len(self.run_c2(events)),2)

    def test_ambiguous_or_conflicting_technical_fields(self):
        for edit in (lambda e:e['syscheck'].update(path=['/a','/b']),
                     lambda e:e['syscheck'].update(event='deleted'),
                     lambda e:e['syscheck'].update(mode=['realtime','scheduled']),
                     lambda e:e['agent'].update(id=['a','b']),
                     lambda e:e.update(manager=['a','b']),
                     lambda e:e['syscheck'].update(path='relative.txt')):
            events=[self.event('a'),self.event('b')]
            for e in events:edit(e)
            self.assertEqual(len(self.run_c2(events)),2)

    def test_inode_hashes_receipts_and_labels_do_not_partition(self):
        a=self.event('a');b=self.event('b')
        for i,e in enumerate((a,b)):
            e.update(activity_id=str(i),attack_instance_id=str(i),confidence=str(i),receipt={'id':i})
            e['syscheck'].update(sha256_after=str(i),inode_after=i)
        self.assertEqual(len(self.run_c2([a,b])),1)

    def test_path_identity_bijection_not_canary_semantics(self):
        events=[self.event('a','/srv/x.txt'),self.event('b','/srv/y.txt'),self.event('c','/srv/x.txt')]
        renamed=copy.deepcopy(events)
        for e in renamed:e['syscheck']['path']={'/srv/x.txt':'/unrelated/alpha.conf','/srv/y.txt':'/data/beta.json'}[e['syscheck']['path']]
        self.assertEqual([m.member_alert_ids for m in self.run_c2(events)],[m.member_alert_ids for m in self.run_c2(renamed)])

    def test_private_instrumentation_identity_not_exported_in_features(self):
        events=[self.event('a','/srv/secret-A.txt'),self.event('b','/srv/secret-B.txt')]
        metas=self.run_c2(events,markers=['secret-A','secret-B'])
        self.assertEqual(len(metas),2)
        import json
        exposed=json.dumps(observable_rows(metas))
        self.assertNotIn('secret-A',exposed);self.assertNotIn('secret-B',exposed)
        self.assertTrue(all('instrumentation_marker' in ' '.join(m.entities) for m in metas))

    def test_pid_in_fim_diff_is_not_a_writer_identity(self):
        a=self.event('a');b=self.event('b')
        a['full_log']='diff: sshd[100]';b['full_log']='diff: sshd[200]'
        self.assertEqual(len(self.run_c2([a,b])),1)

    def test_determinism_conservation_and_candidate_compatibility(self):
        events=[self.event('c','/z'),self.event('a','/a'),self.event('b','/a')]
        first=self.run_c2(events);second=self.run_c2(list(reversed(events)))
        self.assertEqual(observable_rows(first),observable_rows(second))
        self.assertEqual(sorted(e for m in first for e in m.member_alert_ids),['a','b','c'])
        self.assertEqual(set(candidates(first)),{'v2-0','v2-3'})

    def test_non_fim_parity_with_c1(self):
        events=[self.event('a'),self.event('b')]
        for i,e in enumerate(events):
            e.pop('syscheck');e['rule']['id']='5501';e['decoder']['name']='pam';e['full_log']=f'sshd[{10+i}]: session opened'
        mapping=load_stage_mapping('config/wazuh-stage-mapping.json')
        records=[normalize_wazuh_alert(e,mapping) for e in events];raw={e['id']:e for e in events}
        self.assertEqual(observable_rows(compress(records,raw,'B-observable-context-2s')),observable_rows(compress_c2(records,raw)))

    def test_linux_case_and_aliases_are_not_silently_equated(self):
        events=[self.event('a','/srv/A'),self.event('b','/srv/a'),self.event('c','/srv/sub/../a')]
        self.assertEqual(len(self.run_c2(events)),3)
        self.assertIsNotNone(file_context(self.event('w',r'C:\\Data\\audit.txt'))[0])

    def test_complete_offline_chain_does_not_export_benign_pairs(self):
        from lab.dataset_v2.evaluate_fim_compression import assess_variant
        events=[self.event('a','/data/alpha'),self.event('b','/data/beta')]
        decisions=[{'wazuh_alert_id':e,'activity_id':a,'decision':'member-verified','confidence':'verified'} for e,a in [('a','act:a'),('b','act:b')]]
        plan={'activities':[{'activity_id':'act:a','class':'benign','benign_activity_id':'benign:a','attack_instance_id':None},
                            {'activity_id':'act:b','class':'benign','benign_activity_id':'benign:b','attack_instance_id':None}]}
        metas=self.run_c2(events);value=assess_variant(plan,events,decisions,metas,candidates(metas))
        self.assertEqual(value['verified_fim_events_retained'],2)
        for gen in value['generators'].values():
            self.assertEqual(gen['benign_benign_not_supervised'],1)
            self.assertEqual(gen['training_pairs_exported'],0)
            self.assertIsNone(gen['positive_meta_recall'])

    def test_synthetic_load_inputs_have_no_truth(self):
        from lab.dataset_v2.benchmark_fim_compression import synthetic_events
        rows=synthetic_events(20,'distinct-files')
        self.assertEqual(len({r['syscheck']['path'] for r in rows}),20)
        self.assertEqual(len({r['syscheck']['path'] for r in synthetic_events(20,'hot-file')}),1)
        self.assertTrue(all('activity_id' not in r and 'target' not in r for r in rows))


if __name__=='__main__':unittest.main()
