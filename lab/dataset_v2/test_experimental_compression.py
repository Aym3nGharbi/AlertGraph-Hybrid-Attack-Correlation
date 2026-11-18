import copy
import unittest
from dataclasses import replace

from lab.dataset_v2.experimental_compression import compress, observable_context, observable_rows, VARIANTS
from lab.dataset_v2.evaluate_experimental_compression import candidates
from lab.dataset_v2.build_normalized_wazuh_cache import ML_ROOT
from lab.dataset_v2.compressed_provenance import audit_members
from wazuh_dataset import load_stage_mapping, normalize_wazuh_alert


class ExperimentalCompressionTests(unittest.TestCase):
    def event(self, key, pid=None, rule='5501'):
        return {'id':key,'timestamp':'2026-11-15T00:00:00.000+00:00',
                'agent':{'id':'002','name':'host'},'decoder':{'name':'pam'},
                'rule':{'id':rule,'description':'session opened'},
                'data':{'srcip':'192.0.2.1','dstip':'192.0.2.20'},
                'full_log':f'sshd[{pid}]: session opened' if pid else 'session opened'}

    def run_variant(self, events, name=VARIANTS[1]):
        mapping=load_stage_mapping('config/wazuh-stage-mapping.json')
        records=[normalize_wazuh_alert(row,mapping,run_id='fixture') for row in events]
        return compress(records,{r['id']:r for r in events},name)

    def test_same_ip_distinct_pids_separate_and_same_pid_repeats_compress(self):
        events=[self.event('a',100),self.event('b',200),self.event('c',100)]
        self.assertEqual(len(self.run_variant(events,VARIANTS[0])),1)
        self.assertEqual(sorted(sorted(m.member_alert_ids) for m in self.run_variant(events)),[['a','c'],['b']])

    def test_missing_context_conservative_and_uncompressed_controls(self):
        events=[self.event('a'),self.event('b')]
        self.assertEqual(len(self.run_variant(events,VARIANTS[1])),1)
        self.assertEqual(len(self.run_variant(events,VARIANTS[2])),2)
        self.assertEqual(len(self.run_variant(events,VARIANTS[3])),2)

    def test_contradictory_pids_and_aggregate_rules_are_not_merged(self):
        events=[self.event('a',100),self.event('b',100)]
        for e in events: e['full_log']='sshd[100]: message sshd[200]: other'
        self.assertEqual(len(self.run_variant(events)),2)
        self.assertEqual(observable_context(events[0])[1],'conflict')
        for e in events: e['rule']['id']='5712'
        self.assertEqual(len(self.run_variant(events)),2)

    def test_truth_and_private_identifiers_do_not_affect_compression(self):
        events=[self.event('a',100),self.event('b',100)]
        changed=copy.deepcopy(events)
        changed[0].update(attack_instance_id='A1',campaign_id='one',confidence='verified')
        changed[1].update(attack_instance_id='A2',campaign_id='two',confidence='unknown')
        self.assertEqual(observable_rows(self.run_variant(events)),observable_rows(self.run_variant(changed)))

    def test_mixed_or_technical_provenance_is_still_excluded(self):
        events=[self.event('a',100),self.event('b',100)]
        metas=observable_rows(self.run_variant(events))
        acts={'x':{'class':'attack','attack_instance_id':'a1'},'y':{'class':'attack','attack_instance_id':'a2'}}
        decisions=[{'wazuh_alert_id':'a','activity_id':'x','decision':'member-verified'},
                   {'wazuh_alert_id':'b','activity_id':'y','decision':'member-verified'}]
        truth,excluded=audit_members(metas,decisions,acts)
        self.assertFalse(truth); self.assertEqual(len(excluded),1)
        decisions[1]['decision']='nonmember-verified'
        self.assertFalse(audit_members(metas,decisions,acts)[0])

    def test_deterministic_preservation_and_generator_compatibility(self):
        events=[self.event('b',200),self.event('a',100)]
        for variant in VARIANTS:
            a=self.run_variant(events,variant); b=self.run_variant(list(reversed(events)),variant)
            self.assertEqual(observable_rows(a),observable_rows(b))
            self.assertEqual(sorted(e for m in a for e in m.member_alert_ids),['a','b'])
            generated=candidates(a)
            self.assertEqual(set(generated),{'v2-0','v2-3'})

    def test_pid_is_only_context_not_an_ml_entity(self):
        metas=self.run_variant([self.event('a',123456)])
        self.assertFalse(any('123456' in e for m in metas for e in m.entities))

    def test_observed_ports_distinguish_sessions_without_inventing_destination(self):
        events=[self.event('a'),self.event('b')]
        events[0]['data']['srcport']='42001'; events[1]['data']['srcport']='42002'
        self.assertEqual(len(self.run_variant(events)),2)
        self.assertEqual(observable_context(events[0])[1],'network')

    def test_canary_and_supervision_tokens_are_not_context_keys(self):
        a=self.event('a'); b=self.event('b')
        a['syscheck']={'path':'/opt/marker-A1.txt','sha256_after':'private-A1'}
        b['syscheck']={'path':'/opt/marker-A2.txt','sha256_after':'private-A2'}
        self.assertEqual(observable_context(a),observable_context(b))

    def test_historical_two_seconds_is_a_rolling_gap_not_a_total_span(self):
        events=[self.event(str(i),100) for i in range(3)]
        for event,time in zip(events,('00.000','01.900','03.800')):
            event['timestamp']='2026-11-15T00:00:'+time+'+00:00'
        metas=self.run_variant(events,VARIANTS[0])
        self.assertEqual(len(metas),1)
        self.assertGreater(metas[0].last_timestamp-metas[0].first_timestamp,3.7)


if __name__=='__main__': unittest.main()
