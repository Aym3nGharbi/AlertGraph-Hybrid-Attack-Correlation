import copy
import json
import tempfile
import unittest
from pathlib import Path
from .sudo_evidence_adapter import associate_sudo_event, observable_projection, review_bundle, COMMAND, COMMAND_SHA256
from .io_utils import write_new_json,write_new_bytes,sha256_file


class SudoProofTests(unittest.TestCase):
    def fixture(self):
        boot='11111111-1111-4111-8111-111111111111'
        socket={'source_ip':'192.0.2.1','source_port':40000,'target_ip':'192.0.2.2','target_port':22}
        body='labuser : TTY=unknown ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/true'
        alert={'id':'synthetic-event','timestamp':'2026-11-16T09:00:03+00:00',
               'agent':{'name':'linux-agent'},'rule':{'id':'5402','description':'sudo command'},
               'full_log':'Nov 16 09:00:02 ubuntu sudo[123]: '+body}
        journal=[{'__CURSOR':'synthetic-cursor','__REALTIME_TIMESTAMP':'1794819602000000',
                  '_PID':'123','_BOOT_ID':boot,'_COMM':'sudo','_HOSTNAME':'ubuntu',
                  '_AUDIT_LOGINUID':'1000','_AUDIT_SESSION':'7','MESSAGE':body}]
        receipt={'activity_id':'synthetic-benign-activity','command_argv':list(COMMAND),
                 'command_sha256':COMMAND_SHA256,'boot_id':boot,'sudo_pid':123,
                 'agent_name':'linux-agent','hostname':'ubuntu','sudo_start_ticks':100,
                 'target_process_pid':120,'target_process_start_ticks':90,'sshd_pid':110,
                 'controller_socket':socket,'target_ssh_connection':dict(socket),'ssh_client_pid':55,
                 'audit_session':'7','login_uid':1000,'started_at_utc':'2026-11-16T09:00:01+00:00',
                 'ended_at_utc':'2026-11-16T09:00:04+00:00',
                 'collection_started_at_utc':'2026-11-16T09:00:00+00:00',
                 'collection_ended_at_utc':'2026-11-16T09:00:10+00:00'}
        process=[{'pid':123,'boot_id':boot,'start_ticks':100,'ppid':120,
                  'parent_start_ticks':90,'parent_ppid':110,'observed_at_utc':'2026-11-16T09:00:02+00:00'}]
        sockets=[{'pid':55,'status':'ESTABLISHED',**socket}]
        return [alert,journal,[receipt],process,sockets]

    def test_complete_independent_chain(self):
        args=self.fixture();before=copy.deepcopy(args)
        self.assertEqual(associate_sudo_event(*args)['decision'],'member-verified')
        self.assertEqual(args,before)

    def test_time_host_command_or_success_without_process_not_enough(self):
        args=self.fixture();args[3]=[]
        self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')
        args=self.fixture();args[0]['full_log']=args[0]['full_log'].replace('sudo[123]','sudo')
        self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')

    def test_pid_reuse_wrong_boot_lineage_and_session_rejected(self):
        for field,value in [('start_ticks',999),('ppid',999),('parent_ppid',999),('boot_id','00000000-0000-0000-0000-000000000001')]:
            with self.subTest(field=field):
                args=self.fixture();args[3][0][field]=value
                self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')
        args=self.fixture();args[1][0]['_AUDIT_SESSION']='8'
        self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')

    def test_conflicting_receipts_and_duplicate_cursor(self):
        args=self.fixture();other=copy.deepcopy(args[2][0]);other['activity_id']='other';args[2].append(other)
        self.assertEqual(associate_sudo_event(*args)['reason'],'multiple-receipt-identities')
        args=self.fixture();args[1]*=2
        self.assertEqual(associate_sudo_event(*args)['reason'],'duplicate-journal-cursor')

    def test_missing_command_refusal_is_not_verified(self):
        args=self.fixture();args[1][0]['MESSAGE']='a password is required'
        args[0]['full_log']='sudo[123]: a password is required'
        self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')

    def test_wrong_command_and_private_receipt_fields_cannot_help(self):
        args=self.fixture();args[2][0]['command_argv']=['sudo','id'];args[2][0]['confidence']='verified'
        self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')

    def test_stale_wazuh_and_future_observations_rejected(self):
        args=self.fixture();args[0]['timestamp']='2025-11-16T09:00:03+00:00'
        self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')
        args=self.fixture();args[3][0]['observed_at_utc']='2026-11-16T10:00:00+00:00'
        self.assertEqual(associate_sudo_event(*args)['decision'],'excluded')

    def test_feature_projection_has_no_truth_or_private_payload(self):
        args=self.fixture();alert=args[0];before=copy.deepcopy(alert)
        features=observable_projection(alert)
        alert.update(campaign_id='private-campaign',target=1,evidence_ids=['secret-proof'])
        alert['full_log']='secret private receipt'
        self.assertEqual(observable_projection(alert),features)
        alert['rule']['description']='sudo agv2-abcdef123456'
        self.assertNotIn('agv2-abcdef',str(observable_projection(alert)))
        self.assertEqual(before['full_log'],args[1][0]['MESSAGE'].join(['Nov 16 09:00:02 ubuntu sudo[123]: ', '']))

    def test_unknown_never_becomes_negative(self):
        args=self.fixture();args[2]=[]
        decision=associate_sudo_event(*args)
        self.assertEqual(decision['decision'],'excluded')
        self.assertNotIn('target',decision)

    def bundle(self, root):
        args=self.fixture();entries=[]
        for role,values in zip(('wazuh-events','journal-events','execution-receipts','process-observations','socket-observations'),
                               ([args[0]],args[1],args[2],args[3],args[4])):
            path=root/(role+'.jsonl')
            write_new_bytes(path,b''.join((json.dumps(v)+'\n').encode() for v in values))
            entries.append({'role':role,'path':path.name,'sha256':sha256_file(path)})
        write_new_json(root/'sudo-proof-bundle.json',{'schema_version':'alertgraph-sudo-proof-bundle/1.0-experimental','files':entries})

    def test_local_bundle_integrity_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.bundle(root)
            result=review_bundle(root,root/'decisions.json')
            self.assertEqual(result['event_decisions'][0]['decision'],'member-verified')
            with self.assertRaises(FileExistsError):review_bundle(root,root/'decisions.json')

    def test_altered_bundle_rejected_before_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.bundle(root)
            with (root/'process-observations.jsonl').open('ab') as stream:stream.write(b'{}\n')
            with self.assertRaisesRegex(ValueError,'alteree'):review_bundle(root,root/'decisions.json')
            self.assertFalse((root/'decisions.json').exists())


if __name__=='__main__':unittest.main()
