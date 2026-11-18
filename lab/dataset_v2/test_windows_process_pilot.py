"""Tests synthetiques Windows V2 ; aucun processus experimental ni reseau."""
import copy
from datetime import datetime, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from .windows_process import events, run as runner, analysis
from .io_utils import write_new_bytes, write_new_json, sha256_file


def fixture():
    sources=[]; receipts={}; observations=[]
    for role,pid,pg,parentguid,stamp in (
        ('parent',100,'00000000-0000-0000-0000-000000000100','00000000-0000-0000-0000-000000000099','2026-11-17 09:00:00.123'),
        ('child',101,'00000000-0000-0000-0000-000000000101','00000000-0000-0000-0000-000000000100','2026-11-17 09:00:00.456')):
        data={'UtcTime':stamp,'ProcessGuid':'{'+pg+'}','ProcessId':str(pid),
            'Image':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
            'CommandLine':'powershell.exe -NoProfile -EncodedCommand SYNTHETIC_'+role,
            'User':r'LAB\runner','ParentProcessGuid':'{'+parentguid+'}',
            'ParentProcessId':str(pid-1),'ParentImage':r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'}
        source={'provider':events.PROVIDER,'provider_guid':events.PROVIDER_GUID,'event_id':1,
            'record_id':str(pid),'computer':'LAB-WIN','channel':events.CHANNEL,
            'system_time':'2026-11-17T09:00:01.0000000Z','data':data}
        sources.append(source)
        receipts[role]={'pid':pid,'creation_filetime':events.filetime(stamp),'image':data['Image'],
            'command_line':data['CommandLine'],'exit_code':0}
        observations.append({'role':role,'pid':pid,'creation_filetime':events.filetime(stamp),
            'observed_filetime':events.filetime(stamp)+100,'image':data['Image'],
            'computer':'LAB-WIN','live_handle_retained':True})
    receipt={'status':'completed','activity_id':'synthetic-benign','computer':'LAB-WIN',
        'wrapper':{'pid':99},'parent':receipts['parent'],'child':receipts['child'],
        'gate':{'independent_identity_checked_before_release':True},'cleanup':{'confirmed_stopped':True}}
    alerts=[]
    for i,source in enumerate(sources):
        s={'providerName':events.PROVIDER,'providerGuid':'{'+events.PROVIDER_GUID+'}',
            'eventID':'1','computer':source['computer'],'channel':source['channel'],
            'eventRecordID':source['record_id'],'systemTime':source['system_time']}
        data={k[0].lower()+k[1:]:json.dumps(v,ensure_ascii=False)[1:-1] for k,v in source['data'].items()}
        alerts.append({'id':'synthetic-'+str(i),'timestamp':'2026-11-17T09:00:01+00:00',
            'agent':{'id':'001','name':'windows-agent'},'rule':{'id':'92052','description':'Sysmon Process Create','level':5},
            'data':{'win':{'system':s,'eventdata':data}}})
    return alerts,sources,receipt,observations


def xml_bytes(source):
    tag=lambda name:'{'+events.NS['e']+'}'+name
    root=ET.Element(tag('Event'));system=ET.SubElement(root,tag('System'))
    ET.SubElement(system,tag('Provider'),{'Name':source['provider'],'Guid':'{'+source['provider_guid']+'}'})
    for name,value in [('EventID',source['event_id']),('EventRecordID',source['record_id']),('Computer',source['computer']),('Channel',source['channel'])]:
        ET.SubElement(system,tag(name)).text=str(value)
    ET.SubElement(system,tag('TimeCreated'),{'SystemTime':source['system_time']})
    data=ET.SubElement(root,tag('EventData'))
    for name,value in source['data'].items():ET.SubElement(data,tag('Data'),{'Name':name}).text=value
    return ET.tostring(root,encoding='utf-8')


class AttributionTests(unittest.TestCase):
    def decide(self,args,index=1):
        alerts,sources,receipt,observations=args
        return events.associate(alerts[index],sources,receipt,observations,agent='windows-agent')

    def test_parent_child_complete_chain_without_mutation(self):
        args=fixture();before=copy.deepcopy(args)
        for i,role in enumerate(('parent','child')):
            result=self.decide(args,i)
            self.assertEqual(result['decision'],'member-verified');self.assertEqual(result['process_role'],role)
            self.assertFalse(result['features_updated'])
        self.assertEqual(args,before)

    def test_pid_birth_handle_and_host_contradictions_excluded(self):
        for name,value in [('pid',999),('creation_filetime',999),('live_handle_retained',False),('computer','OTHER')]:
            args=fixture();args[3][1][name]=value
            with self.subTest(name=name):self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_parent_guid_parent_pid_and_command_contradictions(self):
        for name,value in [('ParentProcessGuid','00000000-0000-0000-0000-000000000999'),('ParentProcessId','999'),('CommandLine','another command')]:
            args=fixture();args[1][1]['data'][name]=value
            self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_two_sources_same_birth_different_guid_ambiguous(self):
        args=fixture();other=copy.deepcopy(args[1][1]);other['record_id']='999';other['data']['ProcessGuid']='00000000-0000-0000-0000-000000000999';args[1].append(other)
        self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_same_binary_simultaneous_different_pid_not_assigned(self):
        args=fixture();other=copy.deepcopy(args[1][1]);other['record_id']='999';other['data']['ProcessId']='222';other['data']['ProcessGuid']='00000000-0000-0000-0000-000000000999';args[1].append(other)
        self.assertEqual(self.decide(args)['decision'],'member-verified')
        args[0][1]['data']['win']['eventdata']['processId']='222'
        self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_xml_wazuh_key_data_or_whitespace_difference_excluded(self):
        for where,field,value in [('system','eventRecordID','999'),('system','computer','OTHER'),
                                  ('eventdata','commandLine','wrong'),('eventdata','image','wrong')]:
            args=fixture();args[0][1]['data']['win'][where][field]=value
            self.assertEqual(self.decide(args)['decision'],'excluded')
        args=fixture();args[0][1]['data']['win']['eventdata']['commandLine']+=' '
        self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_no_per_field_favorable_serialization_fallback(self):
        args=fixture();args[0][1]['data']['win']['eventdata']['image']=args[1][1]['data']['Image']
        self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_duplicates_missing_proofs_and_failed_gate_excluded(self):
        args=fixture();args[1].append(copy.deepcopy(args[1][1]));self.assertEqual(self.decide(args)['decision'],'excluded')
        args=fixture();args[3].pop();self.assertEqual(self.decide(args)['decision'],'excluded')
        args=fixture();args[2]['gate']['independent_identity_checked_before_release']=False;self.assertEqual(self.decide(args)['decision'],'excluded')
        args=fixture();args[2]['cleanup']['confirmed_stopped']=False;self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_event11_and_unattributed_background_not_negative(self):
        args=fixture();args[0][1]['data']['win']['system']['eventID']='11'
        result=self.decide(args);self.assertEqual(result['decision'],'excluded');self.assertNotIn('target',result)

    def test_unknown_receipt_label_cannot_fix_missing_proof(self):
        args=fixture();args[2].update(confidence='verified',attack_instance_id='private');args[3].clear()
        self.assertEqual(self.decide(args)['decision'],'excluded')

    def test_source_timestamp_precision_is_integer_and_not_tolerance(self):
        n=events.filetime('2026-11-17 09:00:00.1234567')
        self.assertEqual(n%10000000,1234567)
        self.assertEqual(events.filetime('2026-11-17T09:00:00.1234567Z'),n)
        args=fixture();args[1][1]['data']['UtcTime']='2026-11-17 09:00:00.457'
        self.assertEqual(self.decide(args)['decision'],'excluded')


class CollectionTests(unittest.TestCase):
    def bundle(self,root):
        source=fixture()[1][0];p=root/'event.xml';write_new_bytes(p,xml_bytes(source))
        evtx=root/'events.evtx';write_new_bytes(evtx,b'SYNTHETIC-EXPORT-NOT-A-REAL-EVTX')
        entries=[{'path':p.name,'kind':'event-xml-rendering','bytes':p.stat().st_size,'sha256':sha256_file(p)},
                 {'path':evtx.name,'kind':'evtx-export','bytes':evtx.stat().st_size,'sha256':sha256_file(evtx)}]
        write_new_json(root/'source-manifest.json',{'complete':True,'evtx_xml_verified_on_controller':True,'files':entries})
        return p

    def test_xml_preserved_and_hashes_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);p=self.bundle(root);before=p.read_bytes()
            self.assertEqual(len(events.verify_evidence(root)),1);self.assertEqual(p.read_bytes(),before)
            with p.open('ab') as f:f.write(b' ')
            with self.assertRaisesRegex(ValueError,'alteree'):events.verify_evidence(root)

    def test_xml_dtd_entities_and_duplicate_fields_rejected(self):
        with self.assertRaises(ValueError):events.parse_xml(b'<!DOCTYPE x []><x/>')
        source=fixture()[1][0];raw=xml_bytes(source)
        tree=ET.fromstring(raw);data=tree.find('e:EventData',events.NS);data.append(copy.deepcopy(data[0]))
        with self.assertRaisesRegex(ValueError,'duplique'):events.parse_xml(ET.tostring(tree))

    def test_unverified_export_and_path_escape_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.bundle(root);p=root/'source-manifest.json';d=json.loads(p.read_text());d['evtx_xml_verified_on_controller']=False;p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):events.verify_evidence(root)
            d['evtx_xml_verified_on_controller']=True;d['files'][0]['path']='../outside.xml';p.write_text(json.dumps(d))
            with self.assertRaises(ValueError):events.verify_evidence(root)


class RunnerTests(unittest.TestCase):
    def test_preview_never_connects_or_starts_process(self):
        with patch.object(runner,'validate',return_value=({}, {}, {})),patch.object(runner.subprocess,'run') as process:
            result=runner.run('synthetic')
        process.assert_not_called();self.assertFalse(result['execution_authorized'])

    def test_existing_execution_blocks_before_network(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);(root/'windows-execution').mkdir()
            with patch.object(runner,'validate',return_value=({}, {}, {})),patch.object(runner.subprocess,'run') as process:
                with self.assertRaises(FileExistsError):runner.run(root,execute_authorized=True)
            process.assert_not_called()

    def test_missing_credentials_and_stale_clock_block_before_launch(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            with patch.object(runner,'validate',return_value=({}, {}, {})),patch.object(runner.subprocess,'run') as process:
                with self.assertRaises(FileNotFoundError):runner.run(root,execute_authorized=True)
                cred=root/'cred';cred.write_bytes(b'SYNTHETIC');key=root/'key';key.write_bytes(b'SYNTHETIC')
                with patch.object(runner,'require_clock_ready',return_value={'created_at_utc':'2020-01-01T00:00:00+00:00','measurements':[]}):
                    with self.assertRaisesRegex(RuntimeError,'audit frais'):runner.run(root,credential_file=cred,key=key,execute_authorized=True)
            process.assert_not_called()

    def test_unknown_remote_cleanup_remains_explicit_in_source(self):
        text=Path(runner.__file__).with_name('target.ps1').read_text()
        self.assertIn('$childMayExist',text)
        self.assertIn('-not $childMayExist -or $null -ne $child',text)
        self.assertNotIn('Stop-Process -Name',text)
        self.assertNotIn('taskkill',text.lower())


class SyntheticPipelineTests(unittest.TestCase):
    def prepare(self,root):
        alerts,sources,receipt,observations=fixture()
        execution=root/'windows-execution';source_root=execution/'source';entries=[]
        for source in sources:
            p=source_root/('event-'+source['record_id']+'.xml');write_new_bytes(p,xml_bytes(source))
            entries.append({'path':p.name,'kind':'event-xml-rendering','bytes':p.stat().st_size,'sha256':sha256_file(p)})
        p=source_root/'events.evtx';write_new_bytes(p,b'SYNTHETIC-NOT-REAL-EVTX')
        entries.append({'path':p.name,'kind':'evtx-export','bytes':p.stat().st_size,'sha256':sha256_file(p)})
        write_new_json(source_root/'source-manifest.json',{'complete':True,'evtx_xml_verified_on_controller':True,'files':entries})
        write_new_json(execution/'target-response.json',{'receipt':receipt,'kernel_observations':observations})
        write_new_json(execution/'execution-seal.json',{'files_sha256':{str(p.relative_to(execution)):sha256_file(p) for p in execution.rglob('*') if p.is_file()}})
        raw=root/'raw/alerts.jsonl';write_new_bytes(raw,b''.join((json.dumps(e)+'\n').encode() for e in alerts))
        plan={'campaign_id':'synthetic-campaign','run_id':'synthetic-run','activities':[{'activity_id':'synthetic-benign','class':'benign','attack_instance_id':None,'benign_activity_id':'synthetic-benign-instance'}]}
        return plan,alerts

    def test_end_to_end_eight_cells_keep_proofs_private_and_no_benign_training(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);plan,_=self.prepare(root)
            with patch.object(analysis,'validate',return_value=(plan,{}, {'agent_name':'windows-agent','wazuh_string_profile':'json-string-content'})),patch.object(analysis,'verify_collection'):
                result=analysis.analyze(root)
            self.assertTrue(result['both_parent_child_Wazuh_proven'])
            comparison=json.loads((root/'windows-analysis/comparison.json').read_text())
            self.assertEqual(len(comparison['variants']),4)
            self.assertFalse(comparison['attack_metrics_computed'])
            for name,value in comparison['variants'].items():
                self.assertEqual(value['verified_events_retained'],2)
                for gen in value['generators'].values():self.assertEqual(gen['training_pairs_exported'],0)
                text=(root/'windows-analysis'/(name+'-metas.json')).read_text()
                self.assertNotIn('synthetic-benign',text)
                self.assertNotIn('creation_filetime',text)

    def test_duplicate_source_wazuh_copies_are_not_independent_proofs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);plan,alerts=self.prepare(root)
            duplicate=copy.deepcopy(alerts[1]);duplicate['id']='another-wazuh-id'
            with (root/'raw/alerts.jsonl').open('ab') as stream:stream.write((json.dumps(duplicate)+'\n').encode())
            with patch.object(analysis,'validate',return_value=(plan,{}, {'agent_name':'windows-agent','wazuh_string_profile':'json-string-content'})),patch.object(analysis,'verify_collection'):
                result=analysis.analyze(root)
            self.assertFalse(result['both_parent_child_Wazuh_proven'])
            self.assertFalse((root/'windows-analysis/comparison.json').exists())


if __name__=='__main__':unittest.main()
