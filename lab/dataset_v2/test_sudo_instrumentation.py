import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from . import sudo_target_probe as probe
from .sudo_journal_observer import SudoJournalStreamRecorder,build_sudo_journal_argv
from .io_utils import sha256_file

BOOT='11111111-1111-4111-8111-111111111111'


def stat(pid,ppid,start,comm='python'):
    return f'{pid} ({comm}) '+' '.join(['S',str(ppid)]+['0']*17+[str(start)])+'\n'


class ImmediateThread:
    def __init__(self,target,args=(),**kwargs):self.target=target;self.args=args
    def start(self):self.target(*self.args)
    def join(self,*args):pass
    def is_alive(self):return False


class ProcfsProofTests(unittest.TestCase):
    def fixture(self,root):
        boot=root/'sys/kernel/random/boot_id';boot.parent.mkdir(parents=True);boot.write_text(BOOT)
        for pid,ppid,start,comm in ((300,200,30,'python'),(200,100,20,'python'),(100,1,10,'sshd')):
            path=root/str(pid);path.mkdir()
            (path/'stat').write_text(stat(pid,ppid,start,comm))
            (path/'loginuid').write_text('1000');(path/'sessionid').write_text('7')

    def test_procfs_lineage_preserves_original_stat(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            result=probe.capture_lineage(300,200,root)
            self.assertEqual(result['pid'],300);self.assertEqual(result['parent_ppid'],100)
            self.assertEqual(result['stat_raw'],stat(300,200,30))

    def test_comm_with_spaces_and_parentheses(self):
        result=probe.parse_stat(stat(300,200,30,'a (b) c'))
        self.assertEqual(result['comm'],'a (b) c');self.assertEqual(result['start_ticks'],30)

    def test_pid_reused_while_reading_is_rejected(self):
        with patch.object(Path,'read_text',side_effect=[stat(300,200,30),'1000','7',stat(300,200,31)]):
            with self.assertRaisesRegex(ValueError,'identity changed'):probe.read_identity(300,'unused')

    def test_missing_audit_or_indirect_parent_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);(root/'300/sessionid').write_text('4294967295')
            with self.assertRaises(ValueError):probe.capture_lineage(300,200,root)
            (root/'300/sessionid').write_text('7');(root/'100/stat').write_text(stat(100,1,10,'bash'))
            with self.assertRaises(ValueError):probe.capture_lineage(300,200,root)

    def fake_probe(self,capture):
        events=[]
        def observe(*args):events.append('kernel-observation');return capture()
        with patch.object(probe.os,'fork',return_value=300,create=True), \
             patch.object(probe.os,'pipe',side_effect=[(10,11),(12,13),(14,15),(16,17)]), \
             patch.object(probe.os,'close'),patch.object(probe.os,'write',side_effect=lambda fd,data:events.append('gate') if data==b'G' else None), \
             patch.object(probe.os,'read',return_value=b''),patch.object(probe.os,'fdopen',side_effect=lambda *a:io.BytesIO()), \
             patch.object(probe.os,'execv',side_effect=AssertionError('no command may execute')), \
             patch.object(probe.os,'waitstatus_to_exitcode',return_value=0,create=True), \
             patch.object(Path,'is_file',return_value=True),patch.object(probe,'_wait',return_value=0), \
             patch.object(probe,'capture_lineage',side_effect=observe),patch.object(probe.threading,'Thread',ImmediateThread):
            result=probe.run_probe()
        return result,events

    def test_gate_opens_only_after_independent_kernel_observation(self):
        result,events=self.fake_probe(lambda:{'pid':300,'start_ticks':30})
        self.assertEqual(events,['kernel-observation','gate'])
        self.assertTrue(result['capture_complete']);self.assertEqual(result['invocations_attempted'],1)

    def test_failed_observation_prevents_command(self):
        def fail():raise PermissionError('synthetic')
        result,events=self.fake_probe(fail)
        self.assertEqual(result['invocations_attempted'],0);self.assertNotIn('gate',events)

    def test_cleanup_permission_denial_remains_unconfirmed(self):
        with patch.object(probe,'_wait',return_value=None),patch.object(Path,'read_text',return_value=stat(300,200,30)), \
             patch.object(probe.signal,'SIGKILL',9,create=True), \
             patch.object(probe.os,'kill',side_effect=PermissionError('synthetic')):
            self.assertFalse(probe._cleanup(300,{'start_ticks':30})['confirmed_stopped'])


class SudoJournalTests(unittest.TestCase):
    def line(self,comm,cursor):
        return (json.dumps({'_COMM':comm,'__CURSOR':cursor,'__REALTIME_TIMESTAMP':'1794819602000000',
                            '_BOOT_ID':BOOT,'_PID':'300','MESSAGE':'synthetic'})+'\n').encode()

    def test_filters_use_sudo_and_sshd(self):
        command=' '.join(build_sudo_journal_argv('192.0.2.2','synthetic',duration_seconds=45))
        self.assertIn('_COMM=sshd _COMM=sudo',command);self.assertIn('45s',command)

    def test_raw_bytes_hash_and_mixed_channels_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            recorder=SudoJournalStreamRecorder(temp,'synthetic');data=self.line('sshd','1')+self.line('sudo','2')
            for line in data.splitlines(keepends=True):recorder.feed(line)
            manifest=recorder.close(process_exit_code=0)
            self.assertTrue(manifest['complete'])
            self.assertEqual((Path(temp)/manifest['raw_file']).read_bytes(),data)
            self.assertEqual(sha256_file(Path(temp)/manifest['raw_file']),manifest['raw_sha256'])

    def test_duplicate_unexpected_or_partial_stream_cannot_be_accepted(self):
        for mode in ('duplicate','unexpected','partial'):
            with tempfile.TemporaryDirectory() as temp:
                recorder=SudoJournalStreamRecorder(temp,'synthetic');recorder.feed(self.line('sudo','1'))
                if mode=='duplicate':recorder.feed(self.line('sudo','1'))
                if mode=='unexpected':recorder.feed(self.line('bash','2'))
                report=recorder.close(process_exit_code=0,interrupted=mode=='partial')
                self.assertFalse(report['complete'])


if __name__=='__main__':unittest.main()
