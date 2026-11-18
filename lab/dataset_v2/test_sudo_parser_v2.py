"""Regression du delimitateur syslog, sans campagne ni connexion distante."""
import ast
import copy
import inspect
import unittest

from . import sudo_evidence_adapter as original
from . import sudo_evidence_adapter_v2 as revised
from . import test_sudo_evidence_adapter as fixtures


class ExactSudoParserTests(unittest.TestCase):
    def fixture(self, body=None):
        args = fixtures.SudoProofTests().fixture()
        body = body or '   labuser : a password is required ; PWD=/home/labuser ; USER=root ; COMMAND=/usr/bin/true'
        args[0]['full_log'] = 'Nov 16 09:00:02 ubuntu sudo[123]: ' + body
        args[1][0]['MESSAGE'] = body
        return args

    def test_three_spaces_preserved_and_old_result_unchanged(self):
        args = self.fixture(); before = copy.deepcopy(args)
        self.assertEqual(original.associate_sudo_event(*args)['decision'], 'excluded')
        self.assertEqual(revised._pid_message(args[0])[1], args[1][0]['MESSAGE'])
        self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'member-verified')
        self.assertEqual(args, before)
        self.assertEqual(original.associate_sudo_event(*args)['decision'], 'excluded')

    def test_significant_whitespace_not_normalized(self):
        for body in ('   leading', 'middle  spaces\tinside', 'trailing   ',
                     '\t leading\ninterior\r\nend  ', 'unicode é  fin '):
            with self.subTest(body=repr(body)):
                alert = self.fixture(body)[0]
                pid, actual = revised._pid_message(alert)
                self.assertEqual(pid, 123)
                self.assertEqual(actual.encode('utf-8'), body.encode('utf-8'))

    def test_only_one_ascii_serialization_space_removed(self):
        for body in ('', 'x', ' x', '   x', '\tx'):
            alert = {'full_log': 'sudo[123]: ' + body}
            self.assertEqual(revised._pid_message(alert), (123, body))
        for raw in ('sudo[123]:x', 'sudo[123]:\tx', 'sudo[123]:\nx'):
            self.assertEqual(revised._pid_message({'full_log': raw}), (None, None))

    def test_leading_middle_trailing_differences_remain_excluded(self):
        for transform in (lambda s: s[1:], lambda s: ' ' + s,
                          lambda s: s.replace('labuser :', 'labuser  :'),
                          lambda s: s + ' ', lambda s: s.replace('required', 'optional')):
            args = self.fixture()
            args[1][0]['MESSAGE'] = transform(args[1][0]['MESSAGE'])
            with self.subTest(message=repr(args[1][0]['MESSAGE'])):
                self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_pid_boot_birth_and_lineage_contradictions(self):
        for field, value in (('pid', 124), ('start_ticks', 999), ('ppid', 999),
                             ('parent_start_ticks', 999), ('parent_ppid', 999),
                             ('boot_id', '00000000-0000-0000-0000-000000000001')):
            args = self.fixture(); args[3][0][field] = value
            with self.subTest(field=field):
                self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_conflicting_explicit_pid_and_wrong_wazuh_pid(self):
        for mutation in ('data', 'prefix'):
            args = self.fixture()
            if mutation == 'data': args[0]['data'] = {'pid': 124}
            else: args[0]['full_log'] = args[0]['full_log'].replace('[123]', '[124]')
            self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_journal_session_login_boot_and_hostname_must_match(self):
        for field, value in (('_AUDIT_SESSION', '8'), ('_AUDIT_LOGINUID', '1001'),
                             ('_HOSTNAME', 'other'),
                             ('_BOOT_ID', '00000000-0000-0000-0000-000000000001')):
            args = self.fixture(); args[1][0][field] = value
            with self.subTest(field=field):
                self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_wrong_command_in_receipt_or_matching_messages(self):
        args = self.fixture(); args[2][0]['command_argv'] = ['sudo', 'id']
        self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')
        args = self.fixture()
        args[0]['full_log'] = args[0]['full_log'].replace('/usr/bin/true', '/usr/bin/id')
        args[1][0]['MESSAGE'] = args[1][0]['MESSAGE'].replace('/usr/bin/true', '/usr/bin/id')
        self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_duplicate_cursor_or_concurrent_identical_source_is_ambiguous(self):
        for same_cursor in (True, False):
            args = self.fixture(); other = copy.deepcopy(args[1][0])
            if not same_cursor: other['__CURSOR'] = 'different-cursor'
            args[1].append(other)
            self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_multiple_receipts_and_missing_socket_never_assumed_member(self):
        args = self.fixture(); args[2].append(copy.deepcopy(args[2][0]))
        self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')
        args = self.fixture(); args[4] = []
        self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_refusal_with_command_can_be_verified_without_password_or_success(self):
        args = self.fixture()
        result = revised.associate_sudo_event(*args)
        self.assertEqual(result['decision'], 'member-verified')
        self.assertNotIn('target', result)
        args = self.fixture('   labuser : a password is required')
        self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')

    def test_all_original_provenance_predicates_identical(self):
        for name in ('associate_sudo_event', '_pid_message', '_utc', 'observable_projection'):
            self.assertEqual(ast.dump(ast.parse(inspect.getsource(getattr(original, name)))),
                             ast.dump(ast.parse(inspect.getsource(getattr(revised, name)))))

    def test_private_metadata_is_not_a_feature_or_a_proof(self):
        args = self.fixture(); before = revised.observable_projection(args[0])
        args[0].update(campaign_id='private', confidence='verified', evidence_ids=['secret'])
        self.assertEqual(revised.observable_projection(args[0]), before)
        args[3] = []
        self.assertEqual(revised.associate_sudo_event(*args)['decision'], 'excluded')


if __name__ == '__main__':
    unittest.main()
