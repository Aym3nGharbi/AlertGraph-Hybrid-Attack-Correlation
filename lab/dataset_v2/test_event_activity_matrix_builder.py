from __future__ import annotations

import unittest

from lab.dataset_v2.build_event_activity_matrix import (
    _linux_memberships,
    _windows_memberships,
)


class ExactActivitySeparationTests(unittest.TestCase):
    def test_same_ssh_alert_types_are_separated_by_port_and_sshd_pid(self):
        activities = [
            {"activity_id": "a", "marker_id": "ma"},
            {"activity_id": "b", "marker_id": "mb"},
        ]
        receipts = {
            "a": {"steps": [{"result": {"target_boot_id": "boot", "target_ssh_connection": {"source_port": 50001}}}]},
            "b": {"steps": [{"result": {"target_boot_id": "boot", "target_ssh_connection": {"source_port": 50002}}}]},
        }
        events = [
            {"id": "a-auth", "rule": {"id": "5715"}, "data": {"srcport": "50001"}, "full_log": "sshd[100]: Accepted"},
            {"id": "a-open", "rule": {"id": "5501"}, "full_log": "sshd[100]: opened"},
            {"id": "b-auth", "rule": {"id": "5715"}, "data": {"srcport": "50002"}, "full_log": "sshd[101]: Accepted"},
            {"id": "b-open", "rule": {"id": "5501"}, "full_log": "sshd[101]: opened"},
        ]
        memberships, identities, _ = _linux_memberships(events, activities, receipts)
        self.assertEqual(memberships, {"a-auth": "a", "a-open": "a", "b-auth": "b", "b-open": "b"})
        self.assertNotEqual(identities["a"], identities["b"])

    def test_concurrent_windows_processes_are_separated_by_processguid_and_logonid(self):
        activities = [
            {"activity_id": "a", "marker_id": "marker-a"},
            {"activity_id": "b", "marker_id": "marker-b"},
        ]
        receipts = {
            "a": {"steps": [{"result": {"target_process_id": 10}}]},
            "b": {"steps": [{"result": {"target_process_id": 20}}]},
        }

        def event(alert, eid, **data):
            return {"id": alert, "data": {"win": {"system": {"eventID": str(eid)}, "eventdata": data}}}

        events = [
            event("a-process", 1, processId="10", commandLine="cmd marker-a", processGuid="ga", parentProcessGuid="pa", parentProcessId="11", logonId="0xaa"),
            event("b-process", 1, processId="20", commandLine="cmd marker-b", processGuid="gb", parentProcessGuid="pb", parentProcessId="21", logonId="0xbb"),
            event("a-logon", 4624, targetLogonId="0xaa"),
            event("b-logon", 4624, targetLogonId="0xbb"),
            event("background", 4624, targetLogonId="0xcc"),
        ]
        memberships, identities, _ = _windows_memberships(events, activities, receipts)
        self.assertEqual(memberships["a-process"], "a")
        self.assertEqual(memberships["a-logon"], "a")
        self.assertEqual(memberships["b-process"], "b")
        self.assertEqual(memberships["b-logon"], "b")
        self.assertNotIn("background", memberships)
        self.assertNotEqual(identities["a"], identities["b"])


if __name__ == "__main__":
    unittest.main()
