import unittest
from datetime import datetime, timezone

from audit_socbed import (
    AttackStart,
    parse_attack_starts,
    parse_suricata_alert,
    phase_for_timestamp,
    sigma_true_positive,
    suricata_phase,
)


class SocbedAuditTests(unittest.TestCase):
    def test_attack_log_parser(self):
        items = parse_attack_starts(
            [
                '2021-01-01T10:00:00+00:00 x INFO [event="run_attack" attack="misc_sqlmap"] Run',
                'noise',
            ]
        )
        self.assertEqual(items[0].attack, "misc_sqlmap")

    def test_suricata_parser(self):
        alert = parse_suricata_alert(
            "[1:42:3] Example rule [Classification: Test] [Priority: 2] "
            "{TCP} 10.0.0.1:1 -> 10.0.0.2:2\n"
        )
        self.assertEqual(alert["signature"], "Example rule")
        self.assertEqual(alert["priority"], 2)

    def test_sigma_predicate_rejects_benign_same_rule(self):
        event = {"process": {"command_line": "powershell benign.ps1"}}
        self.assertFalse(sigma_true_positive("Non Interactive PowerShell", event))
        event["process"]["command_line"] = "download meterpreter_bind_tcp.exe"
        self.assertTrue(sigma_true_positive("Non Interactive PowerShell", event))

    def test_email_interval_splits_steps_two_and_three(self):
        start = datetime(2021, 1, 1, 10, 0, tzinfo=timezone.utc)
        starts = [AttackStart(start, "infect_email_exe")]
        self.assertEqual(
            phase_for_timestamp(
                start,
                starts,
                signature="ET INFO SUSPICIOUS SMTP EXE - EXE SMTP Attachment",
            ),
            2,
        )
        self.assertEqual(phase_for_timestamp(start, starts, signature="payload"), 3)
        self.assertIsNone(
            phase_for_timestamp(
                datetime(2021, 1, 1, 10, 4, tzinfo=timezone.utc), starts
            )
        )

    def test_delayed_payload_is_still_step_three(self):
        start = datetime(2021, 1, 1, 10, 0, tzinfo=timezone.utc)
        starts = [
            AttackStart(start, "infect_email_exe"),
            AttackStart(datetime(2021, 1, 1, 10, 3, tzinfo=timezone.utc), "c2_take_screenshot"),
        ]
        self.assertEqual(
            suricata_phase(
                datetime(2021, 1, 1, 10, 3, 5, tzinfo=timezone.utc),
                starts,
                "ET INFO EXE IsDebuggerPresent (Used in Malware Anti-Debugging)",
            ),
            3,
        )


if __name__ == "__main__":
    unittest.main()
