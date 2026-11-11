from __future__ import annotations

import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lab.collect_wazuh import instant
from lab.dataset_v2.clock_audit import (
    ClockPolicyError,
    StaticClockProbe,
    audit_campaign_clocks,
    require_clock_ready,
)
from lab.dataset_v2.orchestrator_adapters import emit_orchestrator_records
from lab.dataset_v2.prepare_campaign import prepare_campaign
from lab.dataset_v2.probe_clocks_readonly import CommandResult, _windows_console_text, measure_unix_ssh
from lab.dataset_v2.run_benign_ssh_activity import parse_ssh_connection
from lab.dataset_v2.review_ssh_association import _jsonl as review_jsonl
from lab.dataset_v2.link_winrm_activity_events import _win_event
from lab.dataset_v2.link_activity_events import extract_sshd_pid
from lab.dataset_v2.ssh_collection import (
    TransferResult,
    collect_ssh_campaign,
)


EXAMPLES = Path(__file__).with_name("examples")


def readiness_plan() -> dict[str, object]:
    plan = json.loads((EXAMPLES / "scenario-plan.json").read_text(encoding="utf-8"))
    plan["machines"] = [
        {"role": "controller", "host": "controller", "agent_name": None},
        {"role": "wazuh-manager", "host": "wazuh", "agent_name": None},
        {"role": "linux-target", "host": "linux", "agent_name": "synthetic-linux-agent"},
        {"role": "windows-target", "host": "windows", "agent_name": "synthetic-windows-agent"},
    ]
    return plan


def good_clock_responses() -> dict[str, dict[str, object]]:
    result = {}
    for index, role in enumerate(
        ("controller", "wazuh-manager", "linux-target", "windows-target")
    ):
        # RTT=100 ms, temps distant à +10 ms par rapport au milieu.
        result[role] = {
            "request_started_at_utc": "2026-11-10T09:00:00.000+00:00",
            "request_ended_at_utc": "2026-11-10T09:00:00.100+00:00",
            "remote_time_utc": "2026-11-10T09:00:00.060+00:00",
            "synchronized": True,
            "sync_source": "synthetic-ntp",
        }
    return result


def prepare_ready_campaign(root: Path, suffix: str) -> Path:
    result = prepare_campaign(
        root,
        campaign_id=f"dev-ready-{suffix}",
        run_id=f"dev-ready-{suffix}-r01",
        partition="development",
        scenario_plan=readiness_plan(),
        parameter_seed=55,
    )
    directory = Path(result["campaign_directory"])
    audit_campaign_clocks(directory, StaticClockProbe(good_clock_responses()))
    return directory


class FakeSSHRunner:
    def __init__(self, payload: bytes, *, exit_code: int = 0, interrupted: bool = False, stderr: bytes = b""):
        self.payload = payload
        self.exit_code = exit_code
        self.interrupted = interrupted
        self.stderr = stderr
        self.calls = 0

    def transfer(self, *, host, user, key, remote_path, destination):
        self.calls += 1
        destination.write_bytes(self.payload)
        return TransferResult(
            exit_code=self.exit_code,
            interrupted=self.interrupted,
            stderr=self.stderr,
            bytes_written=len(self.payload),
        )


class FakeCommandRunner:
    def __init__(self):
        self.commands = []

    def run(self, command):
        self.commands.append(command)
        if any("time.time_ns()" in part for part in command):
            return CommandResult(0, b"1794301200060000000\n", b"")
        return CommandResult(0, b"yes\n", b"")


class ClockAuditTests(unittest.TestCase):
    def test_localized_windows_unsynchronized_status_is_decoded(self):
        raw = "Indicateur de dérive : 3(Non synchronisé)".encode("cp850")
        self.assertIn("non synchronise", _windows_console_text(raw))

    def test_unix_probe_uses_only_readonly_commands_and_output_has_no_credentials(self):
        runner = FakeCommandRunner()
        role, response = measure_unix_ssh(
            role="wazuh-manager",
            host="192.0.2.20",
            user="secret-user",
            key=Path("C:/secret/key"),
            runner=runner,
        )
        self.assertEqual(role, "wazuh-manager")
        self.assertEqual(len(runner.commands), 6)
        self.assertEqual(sum(any("time.time_ns()" in part for part in x) for x in runner.commands), 5)
        self.assertTrue(
            any(any("NTPSynchronized" in part for part in command) for command in runner.commands)
        )
        self.assertEqual(len(response["samples"]), 5)
        self.assertEqual(response["selection_policy"], "minimum-rtt-then-sample-index-independent-of-offset")
        serialized = json.dumps(response)
        self.assertNotIn("secret-user", serialized)
        self.assertNotIn("C:/secret/key", serialized)

    @staticmethod
    def _multi_response(samples):
        origin = datetime(2026, 11, 10, 9, 0, tzinfo=timezone.utc)
        rows = []
        for index, (start_ms, rtt_ms, offset_ms) in enumerate(samples):
            started = origin + timedelta(milliseconds=start_ms)
            ended = started + timedelta(milliseconds=rtt_ms)
            remote = started + timedelta(milliseconds=rtt_ms / 2 + offset_ms)
            rows.append({
                "sample_index": index,
                "request_started_at_utc": started.isoformat(),
                "request_ended_at_utc": ended.isoformat(),
                "remote_time_utc": remote.isoformat(),
            })
        selected = min(rows, key=lambda x: (samples[x["sample_index"]][1], x["sample_index"]))
        return {
            "request_started_at_utc": selected["request_started_at_utc"],
            "request_ended_at_utc": selected["request_ended_at_utc"],
            "remote_time_utc": selected["remote_time_utc"],
            "synchronized": True,
            "sync_source": "synthetic-multi-sample",
            "selection_policy": "minimum-rtt-then-sample-index-independent-of-offset",
            "selected_sample_index": selected["sample_index"],
            "samples": rows,
        }

    def test_minimum_rtt_is_selected_and_all_samples_are_recorded(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary, campaign_id="dev-clock-multi", run_id="dev-clock-multi-r01",
                partition="development", scenario_plan=readiness_plan(), parameter_seed=8,
            )
            responses = good_clock_responses()
            responses["wazuh-manager"] = self._multi_response([
                (0, 800, 400), (1000, 100, 200), (2000, 200, 200),
            ])
            report = audit_campaign_clocks(result["campaign_directory"], StaticClockProbe(responses))
            row = next(x for x in report["measurements"] if x["role"] == "wazuh-manager")
            self.assertEqual(row["selected_sample_index"], 1)
            self.assertEqual(len(row["samples"]), 3)
            self.assertAlmostEqual(row["offset_ms"], 200.0, places=2)
            self.assertAlmostEqual(row["uncertainty_ms"], 50.0, places=2)

    def test_favorable_slow_sample_cannot_hide_real_desynchronization(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary, campaign_id="dev-clock-real-bad", run_id="dev-clock-real-bad-r01",
                partition="development", scenario_plan=readiness_plan(), parameter_seed=9,
            )
            responses = good_clock_responses()
            responses["linux-target"] = self._multi_response([
                (0, 900, 0), (1000, 80, 1500), (2000, 120, 1500),
            ])
            with self.assertRaises(ClockPolicyError) as caught:
                audit_campaign_clocks(result["campaign_directory"], StaticClockProbe(responses))
            reasons = caught.exception.report["rejection_reasons"]
            self.assertTrue(any("offset-exceeds-policy" in x for x in reasons))
            self.assertTrue(any("inconsistent-clock-samples" in x for x in reasons))

    def test_incoherent_samples_are_rejected_even_when_selected_offset_is_small(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary, campaign_id="dev-clock-incoherent", run_id="dev-clock-incoherent-r01",
                partition="development", scenario_plan=readiness_plan(), parameter_seed=10,
            )
            responses = good_clock_responses()
            responses["wazuh-manager"] = self._multi_response([
                (0, 100, 100), (1000, 120, 900), (2000, 140, -700),
            ])
            with self.assertRaises(ClockPolicyError) as caught:
                audit_campaign_clocks(result["campaign_directory"], StaticClockProbe(responses))
            self.assertTrue(any("inconsistent-clock-samples" in x
                                for x in caught.exception.report["rejection_reasons"]))

    def test_good_measurements_are_recorded_and_accepted(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary,
                campaign_id="dev-clock-good",
                run_id="dev-clock-good-r01",
                partition="development",
                scenario_plan=readiness_plan(),
                parameter_seed=1,
            )
            directory = Path(result["campaign_directory"])
            report = audit_campaign_clocks(
                directory, StaticClockProbe(good_clock_responses())
            )
            self.assertTrue(report["accepted"])
            self.assertEqual(len(report["measurements"]), 4)
            self.assertTrue(all(abs(x["offset_ms"] - 10.0) < 0.01 for x in report["measurements"]))
            self.assertTrue(all(abs(x["uncertainty_ms"] - 50.0) < 0.01 for x in report["measurements"]))
            require_clock_ready(directory)

    def test_excessive_offset_is_persisted_and_rejects_campaign(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary,
                campaign_id="dev-clock-bad",
                run_id="dev-clock-bad-r01",
                partition="development",
                scenario_plan=readiness_plan(),
                parameter_seed=2,
            )
            directory = Path(result["campaign_directory"])
            responses = good_clock_responses()
            responses["wazuh-manager"]["remote_time_utc"] = "2026-11-10T09:00:05.000+00:00"
            with self.assertRaises(ClockPolicyError) as caught:
                audit_campaign_clocks(directory, StaticClockProbe(responses))
            self.assertTrue(caught.exception.report_path.is_file())
            self.assertFalse(caught.exception.report["accepted"])
            with self.assertRaises(ClockPolicyError):
                require_clock_ready(directory)

    def test_uncertainty_and_unsynchronized_status_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary,
                campaign_id="dev-clock-sync",
                run_id="dev-clock-sync-r01",
                partition="development",
                scenario_plan=readiness_plan(),
                parameter_seed=3,
            )
            responses = good_clock_responses()
            responses["windows-target"]["request_ended_at_utc"] = "2026-11-10T09:00:02.000+00:00"
            responses["windows-target"]["remote_time_utc"] = "2026-11-10T09:00:01.000+00:00"
            responses["windows-target"]["synchronized"] = False
            with self.assertRaises(ClockPolicyError) as caught:
                audit_campaign_clocks(
                    result["campaign_directory"], StaticClockProbe(responses)
                )
            reasons = caught.exception.report["rejection_reasons"]
            self.assertTrue(any("uncertainty-exceeds-policy" in x for x in reasons))
            self.assertTrue(any("synchronization-not-confirmed" in x for x in reasons))


class BenignSSHReceiptTests(unittest.TestCase):
    def test_review_jsonl_is_stable_and_utf8(self):
        payload = [{"value": "preuve indépendante", "id": 1}]
        self.assertEqual(
            review_jsonl(payload),
            b'{"value":"preuve ind\xc3\xa9pendante","id":1}\n',
        )

    def test_win_event_extracts_sysmon_system_and_eventdata(self):
        event = {"data": {"win": {"system": {"eventID": "1"}, "eventdata": {"processId": "42"}}}}
        system, eventdata = _win_event(event)
        self.assertEqual(system["eventID"], "1")
        self.assertEqual(eventdata["processId"], "42")

    def test_parse_ssh_connection_preserves_exact_tuple(self):
        self.assertEqual(
            parse_ssh_connection("192.0.2.10 49152 192.0.2.20 22"),
            {
                "source_ip": "192.0.2.10",
                "source_port": 49152,
                "target_ip": "192.0.2.20",
                "target_port": 22,
            },
        )

    def test_parse_ssh_connection_rejects_incomplete_identity(self):
        with self.assertRaises(ValueError):
            parse_ssh_connection("192.0.2.10 49152 192.0.2.20")

    def test_extract_sshd_pid_requires_explicit_journal_identity(self):
        self.assertEqual(
            extract_sshd_pid({"full_log": "host sshd[4788]: Accepted publickey"}),
            "4788",
        )
        self.assertIsNone(extract_sshd_pid({"full_log": "PAM session opened"}))


class SSHCollectionTests(unittest.TestCase):
    def _payload(self) -> bytes:
        return (EXAMPLES / "wazuh-export.jsonl").read_bytes()

    def _collect(self, directory: Path, runner: FakeSSHRunner):
        return collect_ssh_campaign(
            directory,
            host="192.0.2.20",
            user="secret-user-must-not-be-recorded",
            key="C:/secret/key-must-not-be-recorded",
            since=instant("2026-11-10T09:00:00+00:00"),
            until=instant("2026-11-10T09:05:00+00:00"),
            agents={"synthetic-linux-agent", "synthetic-windows-agent"},
            runner=runner,
            allow_remote_read=True,
        )

    def test_mock_ssh_preserves_bytes_and_omits_connection_identifiers(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = prepare_ready_campaign(Path(temporary), "ssh-ok")
            result = self._collect(directory, FakeSSHRunner(self._payload()))
            expected = b"".join(self._payload().splitlines(keepends=True)[:2])
            self.assertEqual((directory / "raw/alerts.jsonl").read_bytes(), expected)
            serialized = json.dumps(result)
            self.assertNotIn("secret-user", serialized)
            self.assertNotIn("key-must-not-be-recorded", serialized)
            self.assertEqual(result["collection"]["alerts_written"], 2)

    def test_nonzero_ssh_exit_preserves_incomplete_attempt_without_raw_dataset(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = prepare_ready_campaign(Path(temporary), "ssh-fail")
            runner = FakeSSHRunner(
                self._payload()[:100], exit_code=255, stderr=b"secret-user: connection failed"
            )
            with self.assertRaises(RuntimeError):
                self._collect(directory, runner)
            self.assertFalse((directory / "raw").exists())
            failures = list(directory.glob("collection-attempts/*/failure.json"))
            incomplete = list(directory.glob("collection-attempts/*/*.incomplete"))
            self.assertEqual((len(failures), len(incomplete)), (1, 1))
            content = failures[0].read_text(encoding="utf-8")
            self.assertNotIn("secret-user", content)
            self.assertIn("stderr_sha256", content)

    def test_interrupted_transfer_is_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = prepare_ready_campaign(Path(temporary), "ssh-interrupt")
            with self.assertRaises(RuntimeError):
                self._collect(
                    directory,
                    FakeSSHRunner(self._payload()[:80], exit_code=None, interrupted=True),
                )
            failure = json.loads(
                next(directory.glob("collection-attempts/*/failure.json")).read_text(
                    encoding="utf-8"
                )
            )
            self.assertTrue(failure["interrupted"])
            self.assertEqual(failure["reason"], "interrupted")

    def test_collection_requires_an_accepted_clock_audit(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary,
                campaign_id="dev-no-clock",
                run_id="dev-no-clock-r01",
                partition="development",
                scenario_plan=readiness_plan(),
                parameter_seed=5,
            )
            runner = FakeSSHRunner(self._payload())
            with self.assertRaises(RuntimeError):
                self._collect(Path(result["campaign_directory"]), runner)
            self.assertEqual(runner.calls, 0)

    def test_final_test_partition_is_protected_before_ssh(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = prepare_campaign(
                temporary,
                campaign_id="final-ssh-protected",
                run_id="final-ssh-protected-r01",
                partition="final-test",
                scenario_plan=readiness_plan(),
                parameter_seed=9,
                reserve_final_test=True,
            )
            runner = FakeSSHRunner(self._payload())
            with self.assertRaises(PermissionError):
                self._collect(Path(result["campaign_directory"]), runner)
            self.assertEqual(runner.calls, 0)


class ControlledOrchestratorIntegrationTests(unittest.TestCase):
    def test_existing_receipt_requires_clock_and_preserves_target_times(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = prepare_ready_campaign(Path(temporary), "receipt")
            truth = {
                "status": "completed",
                "steps": [
                    {
                        "name": "canary-create",
                        "started_at": "2026-11-10T09:01:00+00:00",
                        "ended_at": "2026-11-10T09:01:01+00:00",
                        "target_started_at_utc": "2026-11-10T09:01:00.010+00:00",
                        "target_ended_at_utc": "2026-11-10T09:01:00.900+00:00",
                        "exit_code": 0,
                        "result": {"mocked": True},
                    }
                ],
            }
            report = emit_orchestrator_records(
                directory, platform="linux", dry_run=False, v1_truth=truth
            )
            self.assertEqual(report["mode"], "adapted-v1-receipt")
            activity = json.loads(
                (directory / "execution/activities.jsonl").read_text(encoding="utf-8").splitlines()[0]
            )
            self.assertEqual(activity["target_started_at_utc"], truth["steps"][0]["target_started_at_utc"])
            evidence = [
                json.loads(x)
                for x in (directory / "execution/evidence.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(
                {x["kind"] for x in evidence}, {"command-hash", "execution-receipt"}
            )
            self.assertNotIn("wazuh-rule-semantic", {x["kind"] for x in evidence})


if __name__ == "__main__":
    unittest.main()
