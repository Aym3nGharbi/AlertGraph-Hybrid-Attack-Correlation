from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from lab.dataset_v2.persistent_journal_observer import (
    JournalStreamRecorder,
    build_ssh_journal_argv,
)


def _line(cursor: str, pid: str = "42", timestamp: str = "1794427200000000") -> bytes:
    value = {
        "__CURSOR": cursor, "__REALTIME_TIMESTAMP": timestamp,
        "_BOOT_ID": "340181474db44fbe9bc71cc3e18fc9be", "_PID": pid, "_COMM": "sshd",
        "MESSAGE": "synthetic sshd evidence",
    }
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


class PersistentJournalObserverTests(unittest.TestCase):
    def test_command_is_noninteractive_and_contains_no_password(self):
        argv = build_ssh_journal_argv("192.0.2.20", "labuser")
        joined = " ".join(argv)
        self.assertIn("BatchMode=yes", joined)
        self.assertIn("ALERTGRAPH_JOURNAL_READY", joined)
        self.assertIn("--follow", joined)
        self.assertIn("timeout --signal=TERM 40s", joined)
        self.assertNotIn("password", joined.lower())

    def test_duration_is_bounded(self):
        with self.assertRaises(ValueError):
            build_ssh_journal_argv("192.0.2.20", "labuser", duration_seconds=9)

    def test_raw_bytes_are_preserved_and_sealed(self):
        payload = _line("cursor-1") + _line("cursor-2", "43")
        with tempfile.TemporaryDirectory() as temporary:
            recorder = JournalStreamRecorder(temporary, "observer-test")
            for line in payload.splitlines(keepends=True):
                recorder.feed(line)
            manifest = recorder.close(process_exit_code=0)
            raw = Path(temporary, "observer-test.jsonl").read_bytes()
            self.assertEqual(raw, payload)
            self.assertEqual(manifest["raw_sha256"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(manifest["valid_record_count"], 2)
            self.assertTrue(manifest["complete"])
            self.assertFalse(manifest["training_ready"])

    def test_duplicate_cursor_or_invalid_record_prevents_complete_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            recorder = JournalStreamRecorder(temporary, "observer-test")
            recorder.feed(_line("same")); recorder.feed(_line("same"))
            recorder.feed(b'{"MESSAGE":"incomplete"}\n')
            manifest = recorder.close(process_exit_code=0)
            self.assertFalse(manifest["complete"])
            self.assertEqual(manifest["duplicate_cursors"], ["same"])
            self.assertEqual(len(manifest["invalid_records"]), 1)

    def test_existing_artifact_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            Path(temporary, "observer-test.jsonl").write_bytes(b"existing\n")
            with self.assertRaises(FileExistsError):
                JournalStreamRecorder(temporary, "observer-test")

    def test_nonzero_ssh_exit_prevents_complete_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            recorder = JournalStreamRecorder(temporary, "observer-test")
            recorder.feed(_line("cursor-1"))
            manifest = recorder.close(process_exit_code=255)
            self.assertFalse(manifest["complete"])


if __name__ == "__main__":
    unittest.main()
