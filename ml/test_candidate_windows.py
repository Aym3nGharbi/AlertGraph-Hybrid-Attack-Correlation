import csv
import io
import unittest
from zipfile import ZIP_DEFLATED, ZipFile

from analyze_candidate_windows import analyze_zip


def fixture_zip() -> io.BytesIO:
    archive_bytes = io.BytesIO()
    with ZipFile(archive_bytes, "w", ZIP_DEFLATED) as archive:
        rows = io.StringIO(newline="")
        writer = csv.writer(rows)
        writer.writerow(
            ["time", "name", "ip", "host", "short", "time_label", "event_label"]
        )
        writer.writerow([0, "Successful sudo to ROOT executed.", "10.0.0.1", "web", "S-1", "service_scans", "service_scan"])
        writer.writerow([1, "Successful sudo to ROOT executed.", "10.0.0.1", "web", "S-1", "service_scans", "service_scan"])
        writer.writerow([5, "shell", "10.0.0.1", "web", "S-2", "webshell", "webshell_cmd"])
        writer.writerow([6, "noise", "10.0.0.2", "mail", "S-3", "false_positive", "-"])
        archive.writestr("alerts_csv/demo_alerts.txt", rows.getvalue())
    archive_bytes.seek(0)
    return archive_bytes


def interleaved_sensor_fixture_zip() -> io.BytesIO:
    """Reproduit l'ordre officiel : flux principal puis AMiner chevauchant."""

    archive_bytes = io.BytesIO()
    with ZipFile(archive_bytes, "w", ZIP_DEFLATED) as archive:
        rows = io.StringIO(newline="")
        writer = csv.writer(rows)
        writer.writerow(
            ["time", "name", "ip", "host", "short", "time_label", "event_label"]
        )
        writer.writerow([0, "first", "10.0.0.1", "web", "W-1", "dirb", "dirb"])
        writer.writerow([100, "last", "10.0.0.1", "web", "W-2", "dirb", "dirb"])
        writer.writerow([1, "AMiner: New event type.", "10.0.0.1", "web", "A-1", "dirb", "dirb"])
        archive.writestr("alerts_csv/demo_alerts.txt", rows.getvalue())
    archive_bytes.seek(0)
    return archive_bytes


class CandidateWindowsTest(unittest.TestCase):
    def test_measures_candidate_load_and_positive_coverage(self) -> None:
        report = analyze_zip(fixture_zip(), windows=(2, 10), caps=(1,))
        summary = report["summary"]

        self.assertEqual(summary["alerts"], 4)
        self.assertEqual(summary["attack_alerts_with_prior_same_entity"], 2)
        self.assertEqual(summary["repeated_signature_within_seconds"][1], 1)
        self.assertEqual(summary["windows"]["2"]["positive_predecessor_coverage_pct"], 50.0)
        self.assertEqual(summary["windows"]["10"]["positive_predecessor_coverage_pct"], 100.0)
        self.assertEqual(summary["windows"]["10"]["max_prior_candidates_same_entity"], 2)

    def test_collapses_repeats_for_analysis_without_changing_raw_count(self) -> None:
        report = analyze_zip(
            fixture_zip(), windows=(10,), caps=(1,), collapse_repeats_seconds=2
        )
        summary = report["summary"]

        self.assertEqual(summary["alerts"], 4)
        self.assertEqual(summary["analyzed_units"], 3)
        self.assertEqual(summary["collapsed_repeats"], 1)
        self.assertEqual(summary["observable_stage_mapping"]["meta_mapped"], 1)
        self.assertEqual(
            summary["observable_stage_mapping"]["meta_stage_counts"]["PRIV_ESC"], 1
        )

    def test_sorts_overlapping_sensor_streams_before_window_analysis(self) -> None:
        report = analyze_zip(
            interleaved_sensor_fixture_zip(), windows=(2,), caps=(10,)
        )
        summary = report["summary"]

        self.assertEqual(summary["non_monotonic_timestamps"], 1)
        self.assertEqual(summary["attack_alerts_with_prior_same_entity"], 2)
        self.assertEqual(
            summary["windows"]["2"]["positive_predecessor_coverage_pct"], 50.0
        )


if __name__ == "__main__":
    unittest.main()

