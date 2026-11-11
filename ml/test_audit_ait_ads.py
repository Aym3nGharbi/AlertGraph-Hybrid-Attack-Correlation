import csv
import io
import unittest
from zipfile import ZIP_DEFLATED, ZipFile

from audit_ait_ads import audit_zip


def fixture_zip() -> io.BytesIO:
    archive_bytes = io.BytesIO()
    with ZipFile(archive_bytes, "w", ZIP_DEFLATED) as archive:
        rows = io.StringIO(newline="")
        writer = csv.writer(rows)
        writer.writerow(
            ["time", "name", "ip", "host", "short", "time_label", "event_label"]
        )
        writer.writerow([1, "scan", "10.0.0.1", "web", "S-1", "service_scans", "service_scan"])
        writer.writerow([2, "noise", "10.0.0.2", "web", "S-2", "false_positive", "-"])
        archive.writestr("alerts_csv/demo_alerts.txt", rows.getvalue())
        archive.writestr("alerts_csv/second_alerts.txt", rows.getvalue())
    archive_bytes.seek(0)
    return archive_bytes


class AuditAitAdsTest(unittest.TestCase):
    def test_counts_labels_without_loading_extracted_files(self) -> None:
        report = audit_zip(fixture_zip())

        self.assertEqual(report["summary"]["total"], 4)
        self.assertEqual(report["summary"]["event_labeled"], 2)
        self.assertEqual(report["summary"]["event_coverage_pct"], 50.0)
        self.assertEqual(report["summary"]["raw_label_mismatches"], 2)
        self.assertEqual(report["scenarios"]["demo"]["time_labels"]["false_positive"], 1)
        self.assertIn("second", report["scenarios"])


if __name__ == "__main__":
    unittest.main()

