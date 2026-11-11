import unittest

from traceability import audit_traceability, require_complete_traceability


class TraceabilityTests(unittest.TestCase):
    def test_complete_partition_is_reversible(self):
        report = audit_traceability(["a", "b", "c"], [["a", "b"], ["c"]])
        self.assertTrue(report["complete"])
        self.assertEqual(report["coverage"], 1.0)
        require_complete_traceability(report)

    def test_duplicate_or_missing_member_is_rejected(self):
        report = audit_traceability(["a", "b", "c"], [["a", "a"], ["c"]])
        self.assertFalse(report["complete"])
        self.assertEqual(report["missing_alert_ids"], ["b"])
        self.assertEqual(report["duplicate_member_alert_ids"], ["a"])
        with self.assertRaises(ValueError):
            require_complete_traceability(report)


if __name__ == "__main__":
    unittest.main()
