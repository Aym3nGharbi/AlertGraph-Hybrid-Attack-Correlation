import unittest
from datetime import datetime

from darpa_dataset import EASTERN, _phase_for_alert, OfficialSession, observed_stage


class DarpaDatasetTest(unittest.TestCase):
    def test_dst_conversion_matches_pcap_epoch(self):
        winter = datetime(2000, 3, 7, 10, 33, 10, tzinfo=EASTERN)
        summer = datetime(2000, 4, 16, 15, 17, 44, tzinfo=EASTERN)
        self.assertEqual(winter.utcoffset().total_seconds(), -5 * 3600)
        self.assertEqual(summer.utcoffset().total_seconds(), -4 * 3600)

    def test_phase_requires_time_and_endpoint_match(self):
        session = OfficialSession(3, 100.0, 110.0, "1.1.1.1", "2.2.2.2")
        index = {("1.1.1.1", "2.2.2.2"): [session]}
        self.assertEqual(_phase_for_alert(105.0, "2.2.2.2", "1.1.1.1", index), 3)
        self.assertIsNone(_phase_for_alert(120.0, "1.1.1.1", "2.2.2.2", index))

    def test_observed_stage_does_not_use_truth(self):
        self.assertEqual(observed_stage("GPL RPC portmap sadmind request UDP"), "VULN_DISC")
        self.assertEqual(observed_stage("GPL RPC sadmind root exploit"), "PUBLIC_APP_EXP")
        self.assertIsNone(observed_stage("ET INFO ordinary browser header"))


if __name__ == "__main__":
    unittest.main()
