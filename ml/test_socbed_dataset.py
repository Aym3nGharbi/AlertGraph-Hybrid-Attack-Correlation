import unittest

from socbed_dataset import _endpoint, member_names, observed_stage


class SocbedDatasetTests(unittest.TestCase):
    def test_member_names(self):
        self.assertEqual(
            member_names("host1_bestpractice_03"),
            (
                "host1_bestpractice/attackconsole_03.log",
                "host1_bestpractice/sigma_03.jsonl",
                "host1_bestpractice/syslog_03.jsonl",
            ),
        )

    def test_endpoint(self):
        self.assertEqual(_endpoint("10.0.0.1:443"), ("10.0.0.1", 443))
        self.assertEqual(_endpoint("1.2.3.4"), ("1.2.3.4", None))

    def test_observed_mapping_does_not_need_truth(self):
        self.assertEqual(
            observed_stage("sigma", "Windows PowerShell Web Request"),
            "COMMAND_AND_CONTROL",
        )
        self.assertIsNone(observed_stage("suricata", "unseen rule"))


if __name__ == "__main__":
    unittest.main()
