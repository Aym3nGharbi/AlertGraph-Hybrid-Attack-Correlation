import tempfile
import unittest
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq

from evaluate_nested_baselines import load_scores, metrics


class NestedBaselinesTest(unittest.TestCase):
    def test_loads_scores_without_ground_truth_features(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            scenario = Path(temporary) / "demo"
            scenario.mkdir()
            pq.write_table(
                pa.Table.from_pylist(
                    [
                        {
                            "delta_seconds": 1.0,
                            "shared_ip_count": 1,
                            "shared_host_count": 1,
                            "service_overlap": 1,
                            "signature_text_jaccard": 1.0,
                            "non_malicious_stage_present": 0,
                            "stage_known_both": 1,
                            "forward_progression_compatible": 1,
                            "same_stage": 0,
                            "target": 1,
                        },
                        {
                            "delta_seconds": 100.0,
                            "shared_ip_count": 0,
                            "shared_host_count": 0,
                            "service_overlap": 0,
                            "signature_text_jaccard": 0.0,
                            "non_malicious_stage_present": 0,
                            "stage_known_both": 0,
                            "forward_progression_compatible": 0,
                            "same_stage": 0,
                            "target": 0,
                        },
                    ]
                ),
                scenario / "pair_examples.parquet",
            )
            data = load_scores(temporary, "demo")

        self.assertGreater(data["similarity"][0], data["similarity"][1])
        report = metrics(data["y"], data["similarity"], 0.5)
        self.assertEqual(report["f1"], 1.0)

    def test_rejects_non_positive_window(self) -> None:
        with self.assertRaises(ValueError):
            load_scores("unused", "demo", window_seconds=0)


if __name__ == "__main__":
    unittest.main()
