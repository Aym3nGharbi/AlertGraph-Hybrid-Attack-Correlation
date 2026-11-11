import unittest

from baseline_scores import causal_score, manual_hybrid_score, similarity_score


def features(**updates):
    values = {
        "delta_seconds": 10.0,
        "shared_ip_count": 1,
        "shared_host_count": 1,
        "service_overlap": 1,
        "signature_text_jaccard": 0.8,
        "non_malicious_stage_present": 0,
        "stage_known_both": 1,
        "forward_progression_compatible": 1,
        "same_stage": 0,
    }
    values.update(updates)
    return values


class BaselineScoresTest(unittest.TestCase):
    def test_similarity_rewards_close_shared_observables(self) -> None:
        close = similarity_score(features())
        distant = similarity_score(
            features(
                delta_seconds=120,
                shared_ip_count=0,
                shared_host_count=0,
                service_overlap=0,
                signature_text_jaccard=0,
            )
        )
        self.assertGreater(close, distant)

    def test_causality_distinguishes_known_compatible_and_unknown(self) -> None:
        self.assertEqual(causal_score(features()), 1.0)
        self.assertEqual(causal_score(features(stage_known_both=0)), 0.15)
        self.assertEqual(
            causal_score(features(non_malicious_stage_present=1)), 0.05
        )

    def test_manual_hybrid_is_convex_combination(self) -> None:
        values = features()
        score = manual_hybrid_score(values, alpha=0.65)
        expected = 0.65 * similarity_score(values) + 0.35 * causal_score(values)
        self.assertAlmostEqual(score, expected)


if __name__ == "__main__":
    unittest.main()
