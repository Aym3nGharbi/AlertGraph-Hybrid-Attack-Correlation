import unittest

import numpy as np
import pandas as pd

from experiment_multi_proof_component_unions import (
    independent_packages,
    multi_proof_reconstruction,
    safe_seed_mask,
)


def meta(ids, signatures, entities):
    return pd.DataFrame(
        {
            "meta_id": ids,
            "signature": signatures,
            "entities": entities,
        }
    )


def pairs(edges, *, local=None, same_signature=None, compatible=None, non_malicious=None):
    size = len(edges)
    return pd.DataFrame(
        {
            "earlier_meta_id": [a for a, _ in edges],
            "later_meta_id": [b for _, b in edges],
            "local_window_evidence": np.ones(size, dtype=int) if local is None else local,
            "shared_entity_count": np.ones(size, dtype=int),
            "non_malicious_stage_present": np.zeros(size, dtype=int) if non_malicious is None else non_malicious,
            "same_signature": np.ones(size, dtype=int) if same_signature is None else same_signature,
            "stage_known_both": np.ones(size, dtype=int),
            "same_stage": np.zeros(size, dtype=int),
            "forward_progression_compatible": np.ones(size, dtype=int) if compatible is None else compatible,
            "target": np.ones(size, dtype=int),
            "label_confidence": ["high"] * size,
        }
    )


class MultiProofComponentUnionTests(unittest.TestCase):
    def test_singleton_compound_local_transition_can_seed(self):
        nodes = meta(["a", "b"], ["sig-a", "sig-b"], [["host:x"], ["host:x"]])
        frame = pairs([("a", "b")], same_signature=np.array([0]))
        mask = safe_seed_mask(frame, nodes, np.array([True]), np.array([4]))
        np.testing.assert_array_equal(mask, [True])

    def test_single_long_transition_remains_soft_and_visible(self):
        nodes = meta(["a", "b"], ["sig-a", "sig-b"], [["host:x"], ["host:x"]])
        frame = pairs([("a", "b")], local=np.array([0]), same_signature=np.array([0]))
        result = multi_proof_reconstruction(
            nodes, frame, np.array([True]), np.array([4]), np.array([4]), np.array([0.9])
        )
        np.testing.assert_array_equal(result["union_edges"], [False])
        np.testing.assert_array_equal(result["soft_relations"], [True])

    def test_harrison_repetitions_form_one_package(self):
        nodes = meta(
            ["a1", "a2", "a3", "b1", "b2", "b3"],
            ["A-All-Evt", "W-All-Ids", "2027865", "2027863", "2027863", "2027863"],
            [["ip:192.168.128.1"]] * 6,
        )
        frame = pairs(
            [("a1", "b1"), ("a2", "b2"), ("a3", "b3")],
            same_signature=np.zeros(3, dtype=int),
            compatible=np.zeros(3, dtype=int),
        )
        left = np.array([0, 1, 2]); right = np.array([3, 4, 5])
        packages = independent_packages(
            np.arange(3), np.zeros(3, dtype=bool), np.arange(3), left, right,
            [frozenset(x) for x in nodes.entities], nodes.signature.to_numpy(), nodes.meta_id.to_numpy(),
        )
        self.assertEqual(len(packages), 1)

    def test_harrison_repetitions_do_not_merge_seeded_components(self):
        nodes = meta(
            ["a1", "a2", "a3", "b1", "b2", "b3"],
            ["sa1", "sa2", "sa3", "2027863", "2027863", "2027863"],
            [
                ["host:a", "ip:192.168.128.1"],
                ["host:a", "ip:192.168.128.1"],
                ["host:a", "ip:192.168.128.1"],
                ["host:b", "ip:192.168.128.1"],
                ["host:b", "ip:192.168.128.1"],
                ["host:b", "ip:192.168.128.1"],
            ],
        )
        frame = pairs(
            [
                ("a1", "a2"), ("a2", "a3"),
                ("b1", "b2"), ("b2", "b3"),
                ("a1", "b1"), ("a2", "b2"), ("a3", "b3"),
            ],
            same_signature=np.array([0, 0, 1, 1, 0, 0, 0]),
            compatible=np.array([1, 1, 1, 1, 0, 0, 0]),
        )
        result = multi_proof_reconstruction(
            nodes, frame, np.ones(7, dtype=bool), np.zeros(7, dtype=int),
            np.full(7, 4), np.linspace(.99, .90, 7),
        )
        self.assertNotEqual(result["membership"][0], result["membership"][3])
        np.testing.assert_array_equal(result["soft_relations"][4:], [True, True, True])

    def test_generic_pivot_chain_is_not_two_independent_packages(self):
        nodes = meta(
            ["attack-a", "pivot", "attack-b"],
            ["A-All-Evt", "dns-event", "A-All-Evt"],
            [["host:dns"], ["host:dns"], ["host:dns"]],
        )
        frame = pairs(
            [("attack-a", "pivot"), ("pivot", "attack-b")],
            local=np.zeros(2, dtype=int), same_signature=np.zeros(2, dtype=int),
        )
        left=np.array([0,1]); right=np.array([1,2])
        packages = independent_packages(
            np.arange(2), np.zeros(2,dtype=bool), np.arange(2), left, right,
            [frozenset(x) for x in nodes.entities], nodes.signature.to_numpy(), nodes.meta_id.to_numpy(),
        )
        self.assertEqual(len(packages), 1)

    def test_old_core_edge_is_validated_not_automatically_accepted(self):
        nodes = meta(["a", "b"], ["sig-a", "sig-b"], [["host:x"], ["host:x"]])
        frame = pairs([("a", "b")], local=np.array([0]), same_signature=np.array([0]))
        result = multi_proof_reconstruction(
            nodes, frame, np.array([True]), np.array([8]), np.array([8]), np.array([0.99])
        )
        self.assertFalse(result["union_edges"][0])
        self.assertTrue(result["soft_relations"][0])

    def test_consumed_evidence_cannot_be_counted_again(self):
        nodes = meta(["a", "b"], ["sa", "sb"], [["host:a"], ["host:b"]])
        left = np.array([0, 0]); right = np.array([1, 1])
        consumed = np.array([True, False])
        packages = independent_packages(
            np.arange(2), consumed, np.arange(2), left, right,
            [frozenset(x) for x in nodes.entities], nodes.signature.to_numpy(), nodes.meta_id.to_numpy(),
        )
        self.assertEqual(len(packages), 1)
        np.testing.assert_array_equal(packages[0], [1])

    def test_primary_and_reverse_orders_are_deterministic_on_supported_graph(self):
        nodes = meta(
            ["a1", "a2", "b1", "b2"],
            ["sa1", "sa2", "sb1", "sb2"],
            [["host:a"], ["host:a"], ["host:b"], ["host:b"]],
        )
        frame = pairs(
            [("a1", "a2"), ("b1", "b2"), ("a1", "b1"), ("a2", "b2")],
            local=np.array([1, 1, 0, 0]), same_signature=np.zeros(4,dtype=int),
            compatible=np.ones(4,dtype=int),
        )
        args=(nodes,frame,np.ones(4,dtype=bool),np.zeros(4,dtype=int),np.full(4,4),np.array([.95,.94,.9,.8]))
        first=multi_proof_reconstruction(*args,application_order="primary")
        second=multi_proof_reconstruction(*args,application_order="reverse")
        np.testing.assert_array_equal(first["membership"],second["membership"])
        self.assertEqual(int(first["union_edges"].sum()),3)


if __name__ == "__main__":
    unittest.main()
