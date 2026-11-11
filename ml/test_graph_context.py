import math
import unittest

from graph_context import pair_graph_context, predecessor_index


class GraphContextTest(unittest.TestCase):
    def test_context_uses_candidate_predecessors_only(self) -> None:
        predecessors = predecessor_index(
            (("a", "c"), ("a", "d"), ("c", "d"))
        )
        context = pair_graph_context("c", "d", predecessors)

        self.assertEqual(context[0], math.log1p(1))
        self.assertEqual(context[1], math.log1p(2))
        self.assertEqual(context[2], math.log1p(1))
        self.assertAlmostEqual(context[3], 0.5)

    def test_isolated_earlier_node_has_zero_common_context(self) -> None:
        predecessors = predecessor_index((("a", "b"),))
        self.assertEqual(
            pair_graph_context("a", "b", predecessors),
            (0.0, math.log1p(1), 0.0, 0.0),
        )


if __name__ == "__main__":
    unittest.main()
