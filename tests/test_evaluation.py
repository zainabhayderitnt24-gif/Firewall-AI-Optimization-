import unittest
from evaluation import (load_benchmark, labeled_evaluation,
                        packet_consistency, synthetic_rules)
from analysis import parse_rules, analyze, optimize

class EvaluationTests(unittest.TestCase):
    def test_60_labeled_design_matches(self):
        frame, ground = load_benchmark()
        merged, metrics=labeled_evaluation(frame,ground)
        self.assertEqual(metrics['total_rules'],60)
        self.assertEqual(metrics['correct_exact_classes'],60)
        self.assertEqual(int(merged['safe_to_remove'].sum()),15)
        self.assertEqual(metrics['ai_review_count'],9)
        self.assertEqual(metrics['independent_rules'],15)

    def test_synthetic_scaling_rule_sets(self):
        for groups in (1, 5, 10, 25):
            frame=synthetic_rules(groups)
            report=analyze(parse_rules(frame))
            self.assertEqual(int(report.safe_to_remove.sum()),3*groups)
            self.assertEqual(len(optimize(frame,report)),9*groups)

    def test_sampled_packet_equivalence_60_and_120(self):
        frame,_=load_benchmark()
        for test_frame in (frame,synthetic_rules(10)):
            checked=packet_consistency(test_frame,samples=400,seed=10)
            self.assertEqual(checked['matching_decisions'],400)
            self.assertGreater(checked['allow_before'],0)
            self.assertGreater(checked['deny_before'],0)

if __name__ == '__main__':
    unittest.main()
