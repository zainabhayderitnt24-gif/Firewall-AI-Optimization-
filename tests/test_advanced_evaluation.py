import unittest
import random
import pandas as pd
from pandas.testing import assert_frame_equal
from analysis import COLUMNS, analyze, analyze_reference, parse_rules, optimize, filter_packet, match_packet
from advanced_evaluation import SIZES, scaling_rules, scalability, algorithm_comparison, anomaly_data, METHODS
from evaluation import random_packet, load_benchmark

class AdvancedTests(unittest.TestCase):
    def test_old_and_vectorized_results(self):
        frame,_=load_benchmark()
        for data in (frame, scaling_rules(100),scaling_rules(500)):
            rules=parse_rules(data)
            assert_frame_equal(analyze(rules),analyze_reference(rules))

    def test_reference_random_mixed_ranges(self):
        rng=random.Random(44)
        networks=['any','10.0.0.0/8','10.1.0.0/16','10.1.2.0/24','10.1.2.5','192.0.2.0/24','192.0.2.5','198.51.100.0/24']
        ports=['any','20-100','80-443','80','443','5000-6000']
        for k in range(8):
            rows=[(f'R{i}',i,rng.choice(networks),rng.choice(networks),rng.choice(ports),rng.choice(ports),rng.choice(['tcp','udp','any']),rng.choice(['allow','deny'])) for i in range(100)]
            rules=parse_rules(pd.DataFrame(rows,columns=COLUMNS))
            assert_frame_equal(analyze(rules),analyze_reference(rules))
            for _ in range(100):
                packet=random_packet(rng,rules)
                expected=next((r.action for r in rules if match_packet(r,*packet)), 'deny')
                self.assertEqual(filter_packet(rules,*packet),expected)

    def test_exact_scaling_sizes_and_reduction(self):
        for n in SIZES:
            frame=scaling_rules(n); rules=parse_rules(frame); report=analyze(rules)
            self.assertEqual(len(rules),n)
            expected=3*(n//12)+sum(i<=n%12 for i in (2,3,6))
            self.assertEqual(int(report.safe_to_remove.sum()),expected)
            self.assertEqual(len(optimize(frame,report)),n-expected)

    def test_scaling_measured_output(self):
        summary,trials=scalability(repetitions=2,packet_samples=50,sizes=(100,500))
        self.assertEqual(len(trials),4)
        self.assertTrue((summary.median_total_ms>0).all())
        self.assertTrue((summary.matching_decisions==summary.packets_checked).all())

    def test_comparison_holdout_predictions(self):
        summary,trials,pred=algorithm_comparison(seeds=(42,),normal_training=80,normal_calibration=40,normal_test=90,anomalies_test=10)
        self.assertEqual(tuple(summary.algorithm),METHODS)
        self.assertEqual(len(pred),300)
        self.assertEqual(len(trials),3)
        self.assertTrue(((trials.tp+trials.fn)==10).all())
        self.assertTrue(((trials.tn+trials.fp)==90).all())
        self.assertTrue(((summary.mean_f1>=0)&(summary.mean_f1<=1)).all())

    def test_anomaly_label_reproducibility(self):
        f,l=anomaly_data(112,90,10); g,m=anomaly_data(112,90,10)
        assert_frame_equal(f,g); assert_frame_equal(l,m)
        self.assertEqual(l.is_anomaly.sum(),10)
        self.assertEqual(list(f.rule_id),list(l.rule_id))
        self.assertEqual(len(parse_rules(f)),100)

    def test_optimization_numeric_order_and_trimmed_ids(self):
        f=pd.DataFrame([(' A ',2,'any','any','any','443','tcp','allow'),(' B ',10,'any','any','any','443','tcp','allow'),('C',11,'any','any','any','22','tcp','deny')],columns=COLUMNS).astype(str)
        out=optimize(f,analyze(parse_rules(f)))
        self.assertEqual(list(out.rule_id),[' A ','C'])

if __name__=='__main__': unittest.main()
