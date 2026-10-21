import random
import unittest
from pathlib import Path

import pandas as pd

from analysis import analyze, contains, filter_packet, optimize, parse_rules
from ai_model import detect_anomalies

ROOT = Path(__file__).resolve().parents[1]


class FirewallRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.frame = pd.read_csv(ROOT / "data" / "sample_rules.csv", dtype=str, keep_default_na=False)
        cls.rules = parse_rules(cls.frame)
        cls.report = analyze(cls.rules)

    def test_detection_cases(self):
        d = self.report.set_index("rule_id")
        self.assertEqual(d.loc["R02", "finding"], "Duplicate")
        self.assertEqual(d.loc["R03", "finding"], "Redundant / shadowed (same action)")
        self.assertEqual(d.loc["R05", "finding"], "Shadowed (opposite action)")
        self.assertTrue(bool(d.loc["R02", "safe_to_remove"]))
        self.assertFalse(bool(d.loc["R05", "safe_to_remove"]))

    def test_removal_preserves_policy_on_2000_diverse_packets(self):
        optimized = optimize(self.frame, self.report)
        new_rules = parse_rules(optimized)
        self.assertEqual(len(optimized), len(self.frame) - 2)
        rng = random.Random(37)
        for i in range(2000):
            prefixes = ["10.", "172.16.", "192.168.", "203.0.", "198.51.", "192.0."]
            prefix = prefixes[i % len(prefixes)]
            def ip(prefix):
                return prefix + ".".join(str(rng.randrange(256)) for _ in range(4 - len(prefix.strip(".").split("."))))
            src = ip(prefix)
            dst = rng.choice(["192.168.1.22", "192.168.1.10", "192.168.3.5", "198.51.100.8"])
            p = rng.choice([22, 53, 80, 443, 8080, rng.randrange(65536)])
            proto = rng.choice(["tcp", "udp"])
            packet = (src, dst, rng.randrange(65536), p, proto)
            self.assertEqual(filter_packet(self.rules, *packet), filter_packet(new_rules, *packet))

    def test_overlap_and_detection_with_changed_action(self):
        fr = pd.DataFrame([
            dict(rule_id="A", priority=1, src_ip="10.0.0.0/8", dst_ip="any", src_port="any", dst_port="443", protocol="tcp", action="deny"),
            dict(rule_id="B", priority=2, src_ip="10.1.1.0/24", dst_ip="any", src_port="any", dst_port="443", protocol="tcp", action="allow"),
        ])
        rr = parse_rules(fr)
        re = analyze(rr).set_index("rule_id")
        self.assertEqual(re.loc["B", "finding"], "Shadowed (opposite action)")
        self.assertFalse(bool(re.loc["B", "safe_to_remove"]))

    def test_invalid_ipv6_not_accepted(self):
        fr = self.frame.copy()
        fr.loc[0, "src_ip"] = "2001:db8::1"
        with self.assertRaisesRegex(ValueError, "IPv4"):
            parse_rules(fr)

    def test_bad_port_not_accepted(self):
        fr = self.frame.copy()
        fr.loc[0, "dst_port"] = "70000"
        with self.assertRaises(ValueError):
            parse_rules(fr)

    def test_ai_model_produces_scores(self):
        result = detect_anomalies(self.rules)
        self.assertEqual(len(result), len(self.rules))
        self.assertTrue(result["anomaly_score"].notna().all())
        self.assertTrue(set(result["ai_flag"]).issubset({"Review", "Typical"}))

    def test_ip_containment(self):
        self.assertTrue(contains(self.rules[0], self.rules[2]))


if __name__ == "__main__":
    unittest.main()
