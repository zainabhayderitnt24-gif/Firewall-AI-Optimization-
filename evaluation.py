"""Reproducible, synthetic-only experimental evaluation for the firewall optimizer."""
from pathlib import Path
from time import perf_counter
from ipaddress import IPv4Address
from statistics import median
import random
import pandas as pd
from analysis import analyze, parse_rules, optimize, filter_packet
from ai_model import detect_anomalies

ROOT = Path(__file__).resolve().parent

# The class labels describe how the small benchmark was deliberately generated.
# "independent rule" is NOT a ground truth label of a malicious/anomalous rule.
LABEL_TO_FINDING = {
    'base rule': 'OK',
    'base DNS rule': 'OK',
    'base SSH deny rule': 'OK',
    'independent rule': 'OK',
    'duplicate of group base': 'Duplicate',
    'duplicate of DNS rule': 'Duplicate',
    'same-action redundant': 'Redundant / shadowed (same action)',
    'shadowed opposite-action': 'Shadowed (opposite action)',
}


def load_benchmark():
    rules = pd.read_csv(ROOT / 'data' / 'benchmark_60_rules.csv', dtype=str, keep_default_na=False)
    labels = pd.read_csv(ROOT / 'data' / 'benchmark_60_labels.csv', dtype=str, keep_default_na=False)
    return rules, labels


def labeled_evaluation(frame, labels, contamination=0.15):
    rules = parse_rules(frame)
    findings = analyze(rules)
    ai = detect_anomalies(rules, contamination=contamination)
    merged = labels.merge(findings, on='rule_id', how='left', validate='one_to_one').merge(
        ai, on='rule_id', validate='one_to_one')
    if merged['finding'].isna().any() or len(merged) != len(frame):
        raise ValueError('Ground truth does not match rule identifiers.')
    merged['expected_finding'] = merged['synthetic_design_label'].map(LABEL_TO_FINDING)
    if merged['expected_finding'].isna().any():
        raise ValueError('Unexpected synthetic design label')
    merged['class_match'] = merged['expected_finding'].eq(merged['finding'])
    design_problem = merged['expected_finding'].ne('OK')
    detected_problem = merged['finding'].ne('OK')
    tp = int((design_problem & detected_problem).sum())
    fp = int((~design_problem & detected_problem).sum())
    fn = int((design_problem & ~detected_problem).sum())
    precision = tp / (tp + fp) if tp+fp else None
    recall = tp / (tp + fn) if tp+fn else None
    f1 = 2*precision*recall/(precision+recall) if precision is not None and recall is not None and precision+recall else None
    # Exploratory proxy only: AI selection of deliberately independent rules.
    # Not a security anomaly detection metric.
    independent = merged['synthetic_design_label'].eq('independent rule')
    ai_review = merged['ai_flag'].eq('Review')
    tp_proxy = int((independent & ai_review).sum())
    fp_proxy = int((~independent & ai_review).sum())
    fn_proxy = int((independent & ~ai_review).sum())
    proxy_precision = tp_proxy / (tp_proxy + fp_proxy) if tp_proxy+fp_proxy else None
    proxy_recall = tp_proxy / (tp_proxy + fn_proxy) if tp_proxy+fn_proxy else None
    proxy_f1 = 2*proxy_precision*proxy_recall/(proxy_precision+proxy_recall) if proxy_precision is not None and proxy_recall is not None and proxy_precision+proxy_recall else None
    return merged, {
        'total_rules': len(merged), 'correct_exact_classes': int(merged['class_match'].sum()),
        'deterministic_tp': tp, 'deterministic_fp': fp, 'deterministic_fn': fn,
        'deterministic_precision': precision, 'deterministic_recall': recall, 'deterministic_f1': f1,
        'ai_review_count': int(ai_review.sum()),
        'independent_rules': int(independent.sum()),
        'ai_independent_proxy_tp': tp_proxy, 'ai_independent_proxy_fp': fp_proxy,
        'ai_independent_proxy_fn': fn_proxy,
        'ai_independent_proxy_precision': proxy_precision,
        'ai_independent_proxy_recall': proxy_recall, 'ai_independent_proxy_f1': proxy_f1,
    }


def synthetic_rules(groups):
    """Generate distinct 12-rule groups; 12..300 rules for controlled scaling."""
    if not 1 <= groups <= 25:
        raise ValueError('1..25 groups supported')
    entries = []
    for g in range(groups):
        dest = f'192.168.{20+g}.0/24'
        host = lambda h: f'192.168.{20+g}.{h}'
        src = f'10.{g}.0.0/16'
        srcdns = f'10.{100+g}.0.0/16'
        srchost = f'10.{150+g}.0.0/27'
        group = [
            (src,dest,'any','443','tcp','allow'),
            (src,dest,'any','443','tcp','allow'),
            (f'10.{g}.1.0/24',host(10),'any','443','tcp','allow'),
            (f'10.{g}.2.0/24',host(11),'any','443','tcp','deny'),
            (srcdns,dest,'any','53','udp','allow'),
            (srcdns,dest,'any','53','udp','allow'),
            (f'10.{100+g}.50.0/24',host(8),'any','53','udp','deny'),
            (srchost,host(5),'any','22','tcp','deny'),
            (f'10.{150+g}.0.5',host(5),'any','22','tcp','allow'),
            (f'10.{200+g}.0.0/27',f'10.{180+g}.0.0/27','any','8080','tcp','allow'),
            ('any',dest,'any','80','tcp','deny'),
            (f'10.{220+g}.0.0/24',host(50),'any','8443','tcp','allow'),
        ]
        for t,attrs in enumerate(group,1):
            idx=12*g+t
            entries.append((f'S{idx:03d}',idx,*attrs))
    return pd.DataFrame(entries,columns=['rule_id','priority','src_ip','dst_ip','src_port','dst_port','protocol','action'])


def random_packet(rng, rules):
    # Target actual rule regions often, not just easy default-deny traffic.
    r = rng.choice(rules)
    def addr(network):
        if network.prefixlen == 0:
            return str(IPv4Address(rng.choice([0x0a000001,0xc0a80011,0xcb007105,0x08080808])))
        lo = int(network.network_address)
        size = network.num_addresses
        return str(IPv4Address(lo + rng.randrange(size)))
    def port(interval):
        lo,hi=interval
        return rng.choice([lo,hi,rng.randint(lo,hi)])
    proto = r.protocol if r.protocol != 'any' else rng.choice(['tcp','udp'])
    return addr(r.src_ip),addr(r.dst_ip),port(r.src_port),port(r.dst_port),proto


def packet_consistency(frame, samples=3000, seed=2026):
    rules = parse_rules(frame)
    reduced = parse_rules(optimize(frame,analyze(rules)))
    rng = random.Random(seed)
    unchanged = 0
    allow_count = 0
    deny_count = 0
    for _ in range(samples):
        packet = random_packet(rng,rules)
        before = filter_packet(rules,*packet)
        after = filter_packet(reduced,*packet)
        unchanged += before == after
        allow_count += before == 'allow'
        deny_count += before == 'deny'
    return {'samples': samples,'matching_decisions': unchanged,'allow_before': allow_count,'deny_before': deny_count}


def run_scaling_benchmarks(repetitions=3, packets=3000):
    """Local software timings, not cloud service latency or firewall throughput."""
    original12 = pd.read_csv(ROOT/'data'/'sample_rules.csv',dtype=str,keep_default_na=False)
    original60,_ = load_benchmark()
    cases = [('Built-in 12', original12),('Labeled 60',original60),
             ('Generated 120',synthetic_rules(10)),('Generated 300',synthetic_rules(25))]
    rows=[]
    for label,frame in cases:
        rules=parse_rules(frame)
        times=[]
        for _ in range(repetitions):
            start=perf_counter()
            report=analyze(rules)
            detect_anomalies(rules,contamination=.15)
            _ = optimize(frame, report)
            times.append((perf_counter()-start)*1000)
        removal=int(analyze(rules)['safe_to_remove'].sum())
        checks=packet_consistency(frame,samples=packets,seed=2026)
        rows.append({'dataset':label,'original_rules':len(frame),'removed_rules':removal,
                     'optimized_rules':len(frame)-removal,'reduction_percent':round(100*removal/len(frame),2),
                     'median_analysis_ai_ms':round(median(times),2),
                     'packets_checked':checks['samples'],'matching_packet_decisions':checks['matching_decisions'],
                     'allow_decisions':checks['allow_before'],'deny_decisions':checks['deny_before']})
    return pd.DataFrame(rows)


if __name__ == '__main__':
    rules,labels=load_benchmark()
    _,metrics=labeled_evaluation(rules,labels)
    print('LABELS AND AI PROXY:', metrics)
    print('SCALING RESULTS:')
    print(run_scaling_benchmarks().to_string(index=False))
