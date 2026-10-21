# Practical implementation — experimental evidence (v1.1)

Research title: **Implementation of a Firewall Rule Optimization System Using AI Techniques**
Student: **Tabarak** (full name / department / supervisor not yet provided).

## Built-in datasets and output

| Dataset | Original | Removable | Optimized | Reduction |
|---|---:|---:|---:|---:|
| 12-rule demonstration | 12 | 2 | 10 | 16.67% |
| 60-rule labeled synthetic dataset | 60 | 15 | 45 | 25.00% |
| 120-rule generated synthetic dataset | 120 | 30 | 90 | 25.00% |
| 300-rule generated synthetic dataset | 300 | 75 | 225 | 25.00% |

The deployed v1.0 app was seen operating in the user's screenshots and produced the uploaded 12-rule and 60-rule reports. The 120- and 300-rule experiments were executed locally on the bundled Python implementation, and are reproducible in v1.1's Evaluation tab. The updated v1.1 has not yet been confirmed as deployed.

The original 60-rule report recorded 9 Isolation Forest review flags and 15 conservatively removable rules. On manually constructed labels the deterministic rule-analysis categories agree for 60 of 60 cases. The number of inserted design anomalies is 30 (10 duplicates, 5 redundant, 15 opposite-action shadowed). The deterministic check matched all 30; this does not estimate real-world detection accuracy.

Exploratory ML proxy: 9 flagged out of 15 deliberately independent rules; 9 corresponded to that label, yielding a proxy recall of 60% and proxy precision of 100%. **Independent != anomalous/insecure. Never report those percentages as cybersecurity attack-detection metrics.**

The packet consistency check sampled 3,000 packets per dataset, with unchanged filtering decisions in every generated sample. These checks are not an exhaustive proof. Within the defined ordered, stateless, first-match IPv4 TCP/UDP model, same-action full containment of a rule by an earlier rule supports its safe removal mathematically; the prototype does not implement all possible redundant-rule optimizations.

## Timing

Median of three repetitions of deterministic analysis + Isolation Forest execution on the local development environment; NOT real firewall throughput or measured cloud application latency. Results depend on runtime/host: see `results/local_scaling_and_packet_checks.csv`.

## Limitations

Simulated / deliberately labeled configurations only; no real production firewall, IPv6, connection-state tracking, real traffic traces, cloud-provider access-control API, traffic throughput or hardware performance were measured. AI prioritizes manual review, while removal safety is determined by deterministic analysis.

## Reproduce

- Run `python -m unittest discover -s tests -v` (10 automated tests).
- Run `python evaluation.py` to regenerate benchmark results.
- Deploy `app.py` on Streamlit and open `📊 Evaluation` → **Run evaluation**. Download benchmark comparisons and scaling results.

## Provenance

Initial 12-rule and 60-rule Streamlit reports supplied by the user on 2026-10-21. The new 120/300 measurements were generated in this environment from the packaged code on 2026-10-21. The benchmark data/labels were intentionally constructed for this academic prototype and are not an external network dataset.
