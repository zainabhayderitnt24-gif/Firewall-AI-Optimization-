# v1.2 — supervisor-requested experiments

Measured locally with the supplied v1.1 GitHub snapshot as the starting point (commit 5acbf76087d7633eb6fb62b1c5d1cea74999a56b). All data are synthetic. The new Streamlit UI has been implemented and syntax-checked, but the Streamlit package was unavailable in the local test environment, so cloud deployment and UI interaction must still be verified on the existing app.

## Scalability

| Rules | Removed | Remaining | Rule analysis (ms) | Full pipeline (ms) | Sampled matches |
|---:|---:|---:|---:|---:|---:|
| 100 | 26 | 74 | 4.21 | 160.78 | 300/300 |
| 500 | 126 | 374 | 20.61 | 272.09 | 300/300 |
| 1000 | 251 | 749 | 44.99 | 373.68 | 300/300 |
| 2000 | 501 | 1499 | 103.78 | 621.43 | 300/300 |
| 5000 | 1251 | 3749 | 427.70 | 1632.94 | 300/300 |

Each time is a median of three measurements on the local development host. The pipeline includes parsing, rule analysis, the original Isolation Forest screening and optimization/output parsing. The stage medians need not sum to the total median. Dataset creation, plotting and packet checks are excluded. A total of 1,500 sampled packet decisions matched. The data contain structured repeated patterns; the reduction fraction is a property of this design, not a real-world guarantee.

## Held-out synthetic anomaly comparison

| Algorithm | Accuracy | Precision | Recall | F1 | ROC-AUC | Model time (ms) |
|---|---:|---:|---:|---:|---:|---:|
| Isolation Forest | 0.8663 | 0.2462 | 0.1533 | 0.1871 | 0.6697 | 185.02 |
| Local Outlier Factor | 0.9257 | 0.6039 | 0.7867 | 0.6817 | 0.9264 | 29.37 |
| One-Class SVM | 0.9287 | 0.6110 | 0.8000 | 0.6924 | 0.8994 | 8.30 |

Three seeds; each uses 600 normal training rules, 300 normal calibration rules, and 1,000 held-out test rules (100 injected anomalies). Shared train-fitted scaling, common features excluding priority, same nominal 5% false-positive calibration target. The mean F1 was highest for One-Class SVM on this benchmark, while LOF had the highest mean ROC-AUC. Isolation Forest had low recall here; features constant in normal training (e.g., any protocol) or out-of-range values can be difficult to distinguish with tree splits. This is a possible explanation, not a demonstrated causal attribution. The benchmark uses fixed hyperparameters and deliberately constructed distributions; it does not establish universal model superiority. Accuracy alone is misleading because 90% of test cases are normal. The main application retains Isolation Forest and deterministic safe-removal logic.

## Evidence and reproduction

See `results/v1.2_local/` for five CSVs, two Matplotlib PNGs, environment metadata, and test log. Run `python advanced_evaluation.py` to regenerate measurements. In the cloud UI, run each new Evaluation button and download the corresponding CSVs and PNGs. Use the cloud-generated timing table if reporting cloud execution time. The historical v1.1 evidence is retained in `RESULTS.md`.

Seventeen automated tests passed. These tests and the benchmark do not replace real firewall testing.
