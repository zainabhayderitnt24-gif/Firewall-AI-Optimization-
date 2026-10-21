# Firewall AI Optimization — Cloud-Deployable Academic Application v1.0

**Title:** Implementation of a Firewall Rule Optimization System Using AI Techniques

This repository contains an end-to-end cloud-hostable web application for importing *simulated* or permission-cleared firewall configurations, analyzing rule anomalies, screening unusual patterns with Isolation Forest, recommending conservative rule removals, and generating comparative reports.

## Architecture

```
Browser → Streamlit Cloud (app.py)
        → CSV input validation (analysis.py)
        → Rule relations: duplicates, redundancy, shadowing, overlaps
        → Isolation Forest anomaly scores (ai_model.py)
        → Safe same-action rule removal (analysis.py)
        → Dashboard + CSV/TXT exports + packet inspection
```

**No physical firewall, router, switch, or purchased server is needed.** Streamlit Community Cloud runs the Python code on a hosted machine. Users access the app by browser.

## Deploy on Streamlit Community Cloud

1. Extract the ZIP. Open the **inner folder** `firewall_ai_cloud_v1`.
2. Upload the **contents** (files AND `data/` directory) to the **root** of a public GitHub repository. Do not upload the ZIP as a single file; ensure `app.py` and `requirements.txt` are directly visible at the repository root. You can also upload `tests/`.
3. Commit the changes to the repository's `main` branch.
4. Go to https://share.streamlit.io → **Create app** → **Deploy a public app from GitHub**.
5. Select your repository, branch `main`, and main file path `app.py`, then select **Deploy**.
6. Wait for Streamlit to install the declared Python packages and load the application. Use the **Manage app → Logs** view if deployment encounters an error.

> GitHub repository contents will be public. Only synthetic/anonymized data should be committed. Do not commit passwords or access credentials.

## Local operation (optional)

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Input format

One CSV header line is mandatory:

`rule_id,priority,src_ip,dst_ip,src_port,dst_port,protocol,action`

Example:

`R01,1,10.0.0.0/8,192.168.1.0/24,any,443,tcp,allow`

- `priority`: unique integer, smaller = earlier evaluation
- `src_ip` / `dst_ip`: IPv4, CIDR or `any`
- `src_port` / `dst_port`: integer 0–65535, inclusive range `1000-2000` or `any`
- `protocol`: `tcp`, `udp`, `any`
- `action`: `allow`, `deny`
- Ordering: first matching rule wins; default action `deny`.

## What is implemented

- Rule CSV loading and validation, example dataset
- Duplicate detection, shadowing by a single earlier covering rule
- Same-action redundancy detection; overlapping opposite-action pair warnings
- Isolation Forest outlier scores, anomaly flags for manual review
- Conservative optimization removes only rules covered by an earlier same-action rule
- Before/after metrics, detection chart, downloadable optimized CSV and analysis files
- Interactive packet decision comparison

## Run software checks

```bash
python -m unittest discover -s tests -v
```

Testing is necessary for a credible academic project and is **not** a replacement for its working application.

## Scientific restrictions and future enhancements

- This project currently models a stateless **IPv4**, ordered, **first-match** TCP/UDP allow/deny firewall with **default deny**. It is *not* an operational hardware or cloud-provider firewall.
- The analyzer handles complete containment by **one earlier rule**. Cases covered by the union of several earlier rules are not detected.
- Opposite-action overlaps are shown for manual review; they are not automatically considered errors.
- Only same-action dominated rules are auto-removal candidates, rather than all potential redundancies. This intentionally sacrifices maximal compression to make the safety reasoning straightforward.
- The Isolation Forest model flags unusual patterns, not proven misconfigurations, security attacks, or guaranteed performance improvements.
- For final research evaluation, use larger deliberately labeled synthetic datasets and record precision/recall, reduction rates, and runtime. No throughput or cloud network latency measurements have been conducted by this prototype.
- Do not upload confidential configurations or real IP/rule lists without authorization.

## Evidence for graduation thesis

Suggested screenshots: main dashboard, rule analysis, AI detection, optimized rules, before/after packet check, exported reports, GitHub repo, and cloud app URL. Report actual observed values, not hypothetical numbers.
