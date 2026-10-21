"""Cloud-based academic AI firewall rule optimizer (not a live firewall)."""
from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO
from ipaddress import IPv4Address
from pathlib import Path

import pandas as pd
import streamlit as st

from analysis import COLUMNS, analyze, filter_packet, optimize, parse_rules
from ai_model import detect_anomalies
from evaluation import load_benchmark, labeled_evaluation, run_scaling_benchmarks

st.set_page_config(page_title="Firewall AI Optimizer", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.block-container {padding-top: 2rem; padding-bottom: 3rem;}
h1 {font-size: 2.35rem !important;}
[data-testid="stMetric"] {border: 1px solid rgba(128,128,128,.28); border-radius: 12px; padding: 12px 16px;}
</style>
""", unsafe_allow_html=True)
st.title("🛡️ Cloud Firewall AI Optimizer")
st.caption("An explainable, AI-assisted analysis and optimization system for ordered IPv4 firewall rules")
st.caption("Academic graduation project prepared for Tabarak (full student name to be supplied)")
st.info("Academic software prototype • No hardware required • Does not access or modify a live firewall")

with st.sidebar:
    st.header("Analysis settings")
    contamination = st.slider(
        "Expected unusual-rule fraction", 0.05, 0.30, 0.15, 0.05,
        help="Isolation Forest threshold, not an estimated percentage of insecure rules.",
    )
    st.divider()
    st.subheader("Supported policy model")
    st.markdown("First match · Stateless · IPv4 · TCP/UDP · Allow/Deny · Default deny")
    st.caption("Priority: smaller number is evaluated first. Overlaps are findings, not automatic security violations.")
    st.divider()
    st.subheader("Input schema")
    st.code(", ".join(COLUMNS), language="text")
    st.caption("IPs: IPv4/CIDR/any. Ports: number, start-end/any. Protocol: tcp, udp, any.")

st.subheader("1 · Load rule configuration")
uploaded_file = st.file_uploader("Upload a CSV containing firewall rules (optional — built-in dataset is available)", type="csv")
source_label = "Uploaded CSV" if uploaded_file else "Built-in demonstration dataset"

try:
    sample_path = Path(__file__).resolve().parent / "data" / "sample_rules.csv"
    frame = pd.read_csv(uploaded_file if uploaded_file is not None else sample_path, dtype=str, keep_default_na=False)
    if len(frame) > 1500:
        raise ValueError("This cloud demo supports at most 1,500 rules per file. Please split the input.")
    rules = parse_rules(frame)
    frame = frame.copy()
    frame["priority"] = frame["priority"].astype(int)
    frame = frame.sort_values("priority").reset_index(drop=True)
    report = analyze(rules)
    ai_report = detect_anomalies(rules, contamination=contamination)
    combined = report.merge(ai_report, on="rule_id", how="left", validate="one_to_one")
    output = optimize(frame, report)
    output_rules = parse_rules(output)
except Exception as exc:
    st.error(f"Could not analyze firewall rules: {exc}")
    st.stop()

st.caption(f"Data source: {source_label}. The built-in data is illustrative, not measured firewall traffic.")
original_n, optimized_n = len(frame), len(output)
removal_n = original_n - optimized_n
review_n = int((combined["ai_flag"] == "Review").sum())

c1, c2, c3, c4 = st.columns(4)
c1.metric("Original rules", original_n)
c2.metric("Removable rules", removal_n)
c3.metric("Remaining rules", optimized_n)
c4.metric("AI review flags", review_n)

analysis_tab, optimize_tab, ai_tab, verify_tab, evidence_tab, help_tab = st.tabs([
    "🔎 Rule analysis", "✅ Optimization", "🧠 AI detection", "🔬 Packet verification", "📊 Evaluation", "📘 Methodology",
])

with analysis_tab:
    st.subheader("2 · Configuration analysis")
    st.dataframe(combined[["rule_id", "priority", "finding", "related_earlier_rules", "safe_to_remove"]],
                 hide_index=True, use_container_width=True)
    findings = combined["finding"].value_counts().rename_axis("Finding").reset_index(name="Rules")
    st.bar_chart(findings.set_index("Finding"), y="Rules")
    st.caption("Duplicate, redundancy, and shadowing checks are deterministic. Opposite-action overlap indicates a need for review; it is not necessarily an error.")

with optimize_tab:
    st.subheader("3 · Conservative, behavior-preserving optimization")
    if removal_n:
        st.success(f"Identified {removal_n} safe rule removal(s) out of {original_n}.")
        removable = combined[combined["safe_to_remove"]][["rule_id", "finding", "related_earlier_rules"]]
        st.dataframe(removable, hide_index=True, use_container_width=True)
    else:
        st.info("No safely removable rules were found by the supported single-cover analysis.")
    st.dataframe(output, hide_index=True, use_container_width=True)
    st.download_button("⬇ Download optimized rules (.csv)", data=output.to_csv(index=False).encode("utf-8"),
                       file_name="optimized_firewall_rules.csv", mime="text/csv")
    pct = 100.0 * removal_n / original_n
    st.metric("Rule reduction", f"{pct:.1f}%")
    st.caption("Each removed rule is fully covered by an earlier same-action rule. Therefore, under the stated first-match model, its removal cannot alter an allow/deny decision. This does not prove benefits to real firewall throughput.")

with ai_tab:
    st.subheader("4 · Machine-learning anomaly screening")
    if len(rules) < 8:
        st.warning("At least 8 rules are needed for meaningful execution of the current ML component.")
    else:
        st.caption("Isolation Forest assigns scores to unusual patterns in the selected rule set. Flags are for manual investigation, not labels of insecure or incorrect rules.")
    ai_table = combined[["rule_id", "priority", "ai_flag", "anomaly_score", "finding"]].sort_values("anomaly_score")
    st.dataframe(ai_table, hide_index=True, use_container_width=True)
    if len(rules) >= 8:
        scores = ai_table.set_index("rule_id")[["anomaly_score"]]
        st.bar_chart(scores, y="anomaly_score")
    st.caption("Contamination changes the AI review threshold, never the deterministic rule-removal decisions.")

with verify_tab:
    st.subheader("5 · Inspect one hypothetical packet")
    st.caption("Enter packet attributes to compare the original and optimized first-match decisions.")
    with st.form("packet_eval"):
        f1, f2, f3 = st.columns(3)
        src_ip = f1.text_input("Source IPv4", "10.1.0.5")
        dst_ip = f2.text_input("Destination IPv4", "192.168.1.22")
        proto = f3.selectbox("Protocol", ["tcp", "udp"])
        f4, f5 = st.columns(2)
        src_port = f4.number_input("Source port", 0, 65535, 54321)
        dst_port = f5.number_input("Destination port", 0, 65535, 443)
        run_packet = st.form_submit_button("Compare packet decision")
    if run_packet:
        try:
            IPv4Address(src_ip)
            IPv4Address(dst_ip)
            before = filter_packet(rules, src_ip, dst_ip, int(src_port), int(dst_port), proto)
            after = filter_packet(output_rules, src_ip, dst_ip, int(src_port), int(dst_port), proto)
            a, b = st.columns(2)
            a.metric("Before", before.upper())
            b.metric("After", after.upper())
            if before == after:
                st.success("The two decisions match for this packet.")
            else:
                st.error("Decisions differ — do not apply the proposed changes.")
        except Exception as exc:
            st.error(f"Invalid packet parameters: {exc}")
    st.caption("Packet checks provide examples. The rule-containment condition is the mathematical basis for guaranteed removals within this model.")

@st.cache_data(show_spinner=False)
def cached_evaluation():
    benchmark, ground_truth = load_benchmark()
    detailed, m = labeled_evaluation(benchmark, ground_truth, contamination=0.15)
    comparison = run_scaling_benchmarks(repetitions=3, packets=3000)
    return detailed, m, comparison

with evidence_tab:
    st.subheader('5A · Reproducible experimental evaluation')
    st.caption('This tab evaluates fixed, intentionally constructed synthetic datasets. It does not test a live firewall or cloud-network throughput.')
    st.markdown('**Use Run evaluation once** to reproduce the design-label comparison, ML proxy screening, scaling and packet checks. No separate file upload is required.')
    if st.button('▶ Run evaluation', key='run_eval'):
        st.session_state['eval_display'] = True
    if st.session_state.get('eval_display',False):
        with st.spinner('Evaluating sample datasets...'):
            detail, metric, scaled = cached_evaluation()
        st.markdown('**A. Deterministic findings against synthetic design labels**')
        a,b,c=st.columns(3)
        a.metric('Exact class agreement',f"{metric['correct_exact_classes']} / {metric['total_rules']}")
        b.metric('Synthetic-case precision',f"{metric['deterministic_precision']:.0%}")
        c.metric('Synthetic-case recall',f"{metric['deterministic_recall']:.0%}")
        st.caption('The designer placed known, simple anomalies in this benchmark. High agreement here does not imply comparable accuracy on unfamiliar real-world configurations.')
        st.markdown('**B. Exploratory AI screening (independent-rule proxy, not security ground truth)**')
        c1,c2,c3,c4=st.columns(4)
        c1.metric('AI review flags',metric['ai_review_count'])
        c2.metric('Independent labeled',metric['independent_rules'])
        c3.metric('Proxy precision',f"{metric['ai_independent_proxy_precision']:.0%}")
        c4.metric('Proxy recall',f"{metric['ai_independent_proxy_recall']:.0%}")
        st.warning('Independent rules are not necessarily anomalous or unsafe. These proxy metrics CANNOT be reported as AI security-threat detection accuracy.')
        st.markdown('**C. Scaling and sampled behavior checks**')
        st.dataframe(scaled,hide_index=True,use_container_width=True)
        st.caption('Times are medians of three full software runs on the current host; do not interpret them as firewall packet-processing times. Packet checks include targeted matches and are only sampled checks, not a formal exhaustive proof.')
        st.bar_chart(scaled.set_index('original_rules')[['median_analysis_ai_ms']])
        st.download_button('⬇ Download evaluation table (.csv)',scaled.to_csv(index=False).encode('utf-8'),
                           file_name='experimental_evaluation_results.csv',mime='text/csv')
        st.download_button('⬇ Download benchmark class comparisons (.csv)',detail.to_csv(index=False).encode('utf-8'),
                           file_name='benchmark_ground_truth_comparison.csv',mime='text/csv')

with help_tab:
    st.markdown("""
    **Project:** Implementation of a Firewall Rule Optimization System Using AI Techniques

    **Workflow:** CSV input → input validation → rule comparison → Isolation Forest anomaly detection → conservative optimization → report and export.

    **Implemented and explained:**
    - Exact duplicate detection
    - Complete shadowing by a single earlier rule
    - Redundant same-action rule removal (no change of filtering decisions in the model)
    - Partial overlapping opposite-action rule warnings
    - AI anomaly scoring with Isolation Forest
    - Downloadable configuration and report
    - Interactive before/after packet decision comparison

    **Research limitations:** This system simulates a stateless IPv4 TCP/UDP first-match firewall with a default-deny policy. It does **not** model stateful connections, real cloud provider security-group semantics, NAT, IPv6, traffic logs, actual latency, or physical performance. ML anomaly scores do not determine whether a rule is malicious.

    **Security:** Use synthetic or permission-cleared data. Do not upload confidential real firewall configurations to a public repository or hosted app.
    """)

st.divider()
st.subheader("6 · Download research evidence")
summary = (
    "Cloud Firewall AI Optimizer — Analysis Report\n"
    f"Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\n"
    f"Input: {source_label}\n"
    "Model: Ordered, stateless IPv4 TCP/UDP first-match firewall; default deny\n"
    f"Original rules: {original_n}\nOptimized rules: {optimized_n}\n"
    f"Proven removable by single earlier same-action coverage: {removal_n}\n"
    f"Reduction: {100.0*removal_n/original_n:.2f}%\n"
    f"Isolation Forest review flags: {review_n}\n"
    "AI review flags are not proof of insecure rules. No live firewall is tested or changed.\n"
    "\nDETECTED FINDINGS:\n"
    + combined[["rule_id", "finding", "related_earlier_rules", "safe_to_remove", "ai_flag"]].to_csv(index=False)
)
lcol, rcol = st.columns(2)
lcol.download_button("⬇ Detailed analysis (.csv)", combined.to_csv(index=False).encode("utf-8"),
                     "firewall_analysis_report.csv", mime="text/csv")
rcol.download_button("⬇ Research summary (.txt)", summary.encode("utf-8"),
                     "firewall_research_summary.txt", mime="text/plain")
st.caption("Firewall AI Optimizer · Academic prototype v1.1 · Cloud deployable · Review every recommendation before using real policies")
