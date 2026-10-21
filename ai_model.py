"""Optional ML review flags. Anomaly is not proof of an incorrect firewall rule."""
import pandas as pd
from sklearn.ensemble import IsolationForest


def detect_anomalies(rules: list, contamination: float = 0.15) -> pd.DataFrame:
    if len(rules) < 8:
        return pd.DataFrame({
            "rule_id": [r.rule_id for r in rules],
            "ai_flag": ["Not evaluated (need 8+ rules)"] * len(rules),
            "anomaly_score": [float("nan")] * len(rules),
        })
    data = []
    for r in rules:
        data.append({
            "src_network": int(r.src_ip.network_address) / (2**32),
            "src_prefix": r.src_ip.prefixlen,
            "dst_network": int(r.dst_ip.network_address) / (2**32),
            "dst_prefix": r.dst_ip.prefixlen,
            "src_port_start": r.src_port[0],
            "src_port_end": r.src_port[1],
            "dst_port_start": r.dst_port[0],
            "dst_port_end": r.dst_port[1],
            "protocol_tcp": int(r.protocol == "tcp"),
            "protocol_udp": int(r.protocol == "udp"),
            "protocol_any": int(r.protocol == "any"),
            "action_allow": int(r.action == "allow"),
            "priority": r.priority,
        })
    features = pd.DataFrame(data)
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(features)
    scores = model.decision_function(features)
    flags = model.predict(features)
    return pd.DataFrame({
        "rule_id": [r.rule_id for r in rules],
        "ai_flag": ["Review" if f == -1 else "Typical" for f in flags],
        "anomaly_score": [round(float(v), 4) for v in scores],
    })
