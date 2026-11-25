"""Deterministic first-match, stateless IPv4 firewall rule analysis."""
from __future__ import annotations
from dataclasses import dataclass
from ipaddress import IPv4Network, ip_network, ip_address
import pandas as pd
import numpy as np

COLUMNS = ["rule_id", "priority", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action"]

@dataclass(frozen=True)
class Rule:
    rule_id: str
    priority: int
    src_ip: IPv4Network
    dst_ip: IPv4Network
    src_port: tuple[int, int]
    dst_port: tuple[int, int]
    protocol: str
    action: str


def parse_ip(raw) -> IPv4Network:
    value = str(raw).strip().lower()
    network = ip_network("0.0.0.0/0" if value in ("any", "*") else value, strict=False)
    if not isinstance(network, IPv4Network):
        raise ValueError("Only IPv4 addresses and IPv4 CIDR ranges are supported")
    return network


def parse_port(raw) -> tuple[int, int]:
    value = str(raw).strip().lower()
    if value in ("any", "*", "0-65535"):
        return 0, 65535
    bounds = value.split("-")
    if len(bounds) > 2:
        raise ValueError(f"Invalid port range: {raw}")
    lo, hi = (int(bounds[0]), int(bounds[-1]))
    if not (0 <= lo <= hi <= 65535):
        raise ValueError(f"Invalid port range: {raw}")
    return lo, hi


def parse_rules(frame: pd.DataFrame) -> list[Rule]:
    missing = set(COLUMNS) - set(frame.columns)
    if missing:
        raise ValueError("Missing required columns: " + ", ".join(sorted(missing)))
    if frame.empty:
        raise ValueError("The CSV file is empty.")
    entries = []
    for row_no, row in frame.iterrows():
        try:
            protocol = str(row.protocol).strip().lower()
            action = str(row.action).strip().lower()
            if protocol not in {"tcp", "udp", "any"}:
                raise ValueError("Protocol must be TCP, UDP, or any")
            if action not in {"allow", "deny"}:
                raise ValueError("Action must be allow or deny")
            entries.append(Rule(
                rule_id=str(row.rule_id).strip(),
                priority=int(row.priority),
                src_ip=parse_ip(row.src_ip),
                dst_ip=parse_ip(row.dst_ip),
                src_port=parse_port(row.src_port),
                dst_port=parse_port(row.dst_port),
                protocol=protocol,
                action=action,
            ))
        except Exception as exc:
            raise ValueError(f"Invalid rule on CSV row {row_no + 2}: {exc}") from exc
    if any(not r.rule_id for r in entries):
        raise ValueError("rule_id must not be empty")
    if len({r.rule_id for r in entries}) != len(entries):
        raise ValueError("rule_id values must be unique")
    if len({r.priority for r in entries}) != len(entries):
        raise ValueError("priority values must be unique (smaller value means earlier rule)")
    return sorted(entries, key=lambda r: r.priority)


def contains(a: Rule, b: Rule) -> bool:
    """Whether rule a matches every packet matched by rule b (ignoring action)."""
    return (
        b.src_ip.subnet_of(a.src_ip)
        and b.dst_ip.subnet_of(a.dst_ip)
        and a.src_port[0] <= b.src_port[0] <= b.src_port[1] <= a.src_port[1]
        and a.dst_port[0] <= b.dst_port[0] <= b.dst_port[1] <= a.dst_port[1]
        and (a.protocol == "any" or a.protocol == b.protocol)
    )


def overlaps(a: Rule, b: Rule) -> bool:
    return (
        a.src_ip.overlaps(b.src_ip)
        and a.dst_ip.overlaps(b.dst_ip)
        and max(a.src_port[0], b.src_port[0]) <= min(a.src_port[1], b.src_port[1])
        and max(a.dst_port[0], b.dst_port[0]) <= min(a.dst_port[1], b.dst_port[1])
        and (a.protocol == "any" or b.protocol == "any" or a.protocol == b.protocol)
    )


def exact_duplicate(a: Rule, b: Rule) -> bool:
    return (
        a.src_ip == b.src_ip and a.dst_ip == b.dst_ip
        and a.src_port == b.src_port and a.dst_port == b.dst_port
        and a.protocol == b.protocol and a.action == b.action
    )


def analyze_reference(rules: list[Rule]) -> pd.DataFrame:
    """Original v1.1 implementation retained as a regression oracle."""
    findings = []
    for idx, rule in enumerate(rules):
        status = "OK"
        evidence = ""
        safe = False
        for prior in rules[:idx]:
            if exact_duplicate(prior, rule):
                status, evidence, safe = "Duplicate", prior.rule_id, True
                break
            if contains(prior, rule):
                if prior.action == rule.action:
                    status, evidence, safe = "Redundant / shadowed (same action)", prior.rule_id, True
                else:
                    status, evidence, safe = "Shadowed (opposite action)", prior.rule_id, False
                break
        if status == "OK":
            opposite = [p.rule_id for p in rules[:idx] if p.action != rule.action and overlaps(p, rule)]
            if opposite:
                status = "Overlapping opposite-action rules (review)"
                evidence = ", ".join(opposite[:5])
        findings.append({
            "rule_id": rule.rule_id,
            "priority": rule.priority,
            "finding": status,
            "related_earlier_rules": evidence,
            "safe_to_remove": safe,
        })
    return pd.DataFrame(findings)


def analyze(rules: list[Rule]) -> pd.DataFrame:
    """Equivalent first-cover analysis with vectorized integer intervals.

    O(n²) worst-case comparisons, O(n) temporary space.
    """
    rows = []
    proto = {"tcp": 1, "udp": 2, "any": 3}
    a = np.asarray([
        (int(r.src_ip.network_address), int(r.src_ip.broadcast_address),
         int(r.dst_ip.network_address), int(r.dst_ip.broadcast_address),
         *r.src_port, *r.dst_port, proto[r.protocol], int(r.action == "allow"))
        for r in rules
    ], dtype=np.int64).reshape(-1, 10)
    for i, r in enumerate(rules):
        b = a[i]; p = a[:i]; status, evidence, safe = "OK", "", False
        compatible = (p[:,8] & b[8]) == b[8]
        cover = compatible & (p[:,0] <= b[0]) & (p[:,1] >= b[1]) & (p[:,2] <= b[2]) & (p[:,3] >= b[3]) & (p[:,4] <= b[4]) & (p[:,5] >= b[5]) & (p[:,6] <= b[6]) & (p[:,7] >= b[7])
        ids = np.flatnonzero(cover)
        if ids.size:
            j = int(ids[0]); evidence = rules[j].rule_id
            if a[j,9] != b[9]:
                status = "Shadowed (opposite action)"
            else:
                safe = True
                status = "Duplicate" if np.array_equal(a[j], b) else "Redundant / shadowed (same action)"
        else:
            overlap = (p[:,9] != b[9]) & ((p[:,8] & b[8]) != 0) & (p[:,0] <= b[1]) & (p[:,1] >= b[0]) & (p[:,2] <= b[3]) & (p[:,3] >= b[2]) & (p[:,4] <= b[5]) & (p[:,5] >= b[4]) & (p[:,6] <= b[7]) & (p[:,7] >= b[6])
            ids = np.flatnonzero(overlap)[:5]
            if ids.size:
                status = "Overlapping opposite-action rules (review)"
                evidence = ", ".join(rules[int(j)].rule_id for j in ids)
        rows.append(dict(rule_id=r.rule_id, priority=r.priority, finding=status,
                         related_earlier_rules=evidence, safe_to_remove=safe))
    return pd.DataFrame(rows, columns=["rule_id", "priority", "finding", "related_earlier_rules", "safe_to_remove"])


def optimize(frame: pd.DataFrame, report: pd.DataFrame) -> pd.DataFrame:
    """Only remove rules provably unreachable due to ONE earlier same-action covering rule."""
    removed = set(report.loc[report.safe_to_remove, "rule_id"])
    output = frame.loc[~frame["rule_id"].astype(str).str.strip().isin(removed)].copy()
    return output.sort_values("priority", key=lambda v: v.astype(int)).reset_index(drop=True)


def match_packet(rule: Rule, src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> bool:
    return (
        ip_address(src_ip) in rule.src_ip
        and ip_address(dst_ip) in rule.dst_ip
        and rule.src_port[0] <= src_port <= rule.src_port[1]
        and rule.dst_port[0] <= dst_port <= rule.dst_port[1]
        and (rule.protocol == "any" or rule.protocol == protocol.lower())
    )


def filter_packet(rules: list[Rule], src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str, default_action="deny") -> str:
    source, dest = ip_address(src_ip), ip_address(dst_ip)
    protocol = protocol.lower()
    for rule in rules:
        if (rule.protocol in ("any", protocol) and rule.src_port[0] <= src_port <= rule.src_port[1]
                and rule.dst_port[0] <= dst_port <= rule.dst_port[1]
                and source in rule.src_ip and dest in rule.dst_ip):
            return rule.action
    return default_action
