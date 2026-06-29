#!/usr/bin/env python3
"""
cloud_coverage.py - render the adjudicated findings onto the ATT&CK Cloud matrix so the
analyst sees at a glance which tactics the evidence touched and which are blank (gaps to
go back and check).
"""
from cloud_findings import VERDICT_RANK, technique_ids

# ATT&CK Cloud tactics in kill-chain order, each with the technique prefixes the cloud
# adjudicator can emit.
ATTACK_TACTICS = [
    ("Initial Access",       ("T1078", "T1190", "T1199", "T1566")),
    ("Execution",            ("T1059", "T1648", "T1204")),
    ("Persistence",          ("T1098", "T1136", "T1543", "T1546")),
    ("Privilege Escalation", ("T1098", "T1548", "T1484")),
    ("Defense Evasion",      ("T1562", "T1070", "T1027")),
    ("Credential Access",    ("T1552", "T1528", "T1110", "T1556", "T1550")),
    ("Discovery",            ("T1526", "T1087", "T1580")),
    ("Lateral Movement",     ("T1021", "T1550")),
    ("Collection",           ("T1114", "T1530", "T1213")),
    ("Command and Control",  ("T1071", "T1090", "T1568", "T1572", "T1105")),
    ("Exfiltration",         ("T1537", "T1567", "T1041")),
    ("Impact",               ("T1496", "T1485", "T1490", "T1498")),
]


def attack_coverage(findings):
    """Map findings onto the ATT&CK Cloud tactics -> coverage rows (tactic, covered,
    techniques seen, strongest verdict, count)."""
    rank_to_verdict = {v: k for k, v in VERDICT_RANK.items()}
    rows = []
    for tactic, prefixes in ATTACK_TACTICS:
        hits = [f for f in findings
                if any(p in str(f.get("MITRE", "")) for p in prefixes)]
        techs = sorted({t for f in hits for t in technique_ids(f.get("MITRE"))
                        if any(t.startswith(p) for p in prefixes)})
        top = max((VERDICT_RANK.get(f.get("Verdict"), 0) for f in hits), default=None)
        rows.append({"tactic": tactic, "covered": bool(hits), "techniques": techs,
                     "max_verdict": rank_to_verdict.get(top) if top is not None else None,
                     "count": len(hits)})
    return rows


def coverage_markdown(rows):
    out = ["# Cloud ATT&CK Coverage", "",
           "| Tactic | Covered | Techniques | Strongest verdict | Findings |",
           "|---|---|---|---|---|"]
    for r in rows:
        mark = "✅" if r["covered"] else "⬜"
        out.append(f"| {r['tactic']} | {mark} | {', '.join(r['techniques']) or '-'} "
                   f"| {r['max_verdict'] or '-'} | {r['count']} |")
    return "\n".join(out) + "\n"
