#!/usr/bin/env python3
"""
generate_reports.py — automated incident reporting + attack-graph correlation.

Consumes a completed per-host collection folder (the folder produced by
Invoke-IRCollection.ps1 / Invoke-IRCollection-Linux.sh) and emits, with no
human authoring:

    Incident_Report.md   full IR report (exec summary, ATT&CK chain, findings,
                         adjudication funnel, lineage, remediation, IOC appendix)
    Attack_Graph.md      Mermaid attack graph correlating the whole intrusion
                         from the adjudicated findings
    IOCs.json            machine-readable IOC bundle (C2 endpoints, hashes,
                         tools, ATT&CK techniques) — consumed by
                         Invoke-Eradication.ps1 to keep known-bad blocked after
                         the firewall is otherwise restored to known-good.

Inputs (newest of each is auto-selected from the host folder):
    Adjudication_*.json        richest source: Verdict/Confidence/Type/Target/...
    RemoteAccess_Findings_*.json   RAT command lines (C2 relay parameters)
    Combined_Findings_*.json   fallback when no adjudication is present

The generator is data-driven and cross-platform (Windows + Linux collections).
PowerShell writes UTF-8 *with BOM*; every JSON read therefore uses utf-8-sig.

Usage:
    generate_reports.py --host-folder PATH [--incident-id ID] [--analyst NAME]
"""
import argparse
import datetime
import glob
import json
import os
import re
import sys
from collections import Counter, OrderedDict

# Verdicts at or above this rank are "true-positive class" / actionable.
TP_CLASS = ("True Positive", "Likely True Positive")
VERDICT_ORDER = ["False Positive", "Likely False Positive", "Indeterminate",
                 "Likely True Positive", "True Positive"]

# Known remote-access / RMM tool tokens whose presence is a confirmed T1219 node.
RAT_TOKENS = ("ScreenConnect", "GoToAssist", "AnyDesk", "TeamViewer", "Atera",
              "ConnectWise", "Splashtop", "RemoteUtilities", "RustDesk", "NetSupport")

# ATT&CK technique -> short human label (for graph/report context).
ATTACK_LABELS = {
    "T1566": "Phishing",
    "T1204": "User Execution",
    "T1204.001": "Malicious Link",
    "T1219": "Remote Access Software",
    "T1543.003": "Service persistence",
    "T1562.001": "Disable security tools",
    "T1003": "Credential dumping (risk)",
    "T1059": "Command/Scripting interpreter",
    "T1218": "Signed-binary proxy execution",
    "T1014": "Rootkit / hidden process",
    "T1547": "Boot/logon autostart",
    "T1112": "Modify registry",
}


# --------------------------------------------------------------------------- io
def load_json(path):
    """Load JSON tolerating the UTF-8 BOM that PowerShell emits."""
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else [data]
    except Exception:
        return []


def newest(host_folder, pattern):
    hits = sorted(glob.glob(os.path.join(host_folder, pattern)),
                  key=os.path.getmtime, reverse=True)
    return hits[0] if hits else None


def get(obj, *names, default=""):
    """Case-tolerant field access across PS/py field-name styles."""
    for n in names:
        if isinstance(obj, dict) and obj.get(n) not in (None, ""):
            return obj.get(n)
    return default


# -------------------------------------------------------------------- analysis
def extract_relay(text):
    """Pull a ScreenConnect-style C2 relay (host/port/session/instance) from a
    command line or detail blob. Returns dict or None."""
    if not text:
        return None
    host = re.search(r"[?&]h=([^&\"\\\s]+)", text)
    port = re.search(r"[?&]p=(\d{1,5})", text)
    if not (host and port):
        return None
    sess = re.search(r"[?&]s=([0-9A-Fa-f-]{16,40})", text)
    inst = re.search(r"Client \(([0-9A-Fa-f]{8,})\)", text)
    return {
        "host": host.group(1),
        "port": int(port.group(1)),
        "session_id": sess.group(1) if sess else None,
        "instance_id": inst.group(1) if inst else None,
    }


C2_TYPE = re.compile(r"(?i)\bC2\b|beacon|command.?and.?control|cloud c2")
ENDPOINT = re.compile(
    r"\b((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z]{2,})\b(?::(\d{1,5}))?")


def extract_c2_endpoint(finding):
    """Pull a plain C2 endpoint (IP/host[:port]) from a C2-typed finding. Used by
    the cloud workflow, where C2 IOCs arrive as addresses rather than RAT relays."""
    ftype = get(finding, "Type")
    if not C2_TYPE.search(ftype):
        return None
    blob = " ".join([get(finding, "Details"), get(finding, "Target"),
                     get(finding, "RemoteAddress")])
    matches = list(ENDPOINT.finditer(blob))
    if not matches:
        return None
    m = next((x for x in matches if x.group(2)), matches[0])   # prefer one with a port
    port = get(finding, "RemotePort")
    return {
        "host": m.group(1),
        "port": int(m.group(2)) if m.group(2) else (int(port) if str(port).isdigit() else 0),
        "session_id": None,
        "instance_id": None,
    }


def is_sanctioned_relay(host):
    """A *.screenconnect.com relay is vendor-sanctioned; a custom host is not."""
    return bool(re.search(r"(^|\.)screenconnect\.com$", host or "", re.I))


def correlate(findings, remote_findings):
    """Reduce raw findings to the structured intrusion story."""
    funnel = Counter(get(f, "Verdict", default="(unadjudicated)") for f in findings)
    tp = [f for f in findings if get(f, "Verdict") in TP_CLASS]

    techniques = OrderedDict()
    for f in findings:
        mitre = get(f, "MITRE")
        for tech in re.findall(r"T\d{4}(?:\.\d{3})?", mitre or ""):
            techniques.setdefault(tech, ATTACK_LABELS.get(tech, ""))

    rats, relays, hashes = [], [], OrderedDict()
    defender_off = False

    # RAT + relay extraction. Scan both the remote-access triage source and the
    # adjudicated findings, so a RAT relay recorded only in the adjudication record
    # is still recovered.
    for f in list(remote_findings) + list(findings):
        ftype = get(f, "Type")
        details = get(f, "Details")
        target = get(f, "Target")
        if ftype == "Remote Access Tool" or any(t in (target + details) for t in RAT_TOKENS):
            tool = next((t for t in RAT_TOKENS if t in (target + " " + details)), target)
            if tool not in [r["tool"] for r in rats]:
                rats.append({"tool": tool, "details": details, "target": target})
        if ftype == "Defender Disabled" or "real-time protection is OFF" in details.lower():
            defender_off = True
        relay = extract_relay(details)
        if relay and relay not in relays:
            relays.append(relay)

    # Plain C2 endpoints (cloud workflow: C2 arrives as IP/host, not a RAT relay).
    for f in list(findings) + list(remote_findings):
        ep = extract_c2_endpoint(f)
        if ep and not any(r["host"] == ep["host"] and r["port"] == ep["port"] for r in relays):
            relays.append(ep)

    # Hashes + signer come from the richer adjudication records.
    rat_sig = None
    rat_path = None
    for f in findings:
        subj = get(f, "SubjectPath")
        sha = get(f, "SHA256")
        if any(t in subj for t in RAT_TOKENS):
            if sha:
                hashes[sha.upper()] = subj
            rat_sig = rat_sig or get(f, "Signer")
            rat_path = rat_path or subj
        mitre = get(f, "MITRE")
        if "T1562" in (mitre or "") or "Defender Disabled" in get(f, "Type"):
            defender_off = True

    # Cluster memory YARA matches per process (Target = "PID 1234 (proc.exe)") so a
    # host with many matches collapses to one row per PID with a hit count + rules.
    yara_clusters = OrderedDict()
    for f in findings:
        if get(f, "Type") == "YARA Match (Memory)":
            tgt = get(f, "Target")
            yara_clusters.setdefault(tgt, [])
            m = re.search(r"Rule:\s*([^|]+?)(?:\s*\||$)", get(f, "Details"))
            if m:
                yara_clusters[tgt].append(m.group(1).strip())

    return {
        "funnel": funnel,
        "tp": tp,
        "tp_count": len(tp),
        "total": len(findings),
        "yara_clusters": yara_clusters,
        "techniques": techniques,
        "rats": rats,
        "relays": relays,
        "hashes": hashes,
        "rat_signer": rat_sig,
        "rat_path": rat_path,
        "defender_off": defender_off,
    }


def severity(model):
    if any(not is_sanctioned_relay(r["host"]) for r in model["relays"]) or model["rats"]:
        return "HIGH — confirmed unauthorized remote access"
    if model["tp_count"]:
        return "MEDIUM — true-positive-class findings require review"
    return "LOW — no true-positive-class findings"


# ---------------------------------------------------------------------- IOCs
def build_iocs(model, host, incident):
    c2 = []
    for r in model["relays"]:
        c2.append({
            "host": r["host"], "port": r["port"],
            "sanctioned": is_sanctioned_relay(r["host"]),
            "session_id": r.get("session_id"), "instance_id": r.get("instance_id"),
        })
    return OrderedDict([
        ("incident_id", incident),
        ("hostname", host),
        ("generated_utc", datetime.datetime.now(datetime.timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%SZ")),
        ("c2_endpoints", c2),
        ("file_hashes_sha256", list(model["hashes"].keys())),
        ("remote_access_tools", [r["tool"] for r in model["rats"]]),
        ("attack_techniques", list(model["techniques"].keys())),
        ("defender_realtime_disabled", model["defender_off"]),
    ])


# --------------------------------------------------------------- report (md)
def md_incident(model, host, incident, analyst, when):
    L = []
    a = L.append
    a(f"# Incident Response Report — {host}")
    a("")
    a("| | |")
    a("|---|---|")
    a(f"| **Host** | {host} |")
    a(f"| **Incident** | {incident} |")
    a(f"| **Date of analysis** | {when} |")
    a(f"| **Analyst** | {analyst} |")
    a(f"| **Severity** | **{severity(model)}** |")
    a("| **Status** | Contained (host isolated) → eradication pending/applied |")
    a("")
    a("> Auto-generated by `generate_reports.py` from the adjudicated findings. "
      "Confirmed items are those at true-positive-class verdict.")
    a("")
    a("---")
    a("")
    a("## 1. Executive summary")
    a("")
    if model["rats"]:
        tools = ", ".join(sorted({r["tool"] for r in model["rats"]}))
        custom = [r for r in model["relays"] if not is_sanctioned_relay(r["host"])]
        a(f"Adjudication confirmed **unauthorized remote-access tooling ({tools})** on "
          f"`{host}`."
          + (f" The client beacons to a **custom, adversary-operated relay "
             f"`{custom[0]['host']}:{custom[0]['port']}`** (not a vendor-sanctioned "
             f"`*.screenconnect.com` endpoint), which proves this is an attacker "
             f"deployment rather than sanctioned IT support." if custom else ""))
        if model["defender_off"]:
            a("")
            a("Microsoft Defender **real-time protection was disabled** on the host "
              "(T1562.001), consistent with a hands-on-keyboard intrusion clearing the "
              "way for follow-on activity.")
    else:
        a(f"Adjudication produced **{model['tp_count']}** true-positive-class finding(s) "
          f"out of **{model['total']}** raw findings on `{host}`.")
    a("")
    a(f"**{model['total']} raw findings → {model['tp_count']} true-positive-class.**")
    a("")
    a("---")
    a("")
    a("## 2. Attack chain (MITRE ATT&CK)")
    a("")
    if model["techniques"]:
        for tech, label in model["techniques"].items():
            lab = f" — {label}" if label else ""
            a(f"- **{tech}**{lab}")
    else:
        a("- No ATT&CK techniques were associated with the findings.")
    a("")
    a("---")
    a("")
    a("## 3. True-positive-class findings")
    a("")
    if model["tp"]:
        a("| Verdict | Conf | Type | Target | Subject |")
        a("|---|---|---|---|---|")
        for f in model["tp"]:
            subj = (get(f, "SubjectPath") or "").replace("|", "\\|")
            a(f"| {get(f,'Verdict')} | {get(f,'Confidence')} | {get(f,'Type')} | "
              f"{get(f,'Target')} | `{subj}` |")
    else:
        a("No true-positive-class findings. **No eradication required.**")
    a("")
    a("---")
    a("")

    # Memory YARA matches, clustered per process (count + rules per PID).
    yc = model.get("yara_clusters") or {}
    if yc:
        total_hits = sum(len(v) for v in yc.values())
        a("## YARA matches by process (memory)")
        a("")
        a(f"{total_hits} match(es) across {len(yc)} process(es), clustered per PID.")
        a("")
        a("| Process (PID) | Hits | Rules |")
        a("|---|---:|---|")
        for tgt in sorted(yc, key=lambda k: len(yc[k]), reverse=True):
            rules = ", ".join(dict.fromkeys(yc[tgt]))   # unique, order-preserving
            a(f"| {tgt} | {len(yc[tgt])} | {rules} |")
        a("")
        a("---")
        a("")

    a("## 4. Adjudication funnel")
    a("")
    a("| Verdict | Count |")
    a("|---|---:|")
    for v in VERDICT_ORDER:
        if model["funnel"].get(v):
            a(f"| {v} | {model['funnel'][v]} |")
    for v, c in model["funnel"].items():
        if v not in VERDICT_ORDER:
            a(f"| {v} | {c} |")
    a(f"| **Total** | **{model['total']}** |")
    a("")
    a("Sources merged: EDR hunt + remote-access triage + persistence/config snapshot.")
    a("")
    a("---")
    a("")
    a("## 5. Resolution / eradication")
    a("")
    a("Run on the **isolated** host from the toolkit root:")
    a("")
    a("```powershell")
    a("# 1) Review the plan (changes nothing):")
    a(f".\\Invoke-Eradication.ps1 -HostFolder .\\{host} -MinVerdict \"Likely True Positive\"")
    a("# 2) Execute (restores the firewall to known-good afterward, keeping known-bad blocked):")
    a(f".\\Invoke-Eradication.ps1 -HostFolder .\\{host} -MinVerdict \"Likely True Positive\" -Apply")
    a("```")
    a("")
    if model["relays"]:
        a("**Network containment kept after eradication (known-bad, do NOT unblock):**")
        for r in model["relays"]:
            tag = "sanctioned" if is_sanctioned_relay(r["host"]) else "adversary relay"
            a(f"- `{r['host']}:{r['port']}` ({tag})")
        a("")
    a("**Manual follow-up:** re-enable Defender real-time protection and run a full scan; "
      "fully uninstall the remote-access client; rotate credentials for any account used "
      "on this host; review for new/modified local accounts.")
    a("")
    a("---")
    a("")
    a("## 6. IOC appendix")
    a("")
    a("```")
    if model["rats"]:
        a("Tool        : " + ", ".join(sorted({r['tool'] for r in model['rats']})))
    if model["rat_signer"]:
        a("Signer      : " + model["rat_signer"])
    for r in model["relays"]:
        flag = "" if is_sanctioned_relay(r["host"]) else "   <-- attacker relay (custom)"
        a(f"RELAY (C2)  : {r['host']} : {r['port']}/TCP{flag}")
        if r.get("session_id"):
            a(f"SESSION ID  : s={r['session_id']}")
        if r.get("instance_id"):
            a(f"INSTANCE    : {r['instance_id']}")
    for h in model["hashes"]:
        a("SHA256      : " + h)
    if model["techniques"]:
        a("ATT&CK      : " + ", ".join(model["techniques"].keys()))
    a("```")
    a("")
    a("*Machine-readable IOC bundle: `IOCs.json`. Attack correlation: `Attack_Graph.md`.*")
    a("")
    return "\n".join(L)


# ---------------------------------------------------------- attack graph (md)
# Fallback tactic classification by finding-type keywords when MITRE is absent.
TYPE_TACTIC = OrderedDict([
    ("Initial Access", ("phish", "browser", "clickfix", "lure", "valid account",
                        "identity", "spearphish", "exploit public")),
    ("Execution", ("lolbin", "script", "command", "macro", "interpreter")),
    ("Persistence", ("persistence", "scheduled task", "cron", "systemd", "registry",
                     "com hijack", "bits", "service", "webshell", "preload", "launch",
                     "autostart", "run key")),
    ("Privilege Escalation", ("privilege", "escalat", "sudo", "setuid", "token")),
    ("Defense Evasion", ("defender", "disable", "hidden process", "injection", "rootkit",
                         "masquerad", "obfusc", "amsi", "etw", "tamper", "anonymous exec")),
    ("Credential Access", ("credential", "lsass", "mimikatz", "password", "hash dump",
                           "kerbero", "secret")),
    ("Discovery", ("discovery", "recon", "enumerat", "port probe")),
    ("Lateral Movement", ("lateral", "psexec", "smb", "rdp", "remote service")),
    ("Command and Control", ("remote access", "c2", "beacon", "rat", "tunnel", "proxy",
                             "relay", "cloud detection")),
    ("Exfiltration", ("exfil", "upload", "transfer out", "data staged")),
    ("Impact", ("ransom", "encrypt", "wipe", "destroy", "deface", "miner", "cryptojack",
                "coinhive", "xmrig")),
])

# Per-tactic node colours (kill-chain palette).
TACTIC_STYLE = {
    "Initial Access": ("#1e40af", "#93c5fd"), "Execution": ("#5b21b6", "#c4b5fd"),
    "Persistence": ("#9a3412", "#fdba74"), "Privilege Escalation": ("#854d0e", "#fde047"),
    "Defense Evasion": ("#92400e", "#fcd34d"), "Credential Access": ("#9f1239", "#fda4af"),
    "Discovery": ("#155e75", "#67e8f9"), "Lateral Movement": ("#3f6212", "#bef264"),
    "Command and Control": ("#7f1d1d", "#fca5a5"), "Exfiltration": ("#701a75", "#f0abfc"),
    "Impact": ("#7f1d1d", "#fecaca"), "Uncategorized": ("#374151", "#9ca3af"),
}


def _g(s):
    """Sanitize dynamic text for a Mermaid node label (strip control characters)."""
    s = str(s) if s is not None else ""
    for ch in '"[]{}|<>()':
        s = s.replace(ch, " ")
    return re.sub(r"\s+", " ", s).strip()[:60] or "?"


def _cls(tactic):
    """Mermaid classDef-safe name for a tactic."""
    return "t_" + re.sub(r"[^a-z]", "", tactic.lower())


def tactic_of(finding):
    """Map a finding to an ATT&CK tactic by its technique, else by type keywords."""
    techs = re.findall(r"T\d{4}(?:\.\d{3})?", get(finding, "MITRE") or "")
    for tactic, prefixes in TACTICS.items():
        if any(any(t.startswith(p) for p in prefixes) for t in techs):
            return tactic
    blob = (get(finding, "Type") + " " + get(finding, "Target") + " " +
            get(finding, "Details")).lower()
    for tactic, kws in TYPE_TACTIC.items():
        if any(k in blob for k in kws):
            return tactic
    return "Uncategorized"


def md_attack_graph(model, host, incident):
    L = []
    a = L.append
    sev = severity(model)
    a(f"# {host} — Attack Graph")
    a("")
    a(f"**Incident:** {incident} · **Host:** {host} · **Severity:** {sev}")
    a("")
    a("The full chain of events, reconstructed from the adjudicated findings. Each "
      "node is one finding/event, ordered along the kill chain (and by time where "
      "known); colour = ATT&CK tactic. The chain is unique to this incident.")
    a("")
    # Order every true-positive-class finding into one event chain: primarily by
    # kill-chain tactic, then by event/detection time, then collection order.
    tp = model["tp"]

    def _order(item):
        idx, f = item
        t = tactic_of(f)
        ti = list(TACTICS).index(t) if t in TACTICS else len(TACTICS)
        when = None
        for fld in ("StartTime", "EventTime", "Timestamp", "FirstSeen"):
            when = _parse_time(get(f, fld))
            if when:
                break
        return (ti, when or datetime.datetime.max, idx)

    events = [f for _, f in sorted(enumerate(tp), key=_order)]
    present = []
    for f in events:
        t = tactic_of(f)
        if t not in present:
            present.append(t)

    a("```mermaid")
    a("flowchart TD")
    a("    classDef host fill:#0f766e,stroke:#5eead4,color:#fff;")
    a("    classDef c2   fill:#991b1b,stroke:#fde047,color:#fff,stroke-width:3px;")
    a("    classDef inferred fill:#1f2937,stroke:#9ca3af,color:#e5e7eb,stroke-dasharray:4 3;")
    for t in present:
        fill, stroke = TACTIC_STYLE.get(t, ("#374151", "#9ca3af"))
        a(f"    classDef {_cls(t)} fill:{fill},stroke:{stroke},color:#fff;")
    a("")
    a(f'    H(["HOST: {_g(host)}"]):::host')

    edges = []
    c2_anchor = "H"
    prev = "H"
    prev_tactic = None
    for i, f in enumerate(events, 1):
        t = tactic_of(f)
        nid = f"E{i}"
        label = _g(get(f, "Type")) + "<br/>" + _g(get(f, "Target"))
        techs = ", ".join(re.findall(r"T\d{4}(?:\.\d{3})?", get(f, "MITRE") or "")[:2])
        label += f"<br/><i>{t}{(' · ' + techs) if techs else ''}</i>"
        a(f'    {nid}["{label}"]:::{_cls(t)}')
        # link into the chain; label the edge when the tactic advances
        if prev_tactic and t != prev_tactic:
            edges.append(f'    {prev} -->|{_g(t)}| {nid}')
        else:
            edges.append(f"    {prev} --> {nid}")
        if t == "Command and Control":
            c2_anchor = nid
        prev, prev_tactic = nid, t

    if not events:
        a('    N0["No confirmed malicious activity<br/>(see Retrospective.md)"]:::inferred')
        edges.append("    H --- N0")
    elif c2_anchor == "H":
        c2_anchor = prev          # no explicit C2 event -> hang relays off the last event

    # C2 endpoints (relays / cloud beacons) — the egress focus, emphasized.
    for cidx, r in enumerate(model["relays"]):
        tag = "sanctioned" if is_sanctioned_relay(r["host"]) else "adversary-operated"
        port = f" : {r['port']}/TCP" if r.get("port") else ""
        a(f'    C{cidx}(["C2 RELAY<br/><b>{_g(r["host"])}{port}</b><br/>{tag}"]):::c2')
        edges.append(f'    {c2_anchor} ==>|"egress"| C{cidx}')

    for e in edges:
        a(e)
    a("```")
    a("")

    custom_relay = next((r for r in model["relays"] if not is_sanctioned_relay(r["host"])), None)
    if custom_relay:
        a(f"## RAT → {custom_relay['host']} (the key path)")
        a("")
        a(f"The remote-access client beacons to **`{custom_relay['host']}:"
          f"{custom_relay['port']}`** — a custom relay rather than a vendor-sanctioned "
          f"endpoint, which is what proves this is an **adversary-operated** deployment. "
          f"Block it at egress before reconnecting the host.")
        a("")

    a("## IOCs")
    a("")
    a("```")
    for r in model["relays"]:
        a(f"RELAY (C2)  : {r['host']} : {r['port']}/TCP")
        if r.get("session_id"):
            a(f"SESSION ID  : s={r['session_id']}")
        if r.get("instance_id"):
            a(f"INSTANCE    : {r['instance_id']}")
    for h in model["hashes"]:
        a("SHA256      : " + h)
    if model["techniques"]:
        a("ATT&CK      : " + ", ".join(model["techniques"].keys()))
    a("```")
    a("")
    return "\n".join(L)


# ----------------------------------------------------- retrospective (md)
# Standard intrusion tactics; each maps to the technique prefixes that evidence it.
TACTICS = OrderedDict([
    ("Initial Access", ("T1566", "T1190", "T1078")),
    ("Execution", ("T1204", "T1059", "T1218", "T1569")),
    ("Persistence", ("T1543", "T1547", "T1546", "T1053", "T1136", "T1505")),
    ("Privilege Escalation", ("T1068", "T1055", "T1134")),
    ("Defense Evasion", ("T1562", "T1014", "T1070", "T1112", "T1027")),
    ("Credential Access", ("T1003", "T1110", "T1555")),
    ("Discovery", ("T1057", "T1082", "T1018")),
    ("Lateral Movement", ("T1021", "T1570")),
    ("Command and Control", ("T1219", "T1071", "T1105", "T1090")),
    ("Exfiltration", ("T1041", "T1567", "T1048")),
    ("Impact", ("T1486", "T1490", "T1489")),
])


def md_retrospective(model, host_folder, host, incident):
    """Objective post-incident retrospective + detection/collection gap analysis."""
    L = []
    a = L.append
    seen = set(model["techniques"].keys())
    fp = model["funnel"].get("False Positive", 0) + model["funnel"].get("Likely False Positive", 0)
    indet = model["funnel"].get("Indeterminate", 0)
    total = model["total"] or 1

    a(f"# {host} — Incident Retrospective & Gap Analysis")
    a("")
    a(f"**Incident:** {incident} · **Host:** {host}")
    a("")
    a("Objective, data-driven review generated from the adjudicated findings. It "
      "states what the pipeline confirmed, what it could not resolve, and where "
      "detection or collection coverage has gaps.")
    a("")
    a("## 1. Outcome")
    a("")
    a(f"- Raw findings triaged: **{model['total']}**")
    a(f"- True-positive-class (actioned): **{model['tp_count']}**")
    a(f"- Unresolved (Indeterminate): **{indet}**")
    a(f"- Cleared as false-positive: **{fp}** "
      f"({round(100*fp/total)}% of all findings)")
    a(f"- Confirmed remote-access C2: **{len([r for r in model['relays'] if not is_sanctioned_relay(r['host'])])}**")
    a("")

    a("## 2. ATT&CK kill-chain coverage")
    a("")
    a("| Tactic | Evidence in this incident | Status |")
    a("|---|---|---|")
    gaps = []
    for tactic, prefixes in TACTICS.items():
        hit = sorted(t for t in seen if any(t.startswith(p) for p in prefixes))
        if hit:
            a(f"| {tactic} | {', '.join(hit)} | covered |")
        else:
            a(f"| {tactic} | — | no evidence collected |")
            gaps.append(tactic)
    a("")

    a("## 3. Detection & collection gaps")
    a("")
    if "Initial Access" in gaps:
        a("- **Initial-access vector not captured.** No T1566/T1190/T1078 evidence "
          "in the collection — the entry point (lure command, exploited service, or "
          "stolen credential) is unconfirmed. Review browser history, RunMRU, and "
          "auth logs to close this.")
    if "Credential Access" in gaps and model["relays"]:
        a("- **Credential exposure unquantified.** An interactive remote-access "
          "session was present but no credential-theft telemetry was collected; "
          "assume credentials on this host are exposed and rotate them.")
    if "Lateral Movement" in gaps and model["relays"]:
        a("- **Lateral movement not assessed.** With confirmed hands-on access, "
          "outbound/peer connections to other hosts were not enumerated.")
    # Artifact-level gaps inferred from the collection folder.
    listing = os.listdir(host_folder) if os.path.isdir(host_folder) else []
    if not any(n.lower().endswith(".raw") or "memory" in n.lower() for n in listing):
        a("- **No memory image captured.** Volatile artifacts (injected code, "
          "in-memory C2 config) were not preserved; re-run collection with memory "
          "capture for fileless-threat coverage.")
    if indet:
        a(f"- **{indet} finding(s) left Indeterminate.** These need analyst review; "
          "a high indeterminate rate indicates adjudication context (signing, "
          "package ownership, network) was incomplete.")
    if not gaps and not indet:
        a("- No structural coverage gaps detected across the standard kill chain.")
    a("")

    a("## 4. What worked")
    a("")
    a(f"- Adjudication suppressed **{fp}** false positive(s) "
      f"({round(100*fp/total)}%), keeping analyst focus on the actionable core.")
    if any(get(f, "SigStatus") == "Valid" for f in model["tp"]):
        a("- A **validly-signed** binary was still escalated to true-positive class "
          "— signature alone did not clear it (the intended override).")
    if model["relays"]:
        a("- C2 relay extracted automatically into machine-readable IOCs for egress "
          "blocking and eradication hand-off.")
    a("")

    a("## 5. Recommendations")
    a("")
    a("1. Keep the adversary C2 blocked/sinkholed after restoration (already wired "
      "into eradication via `IOCs.json`).")
    a("2. Close the collection gaps listed in §3 before declaring the incident shut.")
    a("3. Feed the false-positive patterns back into tuning to lower the FP rate on "
      "the next run.")
    if indet:
        a("4. Manually adjudicate the Indeterminate findings and record the outcome.")
    a("")
    return "\n".join(L)


# ----------------------------------------------------------- timeline (md)
TS_FIELDS = ("StartTime", "Timestamp", "EventTime", "FirstSeen")


def _parse_time(value):
    """Best-effort parse of the timestamp shapes the collectors emit."""
    if not value:
        return None
    s = str(value).strip().rstrip("Z")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%m/%d/%Y %I:%M:%S %p",
                "%m/%d/%Y %H:%M:%S"):
        try:
            return datetime.datetime.strptime(s, fmt)
        except Exception:
            continue
    return None


def md_timeline(findings, host, incident):
    """Chronological event timeline distinguishing activity time from detection time."""
    events = []
    for f in findings:
        # Activity time (process start, event time) is preferred; else detection time.
        act = next((get(f, x) for x in ("StartTime", "EventTime", "FirstSeen") if get(f, x)), "")
        det = get(f, "Timestamp")
        when = _parse_time(act) or _parse_time(det)
        if not when:
            continue
        kind = "activity" if _parse_time(act) else "detection"
        events.append((when, kind, get(f, "Type"), get(f, "Target"),
                       get(f, "Verdict", default="-")))
    events.sort(key=lambda e: e[0])

    L = [f"# {host} — Event Timeline", "",
         f"**Incident:** {incident} · **Host:** {host}", ""]
    if not events:
        L += ["No timestamped events in the findings (timeline could not be built — a "
              "collection gap; see `Retrospective.md`).", ""]
        return "\n".join(L)
    L += ["Times are **activity** (when the adversary acted, from process/event times) where "
          "available, else **detection** (when the pipeline observed it).", "",
          "| Time | Kind | Type | Target | Verdict |", "|---|---|---|---|---|"]
    for when, kind, typ, target, verdict in events:
        L.append(f"| {when:%Y-%m-%d %H:%M:%S} | {kind} | {typ} | {target} | {verdict} |")
    L.append("")
    return "\n".join(L)


# --------------------------------------------------------------------- main
def load_model(host_folder):
    """Load the newest findings from a host folder and correlate them. Shared by
    report generation and the standalone IOC emitter."""
    adj = newest(host_folder, "Adjudication_*.json")
    combined = newest(host_folder, "Combined_Findings_*.json")
    ra = newest(host_folder, "RemoteAccess_Findings_*.json")

    findings = load_json(adj) if adj else load_json(combined) if combined else []
    remote_findings = load_json(ra) if ra else []
    if not remote_findings and combined:
        remote_findings = [f for f in load_json(combined)
                           if get(f, "Type") in ("Remote Access Tool", "Defender Disabled",
                                                  "LOLBin Execution", "Browser Artifact",
                                                  "Cloud C2 Beacon")]
    host = os.path.basename(os.path.normpath(host_folder))
    return correlate(findings, remote_findings), host, findings


def emit_iocs(host_folder, incident_id=None):
    """Write IOCs.json from a host folder. Called in the ANALYSIS stage so the
    eradication hand-off never depends on report generation being run."""
    if not os.path.isdir(host_folder):
        raise SystemExit(f"host folder not found: {host_folder}")
    model, host, _ = load_model(host_folder)
    path = os.path.join(host_folder, "IOCs.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_iocs(model, host, incident_id or host), fh, indent=2)
    return path


def generate(host_folder, incident_id=None, analyst="IR Automation"):
    if not os.path.isdir(host_folder):
        raise SystemExit(f"host folder not found: {host_folder}")
    model, host, findings = load_model(host_folder)
    incident = incident_id or f"{host}"
    when = datetime.date.today().isoformat()

    incident_md = os.path.join(host_folder, "Incident_Report.md")
    graph_md = os.path.join(host_folder, "Attack_Graph.md")
    retro_md = os.path.join(host_folder, "Retrospective.md")
    timeline_md = os.path.join(host_folder, "Timeline.md")
    iocs_json = os.path.join(host_folder, "IOCs.json")

    with open(incident_md, "w", encoding="utf-8") as fh:
        fh.write(md_incident(model, host, incident, analyst, when))
    with open(graph_md, "w", encoding="utf-8") as fh:
        fh.write(md_attack_graph(model, host, incident))
    with open(retro_md, "w", encoding="utf-8") as fh:
        fh.write(md_retrospective(model, host_folder, host, incident))
    with open(timeline_md, "w", encoding="utf-8") as fh:
        fh.write(md_timeline(findings, host, incident))
    with open(iocs_json, "w", encoding="utf-8") as fh:
        json.dump(build_iocs(model, host, incident), fh, indent=2)

    return {
        "incident_report": incident_md,
        "attack_graph": graph_md,
        "retrospective": retro_md,
        "timeline": timeline_md,
        "iocs": iocs_json,
        "total": model["total"],
        "tp_count": model["tp_count"],
        "relays": model["relays"],
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Automated IR report + attack-graph generation.")
    p.add_argument("--host-folder", required=True, help="per-host collection folder")
    p.add_argument("--incident-id", default=None)
    p.add_argument("--analyst", default="IR Automation")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    result = generate(args.host_folder, args.incident_id, args.analyst)
    if not args.quiet:
        print(f"[+] Incident_Report.md  ({result['total']} findings, "
              f"{result['tp_count']} true-positive-class)")
        print(f"[+] Attack_Graph.md")
        print(f"[+] Retrospective.md")
        print(f"[+] Timeline.md")
        print(f"[+] IOCs.json  ({len(result['relays'])} C2 relay(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
