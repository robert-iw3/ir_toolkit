"""Attack-graph generality + Mermaid syntax across many distinct attack shapes."""
import json
import re

import pytest

import generate_reports as gr


# ----------------------------------------------------------- mermaid validator
def extract_mermaid(graph_md):
    m = re.search(r"```mermaid\n(.*?)```", graph_md, re.S)
    assert m, "no mermaid block"
    return m.group(1)


def validate_mermaid(body):
    """Structural Mermaid checks: returns a list of errors ([] == well-formed)."""
    errors = []
    lines = [ln.rstrip() for ln in body.splitlines() if ln.strip()]
    assert lines and lines[0].strip() == "flowchart TD", "must start with flowchart TD"

    declared, classdefs, used_classes = set(), set(), set()
    edge_refs = set()
    node_decl = re.compile(r"^\s*([A-Za-z0-9_]+)\s*[\[\(]")
    classdef = re.compile(r"^\s*classDef\s+([A-Za-z0-9_]+)\s")
    class_ref = re.compile(r":::([A-Za-z0-9_]+)")
    # edge: A <op> [|label|] B  (ops: --> -.-> ==> ---)
    edge = re.compile(r"\b([A-Za-z0-9_]+)\b\s*(?:--?>|-\.->|==>|---)\s*(?:\|[^|]*\|\s*)?\b([A-Za-z0-9_]+)\b")

    for ln in lines[1:]:
        cd = classdef.match(ln)
        if cd:
            classdefs.add(cd.group(1))
            continue
        nd = node_decl.match(ln)
        if nd and "-->" not in ln and "==>" not in ln and "-.->" not in ln and "---" not in ln:
            declared.add(nd.group(1))
        for c in class_ref.findall(ln):
            used_classes.add(c)
        for src, dst in edge.findall(ln):
            edge_refs.add(src)
            edge_refs.add(dst)

    # balanced quotes per line
    for ln in lines:
        if ln.count('"') % 2 != 0:
            errors.append(f"unbalanced quotes: {ln.strip()}")
    # every class referenced via ::: must be defined
    for c in used_classes - classdefs:
        errors.append(f"undefined classDef '{c}'")
    # every edge endpoint must be a declared node
    for ref in edge_refs - declared:
        errors.append(f"edge references undeclared node '{ref}'")
    # no forbidden raw label chars that break mermaid (we sanitize, so none should leak)
    return errors


def gen_graph(tmp_path, name, findings):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "Adjudication_1.json").write_text(json.dumps(findings))
    res = gr.generate(str(folder), name)
    return open(res["attack_graph"], encoding="utf-8").read()


# ----------------------------------------------------------------- scenarios
SCENARIOS = {
    "rat_c2": [
        {"Type": "Remote Access Tool", "Target": "ScreenConnect", "Verdict": "True Positive",
         "MITRE": "T1219", "Details": "service ?e=Access&h=evil.test&p=8041&s=" + "a" * 36},
        {"Type": "Defender Disabled", "Target": "RealTimeProtection", "Verdict": "True Positive",
         "MITRE": "T1562.001", "Details": "real-time protection is OFF"}],
    "cryptominer": [
        {"Type": "Malicious Process", "Target": "xmrig", "Verdict": "True Positive",
         "MITRE": "T1496", "Details": "miner in /tmp"},
        {"Type": "Cron Persistence", "Target": "/etc/cron.d/x", "Verdict": "True Positive",
         "MITRE": "T1053.003", "Details": "miner cron"}],
    "webshell": [
        {"Type": "Webshell", "Target": "/var/www/up.php", "Verdict": "True Positive",
         "MITRE": "T1505.003", "Details": "php webshell"}],
    "cloud_iam": [
        {"Type": "Cloud Detection", "Target": "iam-user", "Verdict": "Likely True Positive",
         "MITRE": "T1078", "Details": "GuardDuty anomalous API"},
        {"Type": "Cloud C2 Beacon", "Target": "203.0.113.5", "Verdict": "True Positive",
         "MITRE": "T1071", "Details": "beacon to 203.0.113.5:443"}],
    "ransomware": [
        {"Type": "Ransomware", "Target": "locker.exe", "Verdict": "True Positive",
         "MITRE": "T1486", "Details": "mass encryption"},
        {"Type": "Shadow Copy Deletion", "Target": "vssadmin", "Verdict": "True Positive",
         "MITRE": "T1490", "Details": "deleted backups"}],
    "cred_theft": [
        {"Type": "Credential Dumping", "Target": "lsass", "Verdict": "True Positive",
         "MITRE": "T1003.001", "Details": "lsass access"},
        {"Type": "Lateral Movement", "Target": "host2 via SMB", "Verdict": "Likely True Positive",
         "MITRE": "T1021.002", "Details": "smb"}],
    "no_mitre": [
        {"Type": "Suspicious systemd service", "Target": "evil.service", "Verdict": "True Positive",
         "Details": "unowned unit", "MITRE": ""}],
    "clean": [
        {"Type": "Hidden Process", "Target": "PID 5", "Verdict": "False Positive",
         "MITRE": "T1014", "Details": "signed"}],
    "messy_labels": [
        {"Type": 'Weird "quoted" [type]', "Target": "a|b{c}<d>", "Verdict": "True Positive",
         "MITRE": "T1059", "Details": "pipes|and|brackets"}],
}


@pytest.mark.parametrize("name", list(SCENARIOS))
def test_graph_is_valid_mermaid(tmp_path, name):
    body = extract_mermaid(gen_graph(tmp_path, name, SCENARIOS[name]))
    errs = validate_mermaid(body)
    assert errs == [], f"{name}: {errs}"


def test_scenarios_produce_distinct_graphs(tmp_path):
    """No two different attacks render the same graph (it is not a copied template)."""
    graphs = {n: gen_graph(tmp_path, n, f) for n, f in SCENARIOS.items()}
    bodies = {n: extract_mermaid(g) for n, g in graphs.items()}
    assert len(set(bodies.values())) == len(bodies), "two attacks produced identical graphs"


def test_tactic_classification():
    def tac(**f):
        return gr.tactic_of(f)
    assert tac(Type="Ransomware", Target="x", MITRE="T1486", Details="") == "Impact"
    assert tac(Type="Cron Persistence", Target="x", MITRE="T1053.003", Details="") == "Persistence"
    assert tac(Type="Webshell", Target="x", MITRE="T1505.003", Details="") == "Persistence"
    assert tac(Type="Cloud C2 Beacon", Target="1.2.3.4", MITRE="T1071", Details="") == "Command and Control"
    assert tac(Type="Credential Dumping", Target="lsass", MITRE="T1003.001", Details="") == "Credential Access"
    # keyword fallback when MITRE is missing
    assert tac(Type="xmrig miner", Target="x", MITRE="", Details="") == "Impact"
    assert tac(Type="Suspicious systemd service", Target="x", MITRE="", Details="") == "Persistence"


def test_clean_incident_has_no_attack_nodes(tmp_path):
    body = extract_mermaid(gen_graph(tmp_path, "clean", SCENARIOS["clean"]))
    assert "No confirmed malicious activity" in body
    assert "C2 RELAY" not in body


def test_c2_only_when_present(tmp_path):
    rat = extract_mermaid(gen_graph(tmp_path, "rat_c2", SCENARIOS["rat_c2"]))
    miner = extract_mermaid(gen_graph(tmp_path, "cryptominer", SCENARIOS["cryptominer"]))
    assert "C2 RELAY" in rat
    assert "C2 RELAY" not in miner


def test_messy_labels_are_sanitized(tmp_path):
    """Quotes/brackets/pipes in finding fields must not break Mermaid."""
    body = extract_mermaid(gen_graph(tmp_path, "messy_labels", SCENARIOS["messy_labels"]))
    assert validate_mermaid(body) == []
    assert '"quoted"' not in body         # raw quotes stripped from labels


def test_powershell_generator_uses_generalized_chain():
    """The PS twin builds the same data-driven chain, not the old RAT-only template."""
    from conftest import GENERATE_PS1, read_text
    src = read_text(GENERATE_PS1)
    assert "social-engineering lure" not in src       # templated lure node removed
    assert "Get-GraphTactic" in src                   # tactic classification
    assert "$TacticOrder" in src                      # kill-chain ordering
    assert "full chain of events" in src
