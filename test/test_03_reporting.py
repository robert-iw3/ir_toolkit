"""Section 3 - reporting: findings correlated into Incident_Report, Attack_Graph, Retrospective, IOCs.json."""
import json
import os

import generate_reports as gr
from conftest import GENERATE_PY, run_py


# -- Windows synthetic collection (RAT + custom C2) ----------------------------
def test_windows_reports_generated(windows_collection):
    res = gr.generate(windows_collection, incident_id="WIN_TEST")
    for key in ("incident_report", "attack_graph", "retrospective", "iocs"):
        assert os.path.isfile(res[key])
    assert res["total"] == 10
    assert res["tp_count"] == 3


def test_windows_c2_relay_extracted(windows_collection):
    gr.generate(windows_collection, incident_id="WIN_TEST")
    iocs = json.load(open(os.path.join(windows_collection, "IOCs.json")))
    assert len(iocs["c2_endpoints"]) == 1
    r = iocs["c2_endpoints"][0]
    assert r["host"] == "relay.example-c2.test"
    assert r["port"] == 9999
    assert r["sanctioned"] is False
    assert r["instance_id"] == "deadbeefcafe1234"


def test_windows_iocs_hash_tools_techniques(windows_collection):
    gr.generate(windows_collection, incident_id="WIN_TEST")
    iocs = json.load(open(os.path.join(windows_collection, "IOCs.json")))
    assert any(h.startswith("AAAA1111") for h in iocs["file_hashes_sha256"])
    assert "ScreenConnect" in iocs["remote_access_tools"]
    assert "T1219" in iocs["attack_techniques"]
    assert iocs["defender_realtime_disabled"] is True


def test_windows_incident_report_content(windows_collection):
    gr.generate(windows_collection, incident_id="WIN_TEST")
    md = open(os.path.join(windows_collection, "Incident_Report.md"), encoding="utf-8").read()
    assert "HIGH" in md
    assert "ScreenConnect" in md
    assert "relay.example-c2.test" in md


def test_windows_attack_graph_is_mermaid(windows_collection):
    gr.generate(windows_collection, incident_id="WIN_TEST")
    g = open(os.path.join(windows_collection, "Attack_Graph.md"), encoding="utf-8").read()
    assert "```mermaid" in g and "flowchart TD" in g
    assert "C2 RELAY" in g
    assert "==>" in g                      # confirmed RAT flows to C2


def test_retrospective_has_gap_analysis(windows_collection):
    gr.generate(windows_collection, incident_id="WIN_TEST")
    r = open(os.path.join(windows_collection, "Retrospective.md"), encoding="utf-8").read()
    assert "Gap Analysis" in r
    assert "kill-chain coverage" in r
    assert "Detection & collection gaps" in r
    # synthetic set has no initial-access technique -> that gap must be called out
    assert "Initial Access" in r
    assert "no evidence collected" in r


def test_generator_cli_runs(windows_collection):
    r = run_py(GENERATE_PY, "--host-folder", windows_collection, "--incident-id", "CLI")
    assert r.returncode == 0, r.stderr
    assert "Retrospective.md" in r.stdout


# -- Linux synthetic collection (no RAT; different field shape) -----------------
def test_linux_reports_generated(linux_collection):
    res = gr.generate(linux_collection, incident_id="LIN_TEST")
    assert os.path.isfile(res["incident_report"])
    iocs = json.load(open(os.path.join(linux_collection, "IOCs.json")))
    assert iocs["c2_endpoints"] == []          # no RAT/C2 in the linux fixture
    md = open(res["incident_report"], encoding="utf-8").read()
    assert "Adjudication funnel" in md


def test_memory_forensics_yara_section(linux_collection):
    # a dedicated _yara_results file with a match must surface in the incident report
    import json as _j
    res = {"engine": "vol", "rules_compiled": 400, "duration_seconds": 312, "timed_out": False,
           "canary_matched": True, "trusted": True, "match_count": 2,
           "matches": [
               # injected code: anonymous executable -> the report must flag it loudly
               {"rule": "Linux_Trojan_Gafgyt", "offset": "0xdead", "pid": "1337", "process": "evil",
                "region": "anon", "perms": "rwx", "path": "", "strings": ["$c2"],
                "matched_hex": "deadbeef", "severity": "Critical"},
               # FP shape: rule grazing a loaded library -> report shows the backing file
               {"rule": "ELF_Mirai", "offset": "0xbeef", "pid": "4225", "process": "Xwayland",
                "region": "file", "perms": "r-x", "path": "/usr/lib/libLLVM.so",
                "strings": ["$arch"], "matched_hex": "cafe", "severity": "High"}]}
    with open(os.path.join(linux_collection, "_yara_results_20260101_100000.json"), "w") as fh:
        _j.dump(res, fh)
    open(os.path.join(linux_collection, "Memory_Findings_20260101_100000.json"), "w").write("[]")
    gr.generate(linux_collection, incident_id="LIN")
    md = open(os.path.join(linux_collection, "Incident_Report.md"), encoding="utf-8").read()
    assert "Memory forensics & YARA" in md
    assert "engine:" in md and "trusted" in md.lower()
    assert "Linux_Trojan_Gafgyt" in md            # the YARA match reached the report
    # ENRICHMENT in the report: injection flagged, FP shape shows the backing library
    assert "anonymous executable" in md and "PID 1337" in md
    assert "libLLVM.so" in md and "verify hash/package" in md


def test_yara_untrusted_banner(linux_collection):
    import json as _j
    res = {"engine": "native", "rules_compiled": 400, "duration_seconds": 5, "timed_out": True,
           "canary_matched": False, "trusted": False, "match_count": 0, "matches": []}
    with open(os.path.join(linux_collection, "_yara_results_20260101_100000.json"), "w") as fh:
        _j.dump(res, fh)
    gr.generate(linux_collection, incident_id="LIN")
    md = open(os.path.join(linux_collection, "Incident_Report.md"), encoding="utf-8").read()
    assert "UNTRUSTED" in md                       # silent-failure is surfaced, not hidden


def test_detect_platform(linux_collection, windows_collection):
    assert gr.detect_platform(linux_collection) == "linux"
    assert gr.detect_platform(windows_collection) == "windows"


def test_incident_report_references_correct_eradication_tool(linux_collection, windows_collection):
    # the resolution section must reference the platform's OWN eradication script, not PowerShell
    # on a Linux host (the reported bug).
    gr.generate(linux_collection, incident_id="LIN")
    lin = open(os.path.join(linux_collection, "Incident_Report.md"), encoding="utf-8").read()
    assert "Invoke-Eradication-Linux.sh" in lin and "--apply" in lin
    assert "Invoke-Eradication.ps1" not in lin       # no PowerShell on Linux

    gr.generate(windows_collection, incident_id="WIN")
    win = open(os.path.join(windows_collection, "Incident_Report.md"), encoding="utf-8").read()
    assert "Invoke-Eradication.ps1" in win and "-Apply" in win
    assert "Invoke-Eradication-Linux.sh" not in win


# -- Cloud-shaped findings (plain C2 endpoint) ---------------------------------
def test_cloud_c2_endpoint_extracted(tmp_path):
    folder = tmp_path / "aws-host"
    folder.mkdir()
    (folder / "Combined_Findings_1.json").write_text(json.dumps([
        {"Type": "Cloud C2 Beacon", "Target": "45.66.77.88",
         "Details": "Outbound beacon to 45.66.77.88:443", "MITRE": "T1071"}]))
    gr.generate(str(folder), incident_id="CLOUD_TEST")
    iocs = json.load(open(folder / "IOCs.json"))
    assert iocs["c2_endpoints"][0]["host"] == "45.66.77.88"
    assert iocs["c2_endpoints"][0]["port"] == 443


def test_memory_yara_clusters_per_pid(tmp_path):
    """Parity with the PS twin: memory YARA matches cluster per PID with a count."""
    folder = tmp_path / "GOTEM"
    folder.mkdir()
    findings = [
        {"Type": "YARA Match (Memory)", "Target": "PID 5308 (SecHealthUI.exe)",
         "Details": "Rule: Webshell_China_Chopper | 1 match(es)", "MITRE": "T1027", "Verdict": "True Positive"},
        {"Type": "YARA Match (Memory)", "Target": "PID 5308 (SecHealthUI.exe)",
         "Details": "Rule: Webshell_PHP_Generic | 1", "MITRE": "T1027", "Verdict": "True Positive"},
        {"Type": "YARA Match (Memory)", "Target": "PID 5308 (SecHealthUI.exe)",
         "Details": "Rule: Suspicious_PowerShell_WebDownload_1 | 1", "MITRE": "T1027", "Verdict": "True Positive"},
        {"Type": "YARA Match (Memory)", "Target": "PID 1234 (svchost.exe)",
         "Details": "Rule: REDLEAVES_CoreImplant | 3", "MITRE": "T1055", "Verdict": "True Positive"},
    ]
    (folder / "Adjudication_1.json").write_text(json.dumps(findings))
    gr.generate(str(folder), incident_id="GOTEM_t")
    md = open(folder / "Incident_Report.md", encoding="utf-8").read()
    assert "YARA matches by process (memory)" in md
    assert "SecHealthUI.exe" in md
    assert "REDLEAVES_CoreImplant" in md
    # the clustered row for PID 5308 shows a hit count of 3
    assert any("SecHealthUI.exe" in ln and "| 3 |" in ln for ln in md.splitlines())


# -- YARA hit pivot report (separate report; correlates hits to other PID signals) ----
def _pivot_folder(tmp_path, findings, name="GOTEM"):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "Adjudication_1.json").write_text(json.dumps(findings))
    (folder / "Memory_Findings_1.json").write_text("[]")
    return folder


def test_yara_pivot_true_positive_named_implant_leads(tmp_path):
    """A named malware/APT-family signature (REDLEAVES) with multiple rules on one PID is the
    true positive — it must be flagged Likely True Positive and lead the report."""
    findings = [
        {"Type": "YARA Match (Memory)", "Target": "PID 13680 (ShellExperienceHost.exe)",
         "Details": "Rule: REDLEAVES_CoreImplant_UniqueStrings | 3 match(es) | anon-exec region (rwx)",
         "MITRE": "T1055", "Verdict": "True Positive"},
        {"Type": "YARA Match (Memory)", "Target": "PID 13680 (ShellExperienceHost.exe)",
         "Details": "Rule: LOLBin_Mshta_Scriptlet | 1 match(es)", "MITRE": "T1218", "Verdict": "True Positive"},
        {"Type": "YARA Match (Memory)", "Target": "PID 13680 (ShellExperienceHost.exe)",
         "Details": "Rule: LOLBin_BITS_Drop | 1 match(es)", "MITRE": "T1197", "Verdict": "True Positive"},
    ]
    folder = _pivot_folder(tmp_path, findings)
    res = gr.generate(str(folder), incident_id="GOTEM_t")
    md = open(res["yara_pivot"], encoding="utf-8").read()
    assert "Likely True Positive" in md
    assert "PID 13680" in md and "REDLEAVES_CoreImplant_UniqueStrings" in md
    assert "1 true-positive-class" in md
    # the named implant is the TP; it carries the eradication-scope enrichment directive
    assert "Eradication scope" in md


def test_yara_pivot_generic_lone_hit_demoted_not_suppressed(tmp_path):
    """A lone generic LOLBin rule (even with a path-spoof, which is FP-prone) is NOT escalated to
    true-positive — but is still present in the report (never suppressed)."""
    findings = [
        {"Type": "YARA Match (Memory)", "Target": "PID 620 (svchost.exe)",
         "Details": "Rule: LOLBin_BITS_Drop | 1 match(es)", "MITRE": "T1197", "Verdict": "Indeterminate"},
        {"Type": "Process Path Spoofing (Memory)", "Target": "PID 620 (svchost.exe)",
         "Details": "System process running from unexpected path: \\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe",
         "MITRE": "T1036", "Verdict": "Indeterminate"},
    ]
    folder = _pivot_folder(tmp_path, findings)
    res = gr.generate(str(folder), incident_id="LONE_t")
    md = open(res["yara_pivot"], encoding="utf-8").read()
    assert "PID 620" in md and "LOLBin_BITS_Drop" in md     # present, not hidden
    assert "0 true-positive-class" in md                    # not escalated on a path-spoof FP
    assert "Likely True Positive" not in md


def test_yara_pivot_generic_hit_with_real_injection_is_tp(tmp_path):
    """Even a generic rule confirms as true-positive when it co-occurs with REAL injection
    evidence (an Injected Memory Region) on the same PID — the legitimate convergence case."""
    findings = [
        {"Type": "YARA Match (Memory)", "Target": "PID 900 (rundll32.exe)",
         "Details": "Rule: Hunting_ShellcodeBytes | 1 match(es)", "MITRE": "T1055", "Verdict": "True Positive"},
        {"Type": "Injected Memory Region", "Target": "PID 900 (rundll32.exe)",
         "Details": "RWX private region at 0x1f0000", "MITRE": "T1055", "Verdict": "True Positive"},
    ]
    folder = _pivot_folder(tmp_path, findings, name="INJ")
    res = gr.generate(str(folder), incident_id="INJ_t")
    md = open(res["yara_pivot"], encoding="utf-8").read()
    assert "1 true-positive-class" in md and "Likely True Positive" in md
    assert "Injected Memory Region" in md                    # the converging evidence is shown


def test_yara_pivot_report_absent_without_hits(tmp_path):
    """No YARA hits in the findings -> no pivot report file is written (nothing to pivot on)."""
    findings = [{"Type": "Network Connection (Memory)", "Target": "PID 100 (svchost.exe)",
                 "Details": "External 8.8.8.8:53", "MITRE": "T1071", "Verdict": "False Positive"}]
    folder = _pivot_folder(tmp_path, findings, name="NoHits")
    res = gr.generate(str(folder), incident_id="NOHITS_t")
    assert res.get("yara_pivot") is None
    assert not os.path.isfile(os.path.join(str(folder), "YARA_Pivot_Report.md"))


def test_yara_pivot_suppressed_when_adjudicator_cleared_every_hit_as_fp(tmp_path):
    """A generic rule firing on 2 distinct rule names would normally clear the score>=3 TP
    threshold on hit-count alone -- but if the adjudicator (Get-FindingContext.ps1 -Live) already
    cleared BOTH underlying YARA hits as False Positive (e.g. signed binary, known-vendor path),
    that verdict must win: the PID must NOT be promoted to true-positive-class, and therefore must
    NOT reach YARA_Pivot_TP.json / memory_enrich.py / IOCs.json eradication scope."""
    findings = [
        {"Type": "YARA Match (Memory)", "Target": "PID 4520 (IntelAudioServ)",
         "Details": "Rule: LOLBin_BITS_Drop | 1 match(es)", "MITRE": "T1197", "Verdict": "False Positive"},
        {"Type": "YARA Match (Memory)", "Target": "PID 4520 (IntelAudioServ)",
         "Details": "Rule: Suspicious_PowerShell_WebDownload_1 | 1 match(es)", "MITRE": "T1027",
         "Verdict": "Likely False Positive"},
    ]
    folder = _pivot_folder(tmp_path, findings, name="FPCLEARED")
    res = gr.generate(str(folder), incident_id="FPCLEARED_t")
    md = open(res["yara_pivot"], encoding="utf-8").read()
    assert "0 true-positive-class" in md
    assert "Likely True Positive" not in md
    assert not os.path.isfile(os.path.join(str(folder), "YARA_Pivot_TP.json"))


def test_yara_pivot_not_suppressed_when_only_some_hits_cleared_fp(tmp_path):
    """If the adjudicator cleared ONE YARA hit as FP but left another (a named malware/APT
    signature, alone worth the TP threshold) True Positive, the pivot's own signal-convergence
    score must still stand -- partial clearance is not blanket clearance."""
    findings = [
        {"Type": "YARA Match (Memory)", "Target": "PID 777 (evil.exe)",
         "Details": "Rule: LOLBin_BITS_Drop | 1 match(es)", "MITRE": "T1197", "Verdict": "False Positive"},
        {"Type": "YARA Match (Memory)", "Target": "PID 777 (evil.exe)",
         "Details": "Rule: REDLEAVES_CoreImplant_UniqueStrings | 1 match(es)", "MITRE": "T1055",
         "Verdict": "True Positive"},
    ]
    folder = _pivot_folder(tmp_path, findings, name="PARTIALFP")
    res = gr.generate(str(folder), incident_id="PARTIALFP_t")
    md = open(res["yara_pivot"], encoding="utf-8").read()
    assert "1 true-positive-class" in md
    assert "Likely True Positive" in md


def test_correlate_yara_pivots_unadjudicated_findings_not_gated(tmp_path):
    """Findings with no Verdict field at all (came from Combined_Findings, not Adjudication_*.json
    -- i.e. the adjudicator never ran) must NOT be treated as adjudicated-FP; there is no verdict
    to defer to, so the pivot's own signal-convergence score is authoritative."""
    findings = [
        {"Type": "YARA Match (Memory)", "Target": "PID 42 (a.exe)",
         "Details": "Rule: REDLEAVES_CoreImplant_UniqueStrings | 1 match(es)"},
    ]
    cp = {p["pid"]: p for p in gr.correlate_yara_pivots(findings)}
    assert cp["42"]["true_positive"] is True


def test_correlate_yara_pivots_confidence_unit():
    """Unit-level: TP confidence is driven by hit quality — named signature confirms, lone generic
    does not, and a path-spoof alone does not rescue a generic hit (FP-prone)."""
    named = [{"Type": "YARA Match (Memory)", "Target": "PID 1 (a.exe)",
              "Details": "Rule: REDLEAVES_CoreImplant_UniqueStrings | 1 match(es)"}]
    generic = [{"Type": "YARA Match (Memory)", "Target": "PID 2 (b.exe)",
                "Details": "Rule: LOLBin_BITS_Drop | 1 match(es)"},
               {"Type": "Process Path Spoofing (Memory)", "Target": "PID 2 (b.exe)",
                "Details": "unexpected path"}]
    cp = {p["pid"]: p for p in gr.correlate_yara_pivots(named + generic)}
    assert cp["1"]["true_positive"] is True               # named family signature
    assert cp["2"]["true_positive"] is False              # generic + path-spoof only
    # ordering: the true positive comes first
    order = [p["pid"] for p in gr.correlate_yara_pivots(named + generic)]
    assert order[0] == "1"


def test_bom_tolerant_loading(tmp_path):
    """PowerShell writes UTF-8 with BOM; the generator must still parse it."""
    folder = tmp_path / "bom-host"
    folder.mkdir()
    data = [{"Verdict": "True Positive", "Type": "X", "Target": "t", "MITRE": "T1219"}]
    with open(folder / "Adjudication_1.json", "w", encoding="utf-8-sig") as fh:
        json.dump(data, fh)
    res = gr.generate(str(folder), incident_id="BOM")
    assert res["total"] == 1
