"""Section 4 - eradication: the firewall restore-minus-known-bad handshake and the quarantine contract."""
import json
import os

import workflow_sim as sim
from conftest import ERADICATE_PS1, read_text


# -- Windows eradication wiring (validated structurally; needs Windows to run) --
def test_eradication_consumes_adjudication():
    src = read_text(ERADICATE_PS1)
    assert "Adjudication_*.json" in src
    assert "MinVerdict" in src


def test_eradication_dry_run_by_default():
    src = read_text(ERADICATE_PS1)
    assert "-Apply" in src
    assert "DRY-RUN" in src


def test_eradication_restores_firewall_to_known_good():
    src = read_text(ERADICATE_PS1)
    assert "_firewall_state.json" in src           # finds the pre-incident backup
    assert "advfirewall import" in src             # restores known-good


def test_eradication_keeps_known_bad_blocked():
    """After restore, adversary C2 from IOCs.json must be re-blocked/sinkholed."""
    src = read_text(ERADICATE_PS1)
    assert "IOCs.json" in src
    assert "c2_endpoints" in src
    assert "sanctioned" in src                     # only NON-sanctioned are re-blocked
    assert "New-NetFirewallRule" in src
    assert "Block" in src
    assert "hosts" in src                          # FQDN sinkhole


def test_eradication_safety_rails_present():
    src = read_text(ERADICATE_PS1)
    for guard in ("Test-Protected", "validly code-signed", "System32"):
        assert guard in src


# -- Cross-Process Thread Handle: surgical thread-level containment ------------
# memory_forensic.py Module 23 (cross-process handle/thread attribution) feeds
# findings whose Target holds TWO PIDs (holder -> target). Killing the whole
# HOLDER process over one malicious thread is strictly worse than necessary --
# and if the holder is (or masquerades as) a core OS session-management process,
# Stop-Process on it can BSOD the host. These tests verify the narrower,
# thread-scoped action exists, is ordered correctly, and re-checks live identity.

def test_thread_handle_case_precedes_generic_process_case():
    """'Cross-Process Thread Handle (Memory)' textually contains 'Process' and would
    match the generic 'Hidden Process|Process|Injection|LOLBin' pattern too -- the
    dedicated case MUST appear first in the switch, or PowerShell's `switch -Regex`
    (which tests every matching pattern, not just the first) would run both."""
    src = read_text(ERADICATE_PS1)
    thread_idx  = src.find("'Cross-Process Thread Handle' {")
    generic_idx = src.find("'Hidden Process|Process|Injection|LOLBin' {")
    assert thread_idx != -1, "Cross-Process Thread Handle case not found"
    assert generic_idx != -1, "generic process case not found"
    assert thread_idx < generic_idx, (
        "Cross-Process Thread Handle case must precede the generic Process case "
        "in switch -Regex evaluation order"
    )


def test_thread_handle_case_breaks_to_prevent_fallthrough():
    """The case must end with an unconditional `break` so it never falls through
    into the generic process-kill case for the same finding."""
    src = read_text(ERADICATE_PS1)
    start = src.find("'Cross-Process Thread Handle' {")
    end   = src.find("'Hidden Process|Process|Injection|LOLBin' {")
    assert start != -1 and end != -1
    block = src[start:end]
    # last non-brace statement before the case closes must be a bare `break`
    assert block.rstrip().rstrip('}').rstrip().endswith('break'), (
        "Cross-Process Thread Handle case does not end with an unconditional break -- "
        "risks double-executing the generic Stop-Process action for the same finding"
    )


def test_thread_handle_parses_holder_pid_not_target_pid():
    """Target format is 'PID <holder> (<name>) -> Target PID <target> TID <tid>' (same
    convention every module uses, anchored so engine.py groups by the holder) -- eradication
    must extract the HOLDER pid (the process reaching in) for identity/safety checks,
    never the target/victim pid."""
    src = read_text(ERADICATE_PS1)
    assert "'^PID\\s+(\\d+)'" in src
    assert "'TID\\s+(\\d+)'" in src


def test_thread_handle_uses_terminate_thread_not_stop_process():
    """The action must scope to the specific thread (OpenThread+TerminateThread),
    not Stop-Process on the whole holder process."""
    src = read_text(ERADICATE_PS1)
    start = src.find("'Cross-Process Thread Handle' {")
    end   = src.find("'Hidden Process|Process|Injection|LOLBin' {")
    block = src[start:end]
    assert "TerminateThread" in block
    assert "OpenThread" in block
    assert "Stop-Process -Id" not in block, (
        "Cross-Process Thread Handle case must not kill the entire holder process "
        "(a comment may reference Stop-Process for context; an actual call must not appear)"
    )


def test_thread_handle_only_requests_terminate_access():
    """OpenThread must request THREAD_TERMINATE (0x0001) only -- not a broader access
    mask -- keeping the P/Invoke call scoped to exactly what it needs."""
    src = read_text(ERADICATE_PS1)
    assert "THREAD_TERMINATE = 0x0001" in src


def test_thread_handle_has_live_bsod_critical_recheck():
    """Defense in depth beyond the upstream Test-Protected guard: re-resolve the
    HOLDER's live process name immediately before calling TerminateThread and refuse
    if it is a core OS session-management process (csrss/services/winlogon/smss/
    wininit/system) -- these crash the system if destabilized, and adjudication data
    can be stale relative to a live host by the time -Apply actually runs."""
    src = read_text(ERADICATE_PS1)
    start = src.find("'Cross-Process Thread Handle' {")
    end   = src.find("'Hidden Process|Process|Injection|LOLBin' {")
    block = src[start:end]
    for name in ('csrss', 'services', 'winlogon', 'smss', 'wininit', 'system'):
        assert name in block, f"BSOD-critical recheck missing '{name}'"
    assert "Get-Process -Id $holderPid" in block


def test_thread_handle_dry_run_by_default():
    """Like every other eradication action, this must be plan-only without -Apply."""
    src = read_text(ERADICATE_PS1)
    start = src.find("'Cross-Process Thread Handle' {")
    end   = src.find("'Hidden Process|Process|Injection|LOLBin' {")
    block = src[start:end]
    assert "if (-not $Apply) { $rec.Status='planned'; break }" in block


# -- The quarantine contract executes here (cross-platform model) --------------
def test_quarantine_moves_file_and_journals(tmp_path):
    victim = tmp_path / "evil.exe"
    victim.write_bytes(b"malicious payload")
    qdir = tmp_path / "Quarantine"
    journal = tmp_path / "rollback.jsonl"

    entry = sim.quarantine(str(victim), str(qdir), str(journal))
    assert not victim.exists()                     # original removed
    assert os.path.isfile(entry["dest"])           # moved to quarantine
    line = json.loads(open(journal).read().strip())
    assert line["action"] == "quarantine"
    assert line["sha256"] == entry["sha256"]


def test_eradication_cloud_reads_known_bad_from_iocs(tmp_path):
    """Invoke-Eradication-Cloud.sh pulls non-sanctioned C2 out of IOCs.json."""
    folder = tmp_path / "aws-host"
    folder.mkdir()
    (folder / "IOCs.json").write_text(json.dumps({
        "c2_endpoints": [
            {"host": "45.66.77.88", "port": 443, "sanctioned": False},
            {"host": "instance-x.screenconnect.com", "port": 443, "sanctioned": True},
        ]}))
    # mirror the script's IOC extraction
    d = json.load(open(folder / "IOCs.json", encoding="utf-8-sig"))
    known_bad = [e["host"] for e in d["c2_endpoints"] if not e["sanctioned"]]
    assert known_bad == ["45.66.77.88"]
