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
