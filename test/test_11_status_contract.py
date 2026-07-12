"""P1-6 - every orchestrator emits a uniform _status.json for SOAR gating.

Platform-agnostic: playbooks/lib/status.sh is the SHARED status library every orchestrator
(Windows/Linux/Cloud) sources, and the cross-orchestrator check here only reads script text
(no execution, no platform tooling required). See test_11_status_contract_cloud.py for the
one test that actually executes the cloud orchestrator.
"""
import json
import os
import subprocess

from conftest import PLAYBOOKS, IRCOLLECT_CLOUD_SH, IRCOLLECT_PS1, IRCOLLECT_SH, read_text

STATUS_LIB = os.path.join(PLAYBOOKS, "lib", "status.sh")
REQUIRED_KEYS = {"incident_id", "hostname", "platform", "status", "tp_count", "phases"}
VALID_STATUS = {"COMPLETED", "PARTIAL", "FAILED"}


def _emit_status(records, out, incident="i", host="h", platform="p", tp=0):
    """Drive status.sh with a sequence of (name, outcome) records."""
    lines = ['source "$1"']
    for name, outcome in records:
        lines.append(f'ir_record "{name}" "{outcome}"')
    lines.append(f'ir_status_write "$2" "{incident}" "{host}" "{platform}" "{tp}"')
    script = "\n".join(lines)
    r = subprocess.run(["bash", "-c", script, "_", STATUS_LIB, str(out)],
                       capture_output=True, text=True, timeout=30)
    return r


def test_status_all_success_is_completed(tmp_path):
    out = tmp_path / "_status.json"
    r = _emit_status([("a", "success"), ("b", "success")], out)
    assert r.stdout.strip() == "COMPLETED"
    data = json.loads(out.read_text())
    assert REQUIRED_KEYS <= set(data)
    assert data["status"] == "COMPLETED"
    assert data["phases"] == {"a": "success", "b": "success"}


def test_status_mixed_is_partial(tmp_path):
    out = tmp_path / "_status.json"
    r = _emit_status([("a", "success"), ("b", "failed")], out, tp=3)
    assert r.stdout.strip() == "PARTIAL"
    data = json.loads(out.read_text())
    assert data["status"] == "PARTIAL"
    assert data["tp_count"] == 3


def test_status_all_failed_is_failed(tmp_path):
    out = tmp_path / "_status.json"
    r = _emit_status([("a", "failed")], out)
    assert r.stdout.strip() == "FAILED"


def test_status_json_is_valid(tmp_path):
    out = tmp_path / "_status.json"
    _emit_status([("forensics", "success"), ("hunt", "skipped")], out)
    data = json.loads(out.read_text())          # must be parseable JSON
    assert data["status"] in VALID_STATUS


def test_orchestrators_all_emit_status():
    assert "_status.json" in read_text(IRCOLLECT_SH)
    assert "_status.json" in read_text(IRCOLLECT_CLOUD_SH)
    assert "_status.json" in read_text(IRCOLLECT_PS1)
