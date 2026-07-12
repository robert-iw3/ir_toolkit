"""P0 #1 - credential/session revocation: principal extraction + the reversible revocation
contract (platform-agnostic). See test_18_credential_revocation_{windows,linux,cloud}.py for
the per-platform orchestrator/eradication wiring."""
import json
import os
import sys

import workflow_sim as sim
from conftest import REPORTING, run_py

sys.path.insert(0, REPORTING)
import extract_principals as ep   # noqa: E402

PRINC_PY = os.path.join(REPORTING, "extract_principals.py")


# -- Principal extraction (analysis stage) -------------------------------------
def _adj(tmp_path, findings):
    folder = tmp_path / "WINHOST"
    folder.mkdir()
    (folder / "Adjudication_1.json").write_text(json.dumps(findings))
    return str(folder)


def test_extracts_only_true_positive_accounts(tmp_path):
    folder = _adj(tmp_path, [
        {"Type": "Hidden Process", "Verdict": "True Positive", "Owner": "WINHOST\\alice", "Target": "p"},
        {"Type": "Hidden Process", "Verdict": "False Positive", "Owner": "WINHOST\\eve", "Target": "p"},
    ])
    _, data = ep.emit(folder, "INC")
    names = {p["name"] for p in data["principals"]}
    assert "alice" in names
    assert "eve" not in names                     # from a false positive -> excluded


def test_local_vs_domain_vs_cloud_classification(tmp_path):
    folder = _adj(tmp_path, [
        {"Type": "Hidden Process", "Verdict": "True Positive", "Owner": "WINHOST\\alice", "Target": "p"},
        {"Type": "Remote Access Tool", "Verdict": "True Positive", "Owner": "CORP\\bob", "Target": "p"},
        {"Type": "Cloud Identity Risk", "Verdict": "Likely True Positive", "Target": "victim@corp.test"},
        {"Type": "Cloud Detection", "Verdict": "Likely True Positive", "Target": "rogue-iam-user"},
    ])
    _, data = ep.emit(folder, "INC")
    by = {p["name"]: p["type"] for p in data["principals"]}
    assert by["alice"] == "local"                 # domain == hostname -> local
    assert by["bob"] == "domain"
    assert by["victim@corp.test"] == "cloud-identity"
    assert by["rogue-iam-user"] == "iam"


def test_protected_accounts_not_auto_revocable(tmp_path):
    folder = _adj(tmp_path, [
        {"Type": "Hidden Process", "Verdict": "True Positive", "Owner": "NT AUTHORITY\\SYSTEM", "Target": "p"},
        {"Type": "Hidden Process", "Verdict": "True Positive", "Owner": "WINHOST\\alice", "Target": "p"},
    ])
    _, data = ep.emit(folder, "INC")
    by = {p["name"].lower(): p["auto_revoke"] for p in data["principals"]}
    assert by["system"] is False
    assert by["alice"] is True


def test_principal_cli(tmp_path):
    folder = _adj(tmp_path, [{"Type": "Hidden Process", "Verdict": "True Positive",
                              "Owner": "WINHOST\\alice", "Target": "p"}])
    r = run_py(PRINC_PY, "--host-folder", folder, "--incident-id", "INC")
    assert r.returncode == 0, r.stderr
    assert os.path.isfile(os.path.join(folder, "Principals.json"))


# -- Reversible revocation contract --------------------------------------------
def test_revoke_journals_and_disables():
    store = {"alice": {"enabled": True}}
    journal = "/tmp/_credtest.jsonl"
    open(journal, "w").close()
    assert sim.revoke_account(store, "alice", journal) == "disabled"
    assert store["alice"]["enabled"] is False
    line = json.loads(open(journal).read().strip())
    assert line == {"action": "disable_account", "name": "alice", "prior_enabled": True}
    os.remove(journal)


def test_revoke_refuses_protected():
    store = {}
    assert sim.revoke_account(store, "root", "/tmp/x.jsonl") == "protected"
    assert sim.revoke_account(store, "Administrator", "/tmp/x.jsonl") == "protected"


def test_revoke_is_reversible(tmp_path):
    store = {"alice": {"enabled": True}, "bob": {"enabled": True}}
    journal = str(tmp_path / "j.jsonl")
    sim.revoke_account(store, "alice", journal)
    sim.revoke_account(store, "bob", journal)
    assert all(not store[u]["enabled"] for u in ("alice", "bob"))
    restored = sim.restore_accounts(store, journal)
    assert set(restored) == {"alice", "bob"}
    assert all(store[u]["enabled"] for u in ("alice", "bob"))
