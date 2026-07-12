"""P0 #1 - credential/session revocation: principal extraction, reversible contract, per-platform wiring."""
import json
import os
import subprocess
import sys

import pytest

import workflow_sim as sim
from conftest import (REPORTING, PLAYBOOKS, ROOT, IRCOLLECT_SH, IRCOLLECT_PS1,
                      IRCOLLECT_CLOUD_SH, ERADICATE_PS1, ERADICATE_CLOUD_SH,
                      read_text, run_py, cloud_env)

sys.path.insert(0, REPORTING)
import extract_principals as ep   # noqa: E402

PRINC_PY = os.path.join(REPORTING, "extract_principals.py")
REVOKE_SH = os.path.join(PLAYBOOKS, "linux", "07_revoke_credentials.sh")


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


# -- Linux revocation playbook (plan mode, safety) -----------------------------
def test_linux_plan_lists_targets_skips_protected(tmp_path):
    princ = tmp_path / "Principals.json"
    princ.write_text(json.dumps({"principals": [
        {"name": "attacker", "type": "local", "auto_revoke": True},
        {"name": "root", "type": "local", "auto_revoke": False},
    ]}))
    r = subprocess.run(["bash", REVOKE_SH, "--principals", str(princ)],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    assert "PLAN: passwd -l attacker" in r.stdout
    assert "root" not in r.stdout.replace("rollback", "")  # root never planned
    assert "[i] PLAN only" in r.stdout                      # nothing applied


# -- Per-platform wiring -------------------------------------------------------
def test_orchestrators_emit_principals():
    assert "extract_principals.py" in read_text(IRCOLLECT_SH)
    assert "extract_principals.py" in read_text(IRCOLLECT_CLOUD_SH)
    win = read_text(IRCOLLECT_PS1)
    assert "-PrincipalsOnly" in win                          # Windows native, no python
    assert "extract_principals.py" not in win


def test_windows_eradication_revokes_credentials_natively():
    src = read_text(ERADICATE_PS1)
    assert "Principals.json" in src
    assert "Disable-LocalUser" in src
    assert "klist purge" in src
    assert "disable_account" in src                          # journaled (reversible)
    assert "$env:USERNAME" in src                            # never disable the responder


def test_cloud_eradication_revokes_iam_principals(tmp_path):
    host = tmp_path / "aws-10_0_0_5"
    host.mkdir()
    (host / "Principals.json").write_text(json.dumps({"principals": [
        {"name": "rogue-iam-user", "type": "iam", "auto_revoke": True},
        {"name": "system", "type": "iam", "auto_revoke": False},
    ]}))
    env = cloud_env(incident="aws-cred", mock_log=tmp_path / "c.log")
    r = subprocess.run(["bash", ERADICATE_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.5",
                        "--host-folder", str(host)], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert "rogue-iam-user" in r.stdout          # implicated IAM principal flows to eradication
    assert "system" not in r.stdout.split("IAM revoke:")[1].split("\n")[0]  # protected excluded


def test_windows_collection_no_python_dependency():
    """Windows orchestrator + native generator must not invoke python or .py scripts."""
    orch = read_text(IRCOLLECT_PS1)
    assert ".py" not in orch                            # orchestrator references no python scripts
    for src in (orch, read_text(os.path.join(REPORTING, "generate_reports.ps1"))):
        assert "Get-Command python" not in src          # no python executable lookup
        assert "python.exe" not in src
        assert "-File" not in src or ".py" not in src.split("-File", 1)[-1][:40]  # no -File *.py invocation
