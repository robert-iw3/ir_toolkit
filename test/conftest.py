"""Shared paths, helpers, and synthetic-collection fixtures for the IR test suite."""
import json
import os
import subprocess
import sys

import pytest

import fixtures

# Repository layout.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAYBOOKS = os.path.join(ROOT, "playbooks")
REPORTING = os.path.join(PLAYBOOKS, "reporting")
WIN_HUNT = os.path.join(PLAYBOOKS, "windows", "threat_hunting")
LINUX_HUNT = os.path.join(PLAYBOOKS, "linux", "threat_hunting")

GENERATE_PY = os.path.join(REPORTING, "generate_reports.py")
GENERATE_PS1 = os.path.join(REPORTING, "generate_reports.ps1")
IRCOLLECT_PS1 = os.path.join(ROOT, "Invoke-IRCollection.ps1")
FORENSICS_PS1 = os.path.join(PLAYBOOKS, "windows", "00_Collect-Forensics.ps1")
IRCOLLECT_SH = os.path.join(ROOT, "Invoke-IRCollection-Linux.sh")
ERADICATE_PS1 = os.path.join(ROOT, "Invoke-Eradication.ps1")
ERADICATE_SH = os.path.join(ROOT, "Invoke-Eradication-Linux.sh")
FIREWALL_PS1 = os.path.join(PLAYBOOKS, "windows", "Enforce-StrictFirewall.ps1")
RESTORE_PS1 = os.path.join(PLAYBOOKS, "windows", "06_Restore-Host.ps1")
RESTORE_SH = os.path.join(PLAYBOOKS, "linux", "06_restore.sh")
CLOUD_DIR = os.path.join(PLAYBOOKS, "cloud")
MOCKS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mocks")
IRCOLLECT_CLOUD_SH = os.path.join(ROOT, "Invoke-IRCollection-Cloud.sh")
ERADICATE_CLOUD_SH = os.path.join(ROOT, "Invoke-Eradication-Cloud.sh")

sys.path.insert(0, REPORTING)


def cloud_env(provider="aws", target="10.0.0.5", incident="ct-test", mock_log=None, **extra):
    """Environment for running a cloud playbook against the mock CLIs."""
    env = dict(os.environ)
    env["PATH"] = MOCKS + os.pathsep + env.get("PATH", "")
    env.update({"IR_CLOUD_PROVIDER": provider, "IR_TARGET": target,
                "IR_INCIDENT_ID": incident, "IR_AWS_REGION": "us-east-1"})
    if mock_log:
        env["IR_MOCK_LOG"] = str(mock_log)
    env.update(extra)
    return env


def read_text(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def load_json_bom(path):
    """Load JSON tolerating PowerShell's UTF-8 BOM."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return json.load(fh)


def newest(folder, pattern):
    import glob
    hits = sorted(glob.glob(os.path.join(folder, pattern)), key=os.path.getmtime, reverse=True)
    return hits[0] if hits else None


@pytest.fixture
def windows_collection(tmp_path):
    """A synthetic Windows collection folder (RAT + custom C2 + disabled Defender)."""
    return fixtures.materialize(str(tmp_path / "WINTEST"), platform="windows")


@pytest.fixture
def linux_collection(tmp_path):
    """A synthetic Linux collection folder (no remote-access tool)."""
    return fixtures.materialize(str(tmp_path / "LINTEST"), platform="linux")


def run_py(script, *args, cwd=None):
    return subprocess.run([sys.executable, script, *args],
                          capture_output=True, text=True, cwd=cwd, timeout=120)
