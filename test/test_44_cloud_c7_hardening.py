"""C7 correctness hardening of already-shipped cloud code:
  - GuardDuty finding-id list is capped by whole IDs (head -n 50), not byte-truncated
    (head -c 500), which could split the last id and fail get-findings.
  - Azure process eradication finds the VM by IP: `az vm list -d` (details required to
    populate publicIps/privateIps) + contains() (those fields are comma-joined IP strings),
    not `==` on a non-populated field (which always missed -> VM never found).
"""
import os
import subprocess

from conftest import CLOUD_DIR, cloud_env

AWS_COLLECT = os.path.join(CLOUD_DIR, "collect", "aws.sh")
ERAD_PROC = os.path.join(CLOUD_DIR, "02_eradicate_process.sh")


def _read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


# ── static: the bug patterns are gone ───────────────────────────────────────────
def test_guardduty_finding_ids_not_byte_truncated():
    src = _read(AWS_COLLECT)
    assert "head -c 500" not in src            # byte truncation could split an id
    assert "head -n 50" in src                 # whole-id cap (get-findings max 50)


def test_azure_vm_lookup_uses_show_details_and_contains():
    src = _read(ERAD_PROC)
    assert "az vm list -d" in src              # -d populates publicIps/privateIps
    assert "contains(to_string(publicIps)" in src and "contains(to_string(privateIps)" in src
    assert "publicIps=='" not in src           # the broken exact-match is gone


# ── functional: Azure eradication now finds the VM by IP ────────────────────────
def test_azure_process_eradication_finds_vm(tmp_path):
    env = cloud_env(provider="azure", target="10.0.0.5", incident="c7-az",
                    mock_log=tmp_path / "c.log")
    env["IR_AZURE_RESOURCE_GROUP"] = "rg"
    r = subprocess.run(["bash", ERAD_PROC], env=env, capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    # dry-run (default): it resolved the VM name and would deallocate it (no longer "vm_not_found")
    assert "would deallocate Azure VM vm-target" in r.stdout
    assert '"status":"skipped"' not in r.stdout
    calls = (tmp_path / "c.log").read_text()
    assert "vm list -d" in calls               # the fixed lookup was issued
