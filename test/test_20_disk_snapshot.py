"""Cloud disk-snapshot acquisition (evidence preservation before eradication).

Closes the Collection gap: the cloud workflow isolated/stopped instances but never
captured a disk snapshot. Opt-in via --snapshot-disks (billable). Exercised against
the recording mock CLIs in test/mocks/.
"""
import json
import subprocess
import sys

from conftest import IRCOLLECT_CLOUD_SH, cloud_env


def _run(tmp_path, provider, target, extra=()):
    # Unique incident id per test: the forensics staging dir is /tmp/ir/<incident>,
    # shared across runs — a reused id would leak artifacts between tests.
    incident = f"{provider}-snap-{tmp_path.name}"
    env = cloud_env(provider=provider, target=target,
                    incident=incident, mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", provider, "--target", target,
         "--incident-id", incident, "--output-root", str(out_root), *extra],
        env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr or r.stdout
    label = f"{provider}-" + "".join(c if c.isalnum() else "_" for c in target)
    return out_root / label, (tmp_path / "calls.log").read_text()


def test_aws_snapshot_disks_acquires_ebs(tmp_path):
    host, calls = _run(tmp_path, "aws", "10.0.0.5", extra=["--snapshot-disks"])
    snap = host / "cloud_forensics" / "ebs_snapshots.json"
    assert snap.exists()
    data = json.loads(snap.read_text())
    assert data["snapshots"] and data["snapshots"][0]["snapshot"].startswith("snap-")
    assert "ec2 create-snapshot" in calls


def test_aws_no_snapshot_without_flag(tmp_path):
    """Snapshotting is opt-in — no flag, no billable snapshot, no artifact."""
    host, calls = _run(tmp_path, "aws", "10.0.0.5")
    assert not (host / "cloud_forensics" / "ebs_snapshots.json").exists()
    assert "create-snapshot" not in calls


def test_azure_snapshot_disks_acquires(tmp_path):
    host, calls = _run(tmp_path, "azure", "vm1", extra=["--snapshot-disks"])
    snap = host / "cloud_forensics" / "azure_disk_snapshots.json"
    assert snap.exists()
    data = json.loads(snap.read_text())
    assert data["snapshots"] and "snapshots/irsnap-1" in data["snapshots"][0]["snapshot"]
    assert "snapshot create" in calls


def test_gcp_snapshot_disks_acquires(tmp_path):
    host, calls = _run(tmp_path, "gcp", "vm1", extra=["--snapshot-disks"])
    snap = host / "cloud_forensics" / "gcp_disk_snapshots.json"
    assert snap.exists()
    data = json.loads(snap.read_text())
    assert data["snapshots"] and data["snapshots"][0]["snapshot"].startswith("irsnap-disk-1")
    assert "compute disks snapshot" in calls
