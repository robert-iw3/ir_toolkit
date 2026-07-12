"""Section 7 - end-to-end (Cloud): full lifecycle against the mock provider
(collection -> report -> eradicate -> restore)."""
import json
import subprocess

from conftest import IRCOLLECT_CLOUD_SH, ERADICATE_CLOUD_SH, cloud_env


def test_cloud_full_lifecycle(tmp_path):
    """Cloud pipeline against the mock provider: collection -> report -> eradicate -> restore."""
    env = cloud_env(incident="aws-life", mock_log=tmp_path / "calls.log")
    out_root = tmp_path / "proj"
    out_root.mkdir()

    # 1-3. COLLECTION -> findings -> REPORTING via the orchestrator.
    coll = subprocess.run(
        ["bash", IRCOLLECT_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.9",
         "--incident-id", "aws-life", "--c2-ips", "198.51.100.7",
         "--output-root", str(out_root)],
        env=env, capture_output=True, text=True, timeout=120)
    assert coll.returncode == 0, coll.stderr
    host = out_root / "aws-10_0_0_9"
    iocs = json.load(open(host / "IOCs.json"))
    assert any(e["host"] == "198.51.100.7" for e in iocs["c2_endpoints"])
    assert (host / "Retrospective.md").exists()

    # 4-5. ERADICATION + RESTORATION via the orchestrator (known-bad sourced from IOCs.json).
    erad = subprocess.run(
        ["bash", ERADICATE_CLOUD_SH, "--provider", "aws", "--target", "10.0.0.9",
         "--host-folder", str(host), "--apply", "--restore"],
        env=env, capture_output=True, text=True, timeout=120)
    assert erad.returncode == 0, erad.stderr
    assert "198.51.100.7" in erad.stdout            # known-bad carried into eradication
    assert "[run] 04_block_c2.sh" in erad.stdout    # C2 blocked
    assert "Restoration" in erad.stdout             # containment released
