"""P3 - cross-host campaign correlation via shared IOCs."""
import json
import os
import sys

from conftest import REPORTING, run_py
from test_15_attack_graph import extract_mermaid, validate_mermaid

sys.path.insert(0, REPORTING)
import correlate_campaign as cc   # noqa: E402

CLI = os.path.join(REPORTING, "correlate_campaign.py")


def _host(root, name, c2=None, hashes=None, tools=None):
    folder = root / name
    folder.mkdir()
    (folder / "IOCs.json").write_text(json.dumps({
        "c2_endpoints": [{"host": h, "port": 443, "sanctioned": False} for h in (c2 or [])],
        "file_hashes_sha256": hashes or [],
        "remote_access_tools": tools or [],
        "attack_techniques": [],
    }))
    return folder


def test_shared_c2_links_hosts(tmp_path):
    _host(tmp_path, "hostA", c2=["evil.test"], tools=["ScreenConnect"])
    _host(tmp_path, "hostB", c2=["evil.test"], tools=["ScreenConnect"])
    _host(tmp_path, "hostC", c2=["other.test"])
    res = cc.generate(str(tmp_path))
    assert res["host_count"] == 3
    data = json.load(open(tmp_path / "campaign.json"))
    shared = {(s["kind"], s["value"]): s["hosts"] for s in data["shared_iocs"]}
    assert shared[("c2", "evil.test")] == ["hostA", "hostB"]
    assert shared[("tool", "ScreenConnect")] == ["hostA", "hostB"]
    assert ("c2", "other.test") not in shared       # single-host IOC not "shared"


def test_no_shared_iocs_means_independent(tmp_path):
    _host(tmp_path, "h1", c2=["a.test"])
    _host(tmp_path, "h2", c2=["b.test"])
    cc.generate(str(tmp_path))
    report = (tmp_path / "Campaign_Report.md").read_text()
    assert "no indicators are shared" in report
    data = json.load(open(tmp_path / "campaign.json"))
    assert data["shared_iocs"] == []


def test_campaign_links_are_pairwise(tmp_path):
    _host(tmp_path, "a", hashes=["DEADBEEF"])
    _host(tmp_path, "b", hashes=["DEADBEEF"])
    _host(tmp_path, "c", hashes=["DEADBEEF"])
    cc.generate(str(tmp_path))
    data = json.load(open(tmp_path / "campaign.json"))
    pairs = {tuple(sorted(l["hosts"])) for l in data["links"]}
    assert pairs == {("a", "b"), ("a", "c"), ("b", "c")}


def test_campaign_graph_is_valid_mermaid(tmp_path):
    _host(tmp_path, "hostA", c2=["evil.test"])
    _host(tmp_path, "hostB", c2=["evil.test"])
    cc.generate(str(tmp_path))
    body = extract_mermaid((tmp_path / "Campaign_Report.md").read_text())
    assert body.splitlines()[0].strip() == "flowchart LR"
    # the campaign graph validator expects flowchart LR; reuse node/edge checks
    errs = [e for e in validate_mermaid("flowchart TD\n" + "\n".join(body.splitlines()[1:]))]
    assert errs == [], errs


def test_campaign_cli(tmp_path):
    _host(tmp_path, "x", c2=["z.test"])
    _host(tmp_path, "y", c2=["z.test"])
    r = run_py(CLI, "--root", str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert "shared IOC" in r.stdout
    assert (tmp_path / "Campaign_Report.md").exists()
