"""Evidence chain-of-custody + tamper-evident signing (evidence_custody.py).

Seals the per-run sha256 manifest with operator identity + a signature so post-collection
tampering is detectable. HMAC path is fully stdlib-testable; gpg/openssl are best-effort.
"""
import json
import os
import subprocess
import sys

from conftest import REPORTING

sys.path.insert(0, REPORTING)
import evidence_custody as ec          # noqa: E402


def _host(tmp_path, stamp="20260101_000000"):
    d = tmp_path / "HOSTC"
    d.mkdir()
    manifest = {"incident_id": "HOSTC_1", "hostname": "HOSTC", "platform": "linux",
                "artifact_count": 3,
                "artifacts": [{"path": "a.json", "sha256": "x"}]}
    (d / f"_manifest_{stamp}.json").write_text(json.dumps(manifest))
    return d, stamp


# ── pure helpers ─────────────────────────────────────────────────────────────
def test_operator_respects_env(monkeypatch):
    monkeypatch.setenv("IR_OPERATOR", "alice@soc")
    assert ec.operator() == "alice@soc"


def test_build_record_seals_manifest_hash(tmp_path):
    d, stamp = _host(tmp_path)
    mpath = str(d / f"_manifest_{stamp}.json")
    rec = ec.build_record(mpath, op="bob@ir")
    assert rec["incident_id"] == "HOSTC_1" and rec["hostname"] == "HOSTC"
    assert rec["collected_by"] == "bob@ir"
    assert rec["manifest_sha256"] == ec.sha256_file(mpath)
    assert rec["artifact_count"] == 3


def test_hmac_roundtrip():
    sig = ec.hmac_sign(b"data", "k")
    assert ec.hmac_verify(b"data", "k", sig)
    assert not ec.hmac_verify(b"tampered", "k", sig)


# ── write + sign ─────────────────────────────────────────────────────────────
def test_write_custody_hmac(tmp_path, monkeypatch):
    d, _ = _host(tmp_path)
    monkeypatch.setenv("IR_CUSTODY_HMAC_KEY", "secret")
    monkeypatch.setenv("IR_OPERATOR", "carol@soc")
    record, out = ec.write_custody(str(d))
    assert record["signature"]["method"] == "hmac-sha256" and record["signature"]["value"]
    assert os.path.exists(out)
    # custody trail appended
    log = (d / "_custody_log.jsonl").read_text().strip().splitlines()
    assert len(log) == 1 and json.loads(log[0])["collected_by"] == "carol@soc"


def test_write_custody_unsigned_still_records_hash(tmp_path, monkeypatch):
    d, _ = _host(tmp_path)
    for k in ("IR_SIGNING_GPG_KEY", "IR_SIGNING_KEY", "IR_CUSTODY_HMAC_KEY"):
        monkeypatch.delenv(k, raising=False)
    record, _ = ec.write_custody(str(d))
    assert record["signature"]["method"] == "unsigned"
    assert record["manifest_sha256"]              # still tamper-evident


def test_write_custody_no_manifest(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    try:
        ec.write_custody(str(d))
        assert False, "expected FileNotFoundError"
    except FileNotFoundError:
        pass


# ── verification ─────────────────────────────────────────────────────────────
def test_verify_ok_then_detects_tamper(tmp_path, monkeypatch):
    d, stamp = _host(tmp_path)
    monkeypatch.setenv("IR_CUSTODY_HMAC_KEY", "secret")
    ec.write_custody(str(d))
    ok, issues = ec.verify_custody(str(d))
    assert ok and not issues
    # tamper with the sealed manifest
    (d / f"_manifest_{stamp}.json").write_text(json.dumps({"artifact_count": 999}))
    ok2, issues2 = ec.verify_custody(str(d))
    assert not ok2 and any("sha256 mismatch" in i for i in issues2)


def test_verify_hmac_needs_key(tmp_path, monkeypatch):
    d, _ = _host(tmp_path)
    monkeypatch.setenv("IR_CUSTODY_HMAC_KEY", "secret")
    ec.write_custody(str(d))
    monkeypatch.delenv("IR_CUSTODY_HMAC_KEY")     # verifier lacks the key
    ok, issues = ec.verify_custody(str(d))
    assert not ok and any("cannot verify" in i for i in issues)


def test_cli_write_then_verify(tmp_path, monkeypatch):
    d, _ = _host(tmp_path)
    env = dict(os.environ, IR_CUSTODY_HMAC_KEY="k", IR_OPERATOR="dave@ir")
    script = os.path.join(REPORTING, "evidence_custody.py")
    w = subprocess.run([sys.executable, script, "--host-folder", str(d), "--quiet"],
                       env=env, capture_output=True, text=True)
    assert w.returncode == 0, w.stderr
    v = subprocess.run([sys.executable, script, "--host-folder", str(d), "--verify"],
                       env=env, capture_output=True, text=True)
    assert v.returncode == 0 and "OK" in v.stdout
