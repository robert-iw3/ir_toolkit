"""Third-party tooling is accounted for in the Linux offline-toolkit builder."""
import json
import os
import subprocess

from conftest import ROOT, IRCOLLECT_SH, read_text

BUILD_SH = os.path.join(ROOT, "Build-OfflineToolkit-Linux.sh")


def test_linux_builder_accounts_for_memory_and_cloud():
    src = read_text(BUILD_SH)
    assert "avml" in src.lower()                 # Linux memory acquisition (+ 'convert' decompresses --compress LiME)
    assert "dwarf2json" in src                   # build Volatility 3 Linux ISF
    assert "vol3_wheels" in src                  # offline analyzer venv
    assert "loldrivers" in src.lower()
    for cli in ("aws", "az", "gcloud"):          # cloud-workflow dependencies recorded
        assert cli in src


def test_linux_builder_check_only_writes_manifest(tmp_path):
    """--check-only records tool presence + writes a sha256 manifest with no network."""
    tools = tmp_path / "tools"
    r = subprocess.run(["bash", BUILD_SH, "--tools-dir", str(tools),
                        "--include-memory", "--check-only"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    manifest = json.loads((tools / "STAGED_MANIFEST.json").read_text())
    names = {t["name"] for t in manifest["tools"]}
    assert "AVML" in names
    # full memory-analysis toolchain is accounted for (staged or recorded not-staged)
    assert {"dwarf2json", "volatility3-wheels", "yara_rules"} <= names
    assert {"cloud:aws", "cloud:az", "cloud:gcloud"} <= names
    # cloud CLIs are absent on this host -> recorded as MISSING (accounted for, not silent)
    aws = next(t for t in manifest["tools"] if t["name"] == "cloud:aws")
    assert "present" in aws["status"] or "MISSING" in aws["status"]


def test_manifest_inventories_system_and_symbol_deps(tmp_path):
    """The manifest is a COMPLETE inventory: vendored tools + kernel symbols + the OS tools
    the stdlib-only workflows shell out to (so an offline host's needs are explicit)."""
    tools = tmp_path / "tools"
    r = subprocess.run(["bash", BUILD_SH, "--tools-dir", str(tools),
                        "--include-memory", "--include-cloud", "--check-only"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    names = {t["name"] for t in json.loads((tools / "STAGED_MANIFEST.json").read_text())["tools"]}
    assert "symbols" in names                                   # kernel ISF accounted for
    assert {"cloud:kubectl", "cloud:terraform"} <= names        # k8s + IaC recorded
    # system tools the workflows depend on are inventoried (present or absent, never silent)
    assert {"sys:python3", "sys:ip", "sys:dpkg", "sys:debuginfod-find"} <= names


def test_dependencies_doc_exists():
    dep = os.path.join(os.path.dirname(BUILD_SH), "DEPENDENCIES.md")
    assert os.path.exists(dep)
    txt = read_text(dep)
    assert "stdlib" in txt.lower() and "vol3_wheels" in txt and "symbols" in txt.lower()


def test_memory_capture_wired_linux():
    lin = read_text(IRCOLLECT_SH)
    assert "--capture-memory" in lin                          # Linux (avml)
    assert "tools/avml" in lin


def test_linux_memory_capture_handles_avml_gracefully(tmp_path):
    """--capture-memory must never fail the collection (rc 0), whether or not avml is
    staged: unstaged -> logged skip; staged-but-fails -> Memory phase fails, run continues."""
    out_root = tmp_path / "proj"
    out_root.mkdir()
    r = subprocess.run(["bash", IRCOLLECT_SH, "--output-root", str(out_root),
                        "--incident-id", "memtest", "--capture-memory",
                        "--skip-hunt", "--skip-reports"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr                       # never fatal — the invariant
    host = next(out_root.iterdir())
    log = (host / [f for f in os.listdir(host) if f.startswith("_runtime")][0]).read_text()
    # graceful either way: a logged skip (unstaged) or a Memory phase that didn't abort
    assert "avml not staged" in log or "PHASE: Memory" in log
