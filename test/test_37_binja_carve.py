"""Section 37 - Windows TP-region carve for Binary Ninja (memory_yara_worker.carve_region).
Mirrors the Linux linux_yara_worker carve: a YARA hit in a Private+exec (injected) VAD is dumped
as raw .bin + a JSON sidecar into tools\\binja\\data\\<id>\\. Pure: carve_region needs no vmmpyc
(vmmpyc is imported inside the worker's main(), not at module load), so it imports cleanly here."""
import json, os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..",
                                "playbooks", "windows", "threat_hunting"))
import memory_yara_worker as w


def test_safe_sanitizes_names():
    assert w._safe("svchost.exe") == "svchost.exe"
    assert w._safe("a/b\\c:d*e") == "a_b_c_d_e"          # path/separator chars -> _
    assert w._safe("") == "x"


def test_carve_injected_anon_exec_writes_bin_and_sidecar(tmp_path):
    data = bytes((i * 7 + 3) & 0xFF for i in range(4096))
    binp = w.carve_region(str(tmp_path), "memory_host.aff4", 13680, "ShellExperienceHost.exe",
                          0x241dcfd0000, data, "p-rwx-", "anon", "", "", {"REDLEAVES_CoreImplant"})
    assert binp and os.path.isfile(binp)
    assert binp.endswith("pid13680_ShellExperienceHost.exe_0x241dcfd0000.bin")
    # raw bytes are written verbatim (inert) and round-trip exactly
    with open(binp, "rb") as fh:
        assert fh.read() == data
    meta = json.load(open(binp[:-4] + ".json", encoding="utf-8"))
    assert meta["injected"] is True                     # anon + exec => injected TP
    assert meta["base_address"] == "0x241dcfd0000"      # load base in Binary Ninja
    assert meta["size"] == 4096
    assert meta["matched_rules"] == ["REDLEAVES_CoreImplant"]
    assert meta["vad_type"] == "" and meta["protection"] == "p-rwx-"   # Private VAD context
    assert "Binary Ninja" in meta["note"] and "true-positive" in meta["note"]


def test_carve_sidecar_matches_linux_schema(tmp_path):
    """The sidecar must carry the same keys the Linux carve emits (so one BN loader handles both),
    plus the Windows-only protection/vad_type context."""
    binp = w.carve_region(str(tmp_path), "img.aff4", 1, "p.exe", 0x1000, b"\x90" * 64,
                          "p-rwx-", "anon", "", "", {"r"})
    meta = json.load(open(binp[:-4] + ".json", encoding="utf-8"))
    for k in ("carved_from", "pid", "process", "base_address", "size", "perms", "region",
              "backing_path", "injected", "matched_rules", "arch_hint", "load_as", "note"):
        assert k in meta, f"missing shared sidecar key: {k}"
    assert meta["arch_hint"] in ("x86_64", "x86")
    assert "protection" in meta and "vad_type" in meta          # Windows context added
    assert meta["carved_from"] == "img.aff4"


def test_carve_file_backed_is_not_injected_and_warns(tmp_path):
    """A hit in a file-backed region (carve-any triage) is injected=false and the note points the
    analyst at verifying the backing DLL rather than treating it as malware."""
    binp = w.carve_region(str(tmp_path), "img.aff4", 4, "x.exe", 0x7ff000000000, b"MZ" + b"\x00" * 100,
                          "-r-x--", "file", "Image", "C:\\Windows\\System32\\example.dll", {"SomeRule"})
    meta = json.load(open(binp[:-4] + ".json", encoding="utf-8"))
    assert meta["injected"] is False
    assert meta["vad_type"] == "Image"
    assert "verify" in meta["note"].lower() and "example.dll" in meta["note"]


def test_carve_oversize_region_skipped(tmp_path):
    """Guard: a region larger than CARVE_MAX is not dumped (avoid writing a giant heap)."""
    assert w.carve_region(str(tmp_path), "img", 1, "p", 0x1000, b"\x00" * (w.CARVE_MAX + 1),
                          "p-rwx-", "anon", "", "", {"r"}) is None
    assert list(tmp_path.iterdir()) == []                # nothing written


def test_carve_empty_data_skipped(tmp_path):
    assert w.carve_region(str(tmp_path), "img", 1, "p", 0x1000, b"", "p-rwx-", "anon", "", "", {"r"}) is None
