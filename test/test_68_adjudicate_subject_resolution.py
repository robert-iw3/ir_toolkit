"""adjudicate.py's resolve_subject()/enrich() -- prefers a collector-supplied
SubjectPath over the generic PID -> /proc/pid/exe guess.

A collector that already knows the SPECIFIC file its finding is about (e.g.
edr_hunt.py's GOT/PLT check: the library a GOT slot resolved into, not the owning
process's own executable) should have package-ownership/hash verification run
against THAT file, not a generic PID fallback -- otherwise the one piece of
independent evidence that can close "genuine alternate definer vs. a swapped-in
malicious library exporting the same symbol" without going back to the host never
actually checks the right file.
"""
import os
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import adjudicate as adj  # noqa: E402


def test_resolve_subject_prefers_explicit_subject_path_over_pid_exe(tmp_path):
    explicit = tmp_path / "libtarget.so.1"
    explicit.write_bytes(b"\x7fELF")
    finding = {
        "Target": f"PID: {os.getpid()} (self)",
        "Details": "irrelevant",
        "SubjectPath": str(explicit),
    }
    path, pid = adj.resolve_subject(finding)
    assert path == str(explicit)          # NOT this test process's own exe
    assert pid == str(os.getpid())         # pid is still resolved independently


def test_resolve_subject_falls_back_to_pid_exe_when_no_explicit_path():
    finding = {"Target": f"PID: {os.getpid()} (self)", "Details": ""}
    path, pid = adj.resolve_subject(finding)
    assert pid == str(os.getpid())
    assert path and os.path.lexists(path)  # falls back to /proc/<pid>/exe as before


def test_resolve_subject_ignores_explicit_path_that_no_longer_exists(tmp_path):
    missing = tmp_path / "gone.so"
    finding = {
        "Target": f"PID: {os.getpid()} (self)",
        "Details": "",
        "SubjectPath": str(missing),
    }
    path, pid = adj.resolve_subject(finding)
    assert path != str(missing)            # doesn't trust a path that vanished
    assert pid == str(os.getpid())


def test_enrich_runs_package_verification_against_explicit_subject_path(tmp_path):
    explicit = tmp_path / "notpackaged.so"
    explicit.write_bytes(b"\x7fELF")
    finding = {
        "Type": "GOT Entry Relocation (verify)",
        "Target": f"PID: {os.getpid()} (self)",
        "Details": "irrelevant",
        "MITRE": "T1574.001",
        "SubjectPath": str(explicit),
    }
    e = adj.enrich(finding)
    assert e["SubjectPath"] == str(explicit)
    assert e["FileExists"] is True
