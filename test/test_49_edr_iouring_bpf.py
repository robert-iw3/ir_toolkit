"""Live-host checks for syscall-less / eBPF anti-EDR surfaces:
  check_io_uring   - io_uring does I/O without the syscalls EDR hooks; flag implanted users.
  check_bpf_objects - implant processes holding eBPF fds + pinned objects in bpffs.
Only implant-looking holders escalate (io_uring/eBPF have many legitimate users).
"""
import sys
from unittest.mock import patch

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import edr_hunt as h  # noqa: E402


def _run(check, fds, exes, walk=None):
    h.FINDINGS.clear()
    with patch.object(h, "proc_pids", return_value=list(fds)), \
         patch.object(h, "_fd_targets", side_effect=lambda p: fds.get(p, [])), \
         patch.object(h, "exe_of", side_effect=lambda p: exes.get(p)), \
         patch.object(h, "comm", side_effect=lambda p: "proc"), \
         patch("os.walk", return_value=iter(walk or [])):
        check()
    return h.FINDINGS


IOURING = "anon_inode:[io_uring]"
BPFPROG = "anon_inode:bpf-prog"


def test_io_uring_from_implant_dir_is_high():
    f = _run(h.check_io_uring, {"100": [IOURING, "socket:[123]"]}, {"100": "/tmp/.x/impl"})
    assert f and f[0]["Severity"] == "High" and f[0]["Type"] == "io_uring Anti-EDR I/O"
    assert "T1106" in f[0]["MITRE"]


def test_io_uring_from_deleted_exe_is_high():
    f = _run(h.check_io_uring, {"101": [IOURING]}, {"101": "/usr/bin/svc (deleted)"})
    assert f and f[0]["Severity"] == "High"


def test_io_uring_legit_process_surfaced_at_info():
    # legit io_uring users are surfaced (not blinded) but only at Info - it is the sole
    # visibility into the io_uring anti-EDR surface, so downgrade rather than suppress.
    f = _run(h.check_io_uring, {"102": [IOURING]}, {"102": "/usr/sbin/nginx"})
    assert not [x for x in f if x["Severity"] == "High"]
    assert any(x["Type"] == "io_uring In Use (verify)" and x["Severity"] == "Info" for x in f)


def test_no_io_uring_is_silent():
    f = _run(h.check_io_uring, {"103": ["socket:[9]", "/etc/passwd"]}, {"103": "/tmp/x"})
    assert f == []


def test_bpf_fd_from_implant_is_high():
    f = _run(h.check_bpf_objects, {"200": [BPFPROG]}, {"200": "/dev/shm/agent"})
    hits = [x for x in f if x["Type"] == "eBPF Object Held By Implant"]
    assert hits and hits[0]["Severity"] == "High"


def test_bpf_fd_legit_not_flagged():
    f = _run(h.check_bpf_objects, {"201": [BPFPROG]}, {"201": "/usr/lib/systemd/systemd"})
    assert not [x for x in f if x["Type"] == "eBPF Object Held By Implant"]


def test_pinned_bpf_objects_surfaced_medium():
    f = _run(h.check_bpf_objects, {}, {},
             walk=[("/sys/fs/bpf", [], ["evil_prog"])])
    hits = [x for x in f if x["Type"] == "Pinned eBPF Objects (verify)"]
    assert hits and hits[0]["Severity"] == "Medium"


def test_empty_bpffs_no_pinned_finding():
    f = _run(h.check_bpf_objects, {}, {}, walk=[])
    assert not [x for x in f if x["Type"] == "Pinned eBPF Objects (verify)"]
