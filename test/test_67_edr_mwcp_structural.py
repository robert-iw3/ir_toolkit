"""Live-host static-scan mwcp_parsers integration (edr_hunt.check_mwcp_structural_configs).

The same family-structural catalog memory_enrich.py runs against carved memory regions,
run here against a LIVE on-disk binary (/proc/<pid>/exe) -- but only for PIDs edr_hunt
already has independent reason to distrust (_pid_exe_trust: deleted from disk, memfd/
fileless, or running from a world-writable path), never every process unconditionally.
"""
import os
import sys
from unittest.mock import patch

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import edr_hunt as h  # noqa: E402

# A structurally valid Telegram Bot API token (10-digit numeric ID : 35-char secret) plus
# the required api.telegram.org endpoint -- both are protocol requirements the family
# parser checks for, not a name/string match.
_TELEGRAM_TP_BYTES = (
    b"junk" * 20 + b"https://api.telegram.org/bot1234567890:"
    + b"A" * 35 + b"/sendMessage" + b"junk" * 20
)


def test_untrusted_pid_with_structural_indicator_produces_on_disk_finding():
    with patch.object(h, "proc_pids", return_value=["999"]):
        with patch.object(h, "_pid_exe_trust", return_value="binary deleted from disk while running"):
            with patch.object(h, "exe_of", return_value="/tmp/evil (deleted)"):
                with patch.object(h, "comm", return_value="evil"):
                    with patch.object(h, "read_file", return_value=_TELEGRAM_TP_BYTES):
                        h.FINDINGS.clear()
                        h.check_mwcp_structural_configs()
    assert len(h.FINDINGS) == 1
    f = h.FINDINGS[0]
    assert "on-disk" in f["Type"]                 # never mislabelled as a memory-carve result
    assert "999" in f["Target"] and "evil" in f["Target"]


def test_untrusted_pid_with_no_indicator_produces_nothing():
    with patch.object(h, "proc_pids", return_value=["999"]):
        with patch.object(h, "_pid_exe_trust", return_value="binary deleted from disk while running"):
            with patch.object(h, "exe_of", return_value="/tmp/evil (deleted)"):
                with patch.object(h, "comm", return_value="evil"):
                    with patch.object(h, "read_file", return_value=b"\x7fELF" + b"\x00" * 200):
                        h.FINDINGS.clear()
                        h.check_mwcp_structural_configs()
    assert h.FINDINGS == []


def test_trusted_pid_is_never_scanned_even_with_an_indicator_present():
    # _pid_exe_trust returning None means edr_hunt has NO independent reason to distrust this
    # PID -- it must be skipped entirely, regardless of what its bytes contain.
    with patch.object(h, "proc_pids", return_value=["1"]):
        with patch.object(h, "_pid_exe_trust", return_value=None):
            with patch.object(h, "read_file", return_value=_TELEGRAM_TP_BYTES) as rf:
                h.FINDINGS.clear()
                h.check_mwcp_structural_configs()
    assert h.FINDINGS == []
    rf.assert_not_called()                          # never even reads bytes for a trusted PID


def test_duplicate_backing_binary_scanned_once():
    # two PIDs sharing the same clean exe path (e.g. a forked worker) shouldn't double-count
    calls = []

    def _rf(path, binary=False, limit=None):
        calls.append(path)
        return _TELEGRAM_TP_BYTES

    with patch.object(h, "proc_pids", return_value=["1", "2"]):
        with patch.object(h, "_pid_exe_trust", return_value="binary under a world-writable path"):
            with patch.object(h, "exe_of", return_value="/tmp/worker"):
                with patch.object(h, "comm", return_value="worker"):
                    with patch.object(h, "read_file", side_effect=_rf):
                        h.FINDINGS.clear()
                        h.check_mwcp_structural_configs()
    assert len(calls) == 1                           # second PID's identical exe path skipped
    assert len(h.FINDINGS) == 1


def test_mwcp_unavailable_degrades_to_noop():
    with patch.object(h, "_mwcp", None):
        with patch.object(h, "proc_pids", return_value=["999"]):
            h.FINDINGS.clear()
            h.check_mwcp_structural_configs()        # must not raise
    assert h.FINDINGS == []


def test_check_wired_into_main_checks_list():
    import inspect
    src = inspect.getsource(h.main)
    assert "check_mwcp_structural_configs" in src
