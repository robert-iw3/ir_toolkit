"""Tests for check_authorized_keys (behavioral SSH key signals) and
check_pam_modules in edr_hunt.py."""
import os
import sys
import textwrap
import time
from unittest.mock import patch, MagicMock

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import edr_hunt as h  # noqa: E402


def _reset():
    h.FINDINGS.clear()


_BLOB = "A" * 48          # valid-looking base64 key blob (>=40 chars)
_BLOB2 = "B" * 48


def _run_authorized_keys(passwd, ak_map, stat_obj, islink=False, sshd=None):
    """Drive check_authorized_keys with mocked passwd / per-path key files."""
    def rf(path, *a, **k):
        if path == "/etc/passwd":
            return passwd
        if path == "/etc/ssh/sshd_config":
            return sshd
        return ak_map.get(path)
    with patch.object(h, "read_file", side_effect=rf):
        with patch("os.path.islink", return_value=islink):
            with patch("os.stat", return_value=stat_obj):
                h.check_authorized_keys()


# ---------------------------------------------------------------------------
# check_authorized_keys - behavioral signals
# ---------------------------------------------------------------------------

def test_world_writable_authorized_keys_is_critical():
    _reset()
    passwd = "analyst:x:1001:1001::/home/analyst:/bin/bash\n"
    ak = "/home/analyst/.ssh/authorized_keys"
    st = MagicMock(st_mode=0o100666, st_uid=1001, st_mtime=time.time())  # world-writable
    _run_authorized_keys(passwd, {ak: f"ssh-rsa {_BLOB} u@h\n"}, st)
    assert any(f["Type"] == "SSH Key File World-Writable" and f["Severity"] == "Critical"
               for f in h.FINDINGS)


def test_owner_mismatch_is_high():
    _reset()
    passwd = "analyst:x:1001:1001::/home/analyst:/bin/bash\n"
    ak = "/home/analyst/.ssh/authorized_keys"
    st = MagicMock(st_mode=0o100600, st_uid=0, st_mtime=time.time())  # owned by root, not analyst
    _run_authorized_keys(passwd, {ak: f"ssh-rsa {_BLOB} u@h\n"}, st)
    assert any(f["Type"] == "SSH Key File Owner Mismatch" and f["Severity"] == "High"
               for f in h.FINDINGS)


def test_forced_command_backdoor_flagged():
    _reset()
    passwd = "analyst:x:1001:1001::/home/analyst:/bin/bash\n"
    ak = "/home/analyst/.ssh/authorized_keys"
    st = MagicMock(st_mode=0o100600, st_uid=1001, st_mtime=time.time())
    key = f'command="/bin/bash -i" ssh-rsa {_BLOB} attacker\n'
    _run_authorized_keys(passwd, {ak: key}, st)
    assert any(f["Type"] == "SSH Forced-Command Backdoor" and f["Severity"] == "High"
               for f in h.FINDINGS)


def test_forced_command_benign_not_flagged():
    """A legitimate restricted forced command (git-shell) must NOT be flagged."""
    _reset()
    passwd = "git:x:1001:1001::/home/git:/bin/bash\n"
    ak = "/home/git/.ssh/authorized_keys"
    st = MagicMock(st_mode=0o100600, st_uid=1001, st_mtime=time.time())
    key = f'command="/usr/bin/git-shell -c \\"$SSH_ORIGINAL_COMMAND\\"" ssh-rsa {_BLOB} git\n'
    _run_authorized_keys(passwd, {ak: key}, st)
    assert not [f for f in h.FINDINGS if f["Type"] == "SSH Forced-Command Backdoor"]


def test_key_reused_across_accounts_flagged():
    _reset()
    passwd = ("analyst:x:1001:1001::/home/analyst:/bin/bash\n"
              "deploy:x:1002:1002::/home/deploy:/bin/bash\n")
    same = f"ssh-rsa {_BLOB} shared@key\n"
    ak_map = {
        "/home/analyst/.ssh/authorized_keys": same,
        "/home/deploy/.ssh/authorized_keys": same,
    }
    st = MagicMock(st_mode=0o100600, st_uid=1001, st_mtime=time.time())
    _run_authorized_keys(passwd, ak_map, st)
    assert any(f["Type"] == "SSH Key Reused Across Accounts" and f["Severity"] == "High"
               for f in h.FINDINGS)


def test_many_keys_flagged():
    _reset()
    passwd = "analyst:x:1001:1001::/home/analyst:/bin/bash\n"
    ak = "/home/analyst/.ssh/authorized_keys"
    body = "\n".join(f"ssh-rsa {chr(65 + i)}{_BLOB} user{i}@host" for i in range(7)) + "\n"
    st = MagicMock(st_mode=0o100600, st_uid=1001, st_mtime=time.time())
    _run_authorized_keys(passwd, {ak: body}, st)
    assert any(f["Type"] == "Many SSH Authorized Keys" for f in h.FINDINGS)


def test_nonstandard_authorizedkeysfile_flagged():
    _reset()
    passwd = "analyst:x:1001:1001::/home/analyst:/bin/bash\n"
    st = MagicMock(st_mode=0o100600, st_uid=1001, st_mtime=time.time())
    sshd = "AuthorizedKeysFile /etc/ssh/keys/%u\n"
    _run_authorized_keys(passwd, {}, st, sshd=sshd)
    assert any(f["Type"] == "Non-standard AuthorizedKeysFile" for f in h.FINDINGS)


def test_nologin_accounts_skipped():
    _reset()
    passwd = "daemon:x:2:2:Daemon:/:/usr/sbin/nologin\n"
    reads = []

    def rf(path, *a, **k):
        reads.append(path)
        if path == "/etc/passwd":
            return passwd
        return None
    with patch.object(h, "read_file", side_effect=rf):
        h.check_authorized_keys()
    assert not [r for r in reads if "authorized_keys" in str(r)]
    assert h.FINDINGS == []


# ---------------------------------------------------------------------------
# check_pam_modules
# ---------------------------------------------------------------------------

def test_pam_module_from_tmp_is_critical(tmp_path):
    """PAM module loaded from /tmp must be flagged as Critical."""
    _reset()
    with patch("os.path.isdir") as mock_id:
        mock_id.side_effect = lambda p: "pam.d" in str(p)
        with patch("os.listdir", return_value=["sshd"]):
            with patch.object(h, "read_file", return_value="auth required /tmp/evil.so\n"):
                h.check_pam_modules()
    assert any(f["Severity"] == "Critical" and "PAM Module" in f["Type"] for f in h.FINDINGS)


def test_pam_module_outside_trusted_path_is_high(tmp_path):
    """PAM module from /opt (outside trusted dirs) should be High."""
    _reset()
    with patch("os.path.isdir") as mock_id:
        mock_id.side_effect = lambda p: "pam.d" in str(p)
        with patch("os.listdir", return_value=["common-auth"]):
            with patch.object(h, "read_file", return_value="auth required /opt/vendor/pam_custom.so\n"):
                h.check_pam_modules()
    types = {f["Type"] for f in h.FINDINGS}
    sev = {f["Severity"] for f in h.FINDINGS}
    assert "PAM Module Tampering" in types
    assert "High" in sev


def test_pam_module_trusted_path_not_flagged(tmp_path):
    """PAM module from /lib/x86_64-linux-gnu/security/ is trusted and should not be flagged."""
    _reset()
    trusted = "/lib/x86_64-linux-gnu/security/pam_unix.so"
    with patch("os.path.isdir") as mock_id:
        mock_id.side_effect = lambda p: "pam.d" in str(p)
        with patch("os.listdir", return_value=["common-auth"]):
            with patch.object(h, "read_file", return_value=f"auth required {trusted}\n"):
                with patch("os.path.getmtime", return_value=0.0):
                    h.check_pam_modules()
    assert not [f for f in h.FINDINGS if f["Type"] == "PAM Module Tampering"]


def test_pam_module_recently_modified_trusted_is_medium(tmp_path):
    """Recently modified trusted PAM module should produce a Medium finding."""
    _reset()
    trusted = "/lib/x86_64-linux-gnu/security/pam_unix.so"
    recent_mtime = time.time() - (5 * 86400)
    with patch("os.path.isdir") as mock_id:
        mock_id.side_effect = lambda p: "pam.d" in str(p)
        with patch("os.listdir", return_value=["common-auth"]):
            with patch.object(h, "read_file", return_value=f"auth required {trusted}\n"):
                with patch("os.path.getmtime", return_value=recent_mtime):
                    h.check_pam_modules()
    medium = [f for f in h.FINDINGS if "Recently Modified PAM Module" in f.get("Type", "")]
    assert medium and medium[0]["Severity"] == "Medium"


def test_pam_comment_lines_skipped():
    """Comment lines in PAM config must not be parsed as module references."""
    _reset()
    pam_content = textwrap.dedent("""\
        # This is a comment
        auth required /lib/x86_64-linux-gnu/security/pam_unix.so
    """)
    with patch("os.path.isdir") as mock_id:
        mock_id.side_effect = lambda p: "pam.d" in str(p)
        with patch("os.listdir", return_value=["sshd"]):
            with patch.object(h, "read_file", return_value=pam_content):
                with patch("os.path.getmtime", return_value=0.0):
                    h.check_pam_modules()
    assert not [f for f in h.FINDINGS if f["Severity"] in ("Critical", "High")]
