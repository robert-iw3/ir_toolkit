"""Egress observation sensor (playbooks/linux/monitor_egress.sh).

Outbound is left open during analysis so the C2 sensor can observe where the implant beacons/exfils
(beacons jitter + dwell for hours, so a point-in-time snapshot misses them); the sensor logs egress
over a window, then auto-blackholes. These tests cover the SAFE, side-effect-free logic only — the
external-IP classifier (must not skip real C2, must not log internal noise) and the status/collect
guards. They never invoke --start/--tick/--blackhole (those mutate the host firewall + cron).
"""
import os
import subprocess

from conftest import ROOT

EGRESS = os.path.join(ROOT, "playbooks", "linux", "monitor_egress.sh")


def _classify(ip, mgmt=""):
    """Run the script's _is_external() in isolation → True if it would be logged as egress."""
    snippet = (
        f'source <(sed -n "/^_is_external()/,/^}}/p" "{EGRESS}"); '
        f'MGMT_IPS="{mgmt}"; if _is_external "{ip}"; then echo EXTERNAL; else echo INTERNAL; fi'
    )
    out = subprocess.run(["bash", "-c", snippet], capture_output=True, text=True)
    return out.stdout.strip()


def test_script_exists_and_parses():
    assert os.path.isfile(EGRESS)
    r = subprocess.run(["bash", "-n", EGRESS], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_external_ips_are_logged():
    # real public C2 / exfil destinations MUST be classified external (logged) — no blindspot
    for ip in ("8.8.8.8", "45.32.219.28", "185.220.101.5", "203.0.113.9"):
        assert _classify(ip) == "EXTERNAL", ip


def test_internal_and_loopback_are_skipped():
    # RFC1918 / loopback / link-local are noise, not egress
    for ip in ("10.0.0.5", "192.168.1.10", "172.16.5.5", "172.31.0.1", "127.0.0.1", "169.254.1.1"):
        assert _classify(ip) == "INTERNAL", ip


def test_management_ip_is_excluded():
    # the responder's own management IP must not be logged as a beacon
    assert _classify("203.0.113.5", mgmt="203.0.113.5") == "INTERNAL"
    assert _classify("8.8.8.8", mgmt="203.0.113.5") == "EXTERNAL"   # but real egress still logged


def test_status_on_missing_incident_is_safe_error():
    # querying a non-existent incident must fail cleanly, never mutate anything
    r = subprocess.run(["bash", EGRESS, "--status", "--incident", "NOPE_TEST"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "no egress observation active" in r.stderr.lower()


def test_collect_on_missing_incident_is_safe_error():
    r = subprocess.run(["bash", EGRESS, "--collect", "--incident", "NOPE_TEST"],
                       capture_output=True, text=True)
    assert r.returncode != 0 and "no egress log" in r.stderr.lower()
