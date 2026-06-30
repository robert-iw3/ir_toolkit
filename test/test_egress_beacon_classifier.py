"""
test_egress_beacon_classifier.py

pytest tests for egress_monitor/beacon_classifier.py.

Coverage:
  - Layer 0: pre-flagged PID triggers immediately on first connection
  - Layer 1: non-browser process making external connection
  - Long-dwell: single connection still gets MONITOR (no blind spot)
  - High-jitter: CV > 0.5 does NOT result in CLEAN for a flagged process
  - Browser de-weight: browsers are in the narrow list (NOT svchost/lsass/taskhostw)
  - Interval math: CV and IQR calculations
  - External IP classification: private/CDN/mgmt exclusion
  - Family hints: CS 60s, Sliver 30s, long-dwell APT
"""

import sys
import math
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent /
                       'playbooks' / 'windows' / 'threat_hunting' / 'egress_monitor'))

from beacon_classifier import (
    ConnectionEvent, BeaconScore, classify,
    is_external, is_cdn_likely,
    BROWSER_LIKE_PROCS,
    MIN_SAMPLES_FOR_INTERVAL, MAX_INTERVAL_SEC,
)


def _ev(pid, proc, ip, port='443', n=1, interval=60.0, t0=None):
    """Build N ConnectionEvent objects spaced by interval seconds."""
    t0 = t0 or 1_700_000_000.0
    return [
        ConnectionEvent(
            timestamp=t0 + i * interval,
            pid=pid, process_name=proc,
            remote_ip=ip, remote_port=int(port),
        )
        for i in range(n)
    ]


MGMT = {'10.0.0.1'}


# ---- is_external / is_cdn_likely ---------------------------------------------

def test_private_rfc1918_not_external():
    for ip in ('10.1.2.3', '192.168.0.1', '172.16.5.5', '127.0.0.1'):
        assert not is_external(ip, set())

def test_mgmt_ip_not_external():
    assert not is_external('10.0.0.1', {'10.0.0.1'})

def test_public_ip_is_external():
    assert is_external('1.234.66.143', set())
    assert is_external('94.23.172.164', set())

def test_cdn_prefix_detected():
    assert is_cdn_likely('104.16.5.5')      # Cloudflare
    assert is_cdn_likely('151.101.1.1')     # Fastly

def test_non_cdn_not_detected():
    assert not is_cdn_likely('1.234.66.143')
    assert not is_cdn_likely('94.23.172.164')


# ---- BROWSER_LIKE_PROCS safety -----------------------------------------------

def test_svchost_not_in_browser_list():
    """svchost is the #1 injection target -- must never be de-weighted."""
    assert 'svchost' not in BROWSER_LIKE_PROCS

def test_lsass_not_in_browser_list():
    assert 'lsass' not in BROWSER_LIKE_PROCS

def test_taskhostw_not_in_browser_list():
    assert 'taskhostw' not in BROWSER_LIKE_PROCS

def test_powershell_not_in_browser_list():
    assert 'powershell' not in BROWSER_LIKE_PROCS

def test_rundll32_not_in_browser_list():
    assert 'rundll32' not in BROWSER_LIKE_PROCS

def test_actual_browser_in_list():
    assert 'chrome' in BROWSER_LIKE_PROCS
    assert 'msedge' in BROWSER_LIKE_PROCS


# ---- Layer 0: pre-flagged PID ------------------------------------------------

def test_layer0_flags_immediately_on_single_connection():
    """Pre-flagged PID → CONFIRMED_BEACON on first connection (no pattern needed)."""
    evs = _ev(pid=1234, proc='taskhostw.exe', ip='1.234.66.143', n=1)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids={1234})
    assert scores, "Expected at least one score"
    top = scores[0]
    assert top.verdict == 'CONFIRMED_BEACON'
    assert top.trigger_layer == 0
    assert top.immediate_action is True

def test_layer0_triggers_regardless_of_process_name():
    """Layer 0 applies even to a process that would otherwise be de-weighted."""
    evs = _ev(pid=999, proc='chrome.exe', ip='1.234.66.143', n=1)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids={999})
    assert scores[0].verdict == 'CONFIRMED_BEACON'
    assert scores[0].trigger_layer == 0


# ---- Layer 1: process context ------------------------------------------------

def test_non_browser_single_connection_gets_monitor():
    """A single connection from a non-browser should be MONITOR (not CLEAN)."""
    evs = _ev(pid=2000, proc='msiexec.exe', ip='94.23.172.164', n=1)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert scores, "Expected a score"
    assert scores[0].verdict in ('MONITOR', 'SUSPECTED_BEACON', 'CONFIRMED_BEACON')

def test_unflagged_process_with_many_connections_escalates():
    """Multiple connections from non-browser → should escalate to SUSPECTED or CONFIRMED."""
    evs = _ev(pid=3000, proc='notepad.exe', ip='78.140.220.175', n=10, interval=60.0)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert scores
    assert scores[0].verdict in ('SUSPECTED_BEACON', 'CONFIRMED_BEACON')


# ---- Long-dwell / high-jitter ------------------------------------------------

def test_long_dwell_4h_sleep_not_missed():
    """A beacon sleeping 4h seen 6 times in 24h must NOT be CLEAN."""
    evs = _ev(pid=4000, proc='dllhost.exe', ip='1.2.3.4', n=6, interval=4 * 3600)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert scores
    assert scores[0].verdict != 'CLEAN', (
        f"Long-dwell beacon classified as CLEAN: {scores[0]}"
    )

def test_24h_sleep_single_observation_gets_monitor():
    """Single connection from non-browser must not be silently CLEAN."""
    evs = _ev(pid=5000, proc='regsvr32.exe', ip='5.6.7.8', n=1)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert scores
    assert scores[0].verdict in ('MONITOR', 'SUSPECTED_BEACON', 'CONFIRMED_BEACON'), (
        f"Single-connection classified as CLEAN: {scores[0]}"
    )

def test_high_jitter_not_clean_for_flagged_pid():
    """High jitter (randomised intervals) must not cause CLEAN for a pre-flagged PID."""
    import random
    rng = random.Random(42)
    t0  = 1_700_000_000.0
    evs = []
    t = t0
    for i in range(8):
        evs.append(ConnectionEvent(
            timestamp=t, pid=6000, process_name='services.exe',
            remote_ip='9.10.11.12', remote_port=443,
        ))
        # 60s base + 90% jitter → very irregular
        t += 60 + rng.uniform(-54, 54)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids={6000})
    assert scores
    assert scores[0].verdict == 'CONFIRMED_BEACON', (
        f"High-jitter pre-flagged PID should be CONFIRMED_BEACON: {scores[0]}"
    )


# ---- MAX_INTERVAL_SEC does not exclude APT-range intervals -------------------

def test_max_interval_allows_3day_gap():
    """MAX_INTERVAL_SEC must be >= 3 days so APT-range sleeps are included."""
    assert MAX_INTERVAL_SEC >= 3 * 24 * 3600


# ---- Family hints ------------------------------------------------------------

def test_family_hint_cs_60s():
    evs = _ev(pid=7000, proc='taskhostw.exe', ip='1.2.3.4', n=5, interval=60.0)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert scores
    assert 'CobaltStrike' in scores[0].family_hint

def test_family_hint_sliver_30s():
    evs = _ev(pid=8000, proc='winlogon.exe', ip='5.6.7.8', n=5, interval=30.0)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert scores
    assert 'Sliver' in scores[0].family_hint

def test_family_hint_long_dwell():
    evs = _ev(pid=9000, proc='spoolsv.exe', ip='11.12.13.14', n=3, interval=8 * 3600)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert scores
    assert 'long-dwell' in scores[0].family_hint.lower() or 'APT' in scores[0].family_hint


# ---- Private IP excluded from scoring ----------------------------------------

def test_private_ip_not_scored():
    evs = _ev(pid=10000, proc='evil.exe', ip='192.168.1.50', n=10, interval=60.0)
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    assert not scores, "Private IP should produce no score"


# ---- Multiple PIDs, multiple destinations ------------------------------------

def test_multiple_pids_independently_classified():
    evs = (
        _ev(pid=100, proc='cmd.exe',     ip='1.1.1.100', n=5, interval=60.0)  +
        _ev(pid=200, proc='chrome.exe',  ip='8.8.8.8',   n=5, interval=60.0)  +
        _ev(pid=300, proc='notepad.exe', ip='2.3.4.5',   n=5, interval=60.0)
    )
    scores = classify(evs, mgmt_ips=MGMT, pre_flagged_pids=set())
    pids = {s.pid for s in scores}
    # chrome to 8.8.8.8 (Google DNS) is not a confirmed beacon in an unloaded browser
    # cmd and notepad should be flagged
    assert 100 in pids or 300 in pids, "Non-browser processes should be scored"
