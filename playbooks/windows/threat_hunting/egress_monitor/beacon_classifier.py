"""
beacon_classifier.py -- Multi-layer C2 beacon detection.

DESIGN PHILOSOPHY:
  Beacons vary enormously in sleep time (2s to 24h+), jitter (0% to 99%),
  and protocol. Relying on periodicity alone creates blind spots for:
    - Long-dwell/low-and-slow campaigns: 4h/8h/24h sleep, rarely seen in a
      short collection window
    - High-jitter configs: CS operators routinely set 50-99% jitter to
      defeat statistical detection -- CV-based thresholds will miss them
    - Protocol variation: DNS/HTTPS/SMB beacons don't look like HTTP polling

  The primary detection signal is PROCESS CONTEXT, not traffic timing:
    - A process with an anonymous exec VAD making an external connection
      is suspicious on the FIRST event, before any pattern is established
    - A non-browser process making HTTPS connections to IPs (not CDN domains)
      is suspicious even with a single observed connection

  Periodicity is a SECONDARY signal that upgrades confidence once enough
  samples exist, but NEVER blocks initial investigation.

  Classification layers:
    Layer 0: Process pre-flagged (anonymous exec VAD, enrichment flag)
             → TRIGGER on first external connection, no timing needed
    Layer 1: ANY external connection from non-browser, non-system process
             → LOG and track; score other indicators
    Layer 2: Pattern analysis over accumulated connections
             → Periodicity, size consistency, jitter profile
    Layer 3: Long-dwell monitoring (24-72h window)
             → Even 1-2 connections in 24h from a flagged process is significant

Covers: CobaltStrike, Sliver, Havoc, BruteRatel, Merlin, Metasploit, AsyncRAT,
        any custom beacon, and long-dwell APT implants.
"""

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# ---- Tunable thresholds -------------------------------------------------------

# Minimum connection samples to run interval analysis.
# Set low (2) so long-dwell beacons seen twice over 24h still get scored.
MIN_SAMPLES_FOR_INTERVAL = 2

# Max interval to include in periodicity analysis.
# Do NOT cap aggressively -- 24h sleep is still a beacon.
# Only exclude implausibly long gaps (> 3 days).
MAX_INTERVAL_SEC = 3 * 24 * 3600   # 3 days

# Minimum interval to include (exclude sub-second browser connection bursts)
MIN_INTERVAL_SEC = 1

# Coefficient of variation (std/mean) threshold for LOW-jitter classification.
# High-jitter (>0.35) is NOT excluded -- it just gets a lower confidence boost.
# A CV of 0.99 (99% jitter) is still possibly a beacon; we log it but don't block.
CV_LOW_JITTER  = 0.15   # very regular → strong beacon signal
CV_MED_JITTER  = 0.50   # somewhat regular → moderate signal
# CV > 0.50: irregular timing, but context still matters

# Ports that are unusual for browser-like activity on non-browser processes
BEACON_PORT_HINTS = {80, 443, 8080, 8443, 4443, 4444, 8888, 8889, 53, 8000, 8001}

# UI browsers: the only processes where external HTTP/S connections are routine
# enough to warrant de-weighting periodic-connection scoring.
#
# Critical omissions (INTENTIONAL — never add these):
#   svchost, lsass, taskhostw, rundll32, regsvr32, dllhost, wscript, cscript,
#   msiexec, services, winlogon — top injection targets; any external connection
#   from these is MORE suspicious, not less.
#
#   powershell, pwsh, cmd, wmic, mshta, explorer — shells and loaders;
#   connecting externally is inherently suspicious for all of them.
#
# UA spoofing is invisible at this layer — we read the process name from
# netstat, not the HTTP User-Agent header. Malware injected into a legitimate
# Windows process and sending spoofed UA strings is caught by Layer 0 (VAD
# flag), regardless of what UA it claims in its HTTP traffic.
#
# If a process IS in this list but carries a pre-flagged VAD, Layer 0 overrides.
BROWSER_LIKE_PROCS = {
    'chrome', 'msedge', 'firefox', 'iexplore', 'brave', 'msedgewebview2',
    # Deliberately narrow — only unambiguous UI browsers
}

# Private / non-routable prefixes
_PRIVATE_PREFIXES = (
    '10.', '172.16.', '172.17.', '172.18.', '172.19.',
    '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
    '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
    '172.30.', '172.31.',
    '192.168.', '127.', '169.254.',
    '::1', 'fe80:', '0.0.0.0', '::',
)

# Known-benign IP ranges. Strong negative signal (-0.40 on confidence).
# NOT a hard exclude: malware can domain-front through CDNs.
# Without a pre-flagged PID, connections to these ranges alone cannot
# confirm a beacon -- analyst review required before acting on them.
_CDN_PREFIXES = (
    # Microsoft 365 / Azure / Windows Update / Defender cloud
    '13.107.', '13.64.', '13.65.', '13.66.', '13.67.', '13.89.',
    '20.', '40.', '52.',
    # Google
    '142.250.', '172.217.', '216.58.', '64.233.', '74.125.', '108.177.',
    # Cloudflare
    '104.16.', '104.17.', '104.18.', '104.19.',
    '162.159.', '172.64.', '172.65.',
    # Fastly (VS Code, npm, GitHub)
    '151.101.',
    # Akamai
    '23.1.', '23.32.', '23.49.', '23.215.',
    # Adobe Creative Cloud
    '63.140.', '66.117.',
    # AWS (broad -- includes Anthropic API, AWS services)
    '3.', '18.', '34.',
)

# Known telemetry / update processes that make legitimate periodic external
# connections. Without an enrichment flag confirming suspicious VAD/injection,
# these should NOT receive CONFIRMED_BEACON -- only MONITOR or SUSPECTED.
# Layer 0 (pre-flagged PID from enrichment) overrides this entirely.
_TELEMETRY_PROCS = {
    'msmpseng', 'msmpeng', 'mpdefendercoreservice', 'microsoftsecurityapp',
    'mpsecuritycenter', 'securityhealthservice', 'securityhealthsystray',
    'microsoftedgeupdate', 'edgeupdate', 'wuauclt', 'usoclient',
    'searchhost', 'searchindexer', 'wudfhost', 'diaghost',
    'acrotray', 'adobeupdateservice', 'adobearmservice', 'adobecollabosyncs',
    'adobenotificationclient', 'ccxprocess', 'ccxmanager', 'creativecloud',
    # Developer tools making heartbeat connections
    'code', 'cursor', 'vsls-agent',
    # iCloud
    'iclouddrive', 'icloudservices',
}


@dataclass
class ConnectionEvent:
    timestamp: float        # epoch seconds (float for sub-second precision)
    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    bytes_sent: int = 0
    bytes_recv: int = 0
    flags: set = field(default_factory=set)  # 'flagged_vad', 'enrichment_flag', etc.


@dataclass
class BeaconScore:
    pid: int
    process_name: str
    remote_ip: str
    remote_port: int
    verdict: str             # CONFIRMED_BEACON | SUSPECTED_BEACON | MONITOR | CLEAN
    confidence: float        # 0.0 – 1.0
    trigger_layer: int       # 0=context-flag, 1=first-connection, 2=pattern, 3=long-dwell
    sample_count: int
    median_interval_sec: float
    jitter_cv: float
    family_hint: str
    indicators: list[str] = field(default_factory=list)
    first_seen: float = 0.0
    last_seen: float = 0.0
    # Trigger carve + mwcp pipeline on this connection
    immediate_action: bool = False
    # Blackhole is ALWAYS gated on mwcp finding real config (mutex, C2, CS config).
    # immediate_action fires the carve; the daemon's blackhole logic checks carve results.
    # This field documents the intent -- the daemon MUST NOT blackhole on score alone.
    blackhole_requires_mwcp_confirmation: bool = True


def is_external(ip: str, mgmt_ips: set) -> bool:
    if not ip or ip in mgmt_ips:
        return False
    if any(ip.startswith(p) for p in _PRIVATE_PREFIXES):
        return False
    return True


def is_cdn_likely(ip: str) -> bool:
    return any(ip.startswith(p) for p in _CDN_PREFIXES)


def _coeff_variation(values: list) -> float:
    if len(values) < 2:
        return 999.0   # undefined = very irregular
    try:
        mean = statistics.mean(values)
        if mean <= 0:
            return 999.0
        return statistics.stdev(values) / mean
    except statistics.StatisticsError:
        return 999.0


def _iqr_variation(values: list) -> float:
    """Interquartile range / median -- robust to outliers, better for high-jitter beacons."""
    if len(values) < 4:
        return _coeff_variation(values)
    s = sorted(values)
    n = len(s)
    q1 = s[n // 4]
    q3 = s[3 * n // 4]
    med = statistics.median(s)
    if med <= 0:
        return 999.0
    return (q3 - q1) / med


def classify(events: list, mgmt_ips: set,
             pre_flagged_pids: set = None) -> list:
    """
    Classify connection events into beacon verdicts.

    pre_flagged_pids: PIDs already flagged by memory enrichment (anonymous exec VAD,
                      ETW-TI absence, etc.). ANY external connection from these
                      triggers immediate investigation (Layer 0).
    """
    if pre_flagged_pids is None:
        pre_flagged_pids = set()

    # Group by (pid, remote_ip, remote_port)
    groups = defaultdict(list)
    for ev in events:
        if not is_external(ev.remote_ip, mgmt_ips):
            continue
        groups[(ev.pid, ev.remote_ip, ev.remote_port)].append(ev)

    scores = []
    for (pid, ip, port), evts in groups.items():
        evts_s = sorted(evts, key=lambda e: e.timestamp)
        proc_name = evts_s[-1].process_name.lower().replace('.exe', '')
        n = len(evts_s)

        indicators = []
        confidence = 0.0
        trigger_layer = 3
        immediate_action = False
        family_hint = 'Generic'

        # ------------------------------------------------------------------
        # Layer 0: Process pre-flagged by enrichment (highest priority)
        # ANY external connection from these PIDs → immediate carve
        # ------------------------------------------------------------------
        if pid in pre_flagged_pids or 'flagged_vad' in (evts_s[0].flags or set()):
            confidence += 0.70
            trigger_layer = 0
            immediate_action = True
            indicators.append('process pre-flagged (anonymous exec VAD / enrichment flag)')

        # ------------------------------------------------------------------
        # Layer 1: Process context
        # ------------------------------------------------------------------
        is_browser_like   = proc_name in BROWSER_LIKE_PROCS
        is_telemetry_proc = proc_name in _TELEMETRY_PROCS

        if not is_browser_like and not is_telemetry_proc:
            confidence += 0.20
            trigger_layer = min(trigger_layer, 1)
            indicators.append(f'non-browser/non-telemetry process {proc_name!r} making external connection')
        elif is_telemetry_proc:
            # Telemetry processes legitimately connect externally. BUT they are also
            # injection targets. Without a pre-flagged VAD, don't auto-confirm.
            # Log for analyst review; do not blackhole on score alone.
            indicators.append(f'{proc_name!r} is a known telemetry/update process '
                              f'(requires VAD flag to confirm -- injection vector possible)')

        # NOTE: NO CDN IP de-weighting.
        # Threat actors route C2 through Cloudflare, AWS CloudFront, Azure CDN,
        # and OneDrive (domain fronting / redirectors). An IP in a CDN range is
        # NOT evidence of benign traffic -- it is a common evasion technique.
        # The destination IP alone cannot distinguish legit vs C2 CDN traffic.
        # Verdict is driven by process anomaly (VAD flag) + mwcp config evidence,
        # NOT by which CDN the traffic happens to be routed through.
        if is_cdn_likely(ip):
            indicators.append(f'{ip} routes through CDN/cloud range (common domain-fronting path)')

        # Port hint
        if port in BEACON_PORT_HINTS:
            confidence += 0.10
            indicators.append(f'port {port} is common beacon port')

        # ------------------------------------------------------------------
        # Layer 2: Pattern analysis (only if enough samples exist)
        # Long-dwell beacons get only 2-3 samples in 24h -- that's fine.
        # ------------------------------------------------------------------
        intervals = []
        for i in range(1, n):
            dt = evts_s[i].timestamp - evts_s[i-1].timestamp
            if MIN_INTERVAL_SEC <= dt <= MAX_INTERVAL_SEC:
                intervals.append(dt)

        median_iv = 0.0
        cv = 999.0

        if len(intervals) >= MIN_SAMPLES_FOR_INTERVAL:
            median_iv = statistics.median(intervals)
            cv = _coeff_variation(intervals)
            iqrv = _iqr_variation(intervals)

            # Use the smaller of CV and IQR/median for robustness
            effective_variation = min(cv, iqrv)

            if effective_variation <= CV_LOW_JITTER:
                confidence += 0.35
                trigger_layer = min(trigger_layer, 2)
                indicators.append(f'very regular interval (CV={cv:.2f}, IQR/med={iqrv:.2f}, '
                                   f'median={median_iv:.0f}s)')
            elif effective_variation <= CV_MED_JITTER:
                confidence += 0.20
                trigger_layer = min(trigger_layer, 2)
                indicators.append(f'moderately regular interval (CV={cv:.2f}, median={median_iv:.0f}s)')
            else:
                # High jitter -- don't penalize; note it and check sample count
                indicators.append(f'irregular interval (CV={cv:.2f}, median={median_iv:.0f}s) '
                                   f'-- high jitter config or insufficient samples')

            # Repetition count as an independent signal
            if n >= 10:
                confidence += 0.20
                indicators.append(f'{n} check-ins observed')
            elif n >= 5:
                confidence += 0.10
                indicators.append(f'{n} check-ins observed')
            elif n >= 2:
                confidence += 0.05
                indicators.append(f'{n} check-ins observed (long-dwell possible)')

        # ------------------------------------------------------------------
        # Layer 3: Long-dwell single-observation (most easily missed)
        # Even a SINGLE connection from a non-browser process is worth logging.
        # Confidence stays low but it gets MONITOR verdict so analyst sees it.
        # ------------------------------------------------------------------
        if n == 1 and not is_browser_like:
            indicators.append('single observed connection (may be first beacon of long-dwell campaign)')

        # ------------------------------------------------------------------
        # Family hint based on interval
        # ------------------------------------------------------------------
        if median_iv > 0:
            if 55 <= median_iv <= 65:
                family_hint = 'CobaltStrike (60s default)'
                confidence += 0.10
                indicators.append('interval matches CS 60s default sleep')
            elif 25 <= median_iv <= 35:
                family_hint = 'Sliver (30s default)'
                confidence += 0.08
                indicators.append('interval matches Sliver 30s default')
            elif 1 <= median_iv <= 5:
                family_hint = 'Havoc/aggressive'
                indicators.append('very short interval (<5s) -- Havoc or aggressive CS config')
            elif 3 <= median_iv <= 7:
                family_hint = 'Meterpreter (~5s)'
                indicators.append('interval matches Meterpreter default')
            elif median_iv > 3600:
                family_hint = 'Long-dwell APT'
                indicators.append(f'very long sleep ({median_iv/3600:.1f}h) -- long-dwell implant')

        # ------------------------------------------------------------------
        # Verdict
        # Carve (immediate_action) fires on CONFIRMED or pre-flagged PID.
        # BLACKHOLE is always gated on mwcp finding real malware config --
        # this is enforced in egress_monitor.py, not here.
        # ------------------------------------------------------------------
        confidence = max(0.0, min(confidence, 1.0))

        # Telemetry/update processes can only reach SUSPECTED at most without
        # a pre-flagged VAD -- they legitimately connect externally and
        # blackholing Microsoft Defender or Office 365 would break the host.
        if is_telemetry_proc and trigger_layer != 0:
            confidence = min(confidence, 0.60)

        if immediate_action or confidence >= 0.75:
            verdict = 'CONFIRMED_BEACON'
        elif confidence >= 0.45:
            verdict = 'SUSPECTED_BEACON'
        elif confidence >= 0.20 or (n >= 1 and not is_browser_like):
            verdict = 'MONITOR'
        else:
            verdict = 'CLEAN'

        # Carve fires on CONFIRMED (or when pre-flagged regardless of verdict)
        if verdict == 'CONFIRMED_BEACON' or trigger_layer == 0:
            immediate_action = True

        scores.append(BeaconScore(
            pid=pid,
            process_name=evts_s[-1].process_name,
            remote_ip=ip,
            remote_port=port,
            verdict=verdict,
            confidence=confidence,
            trigger_layer=trigger_layer,
            sample_count=n,
            median_interval_sec=median_iv,
            jitter_cv=cv,
            family_hint=family_hint,
            indicators=indicators,
            first_seen=evts_s[0].timestamp,
            last_seen=evts_s[-1].timestamp,
            immediate_action=immediate_action,
            blackhole_requires_mwcp_confirmation=True,  # always -- daemon enforces this
        ))

    return sorted(scores, key=lambda s: s.confidence, reverse=True)
