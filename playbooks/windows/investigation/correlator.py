"""Multi-source correlation layer -- the QA pass that sees what individual tools miss.

Each tool in the IR workflow captures one slice of the picture:
  memory_forensic.py  -- what is in memory RIGHT NOW (encrypted regions, hooks, threads)
  mwcp_scan.py        -- what C2 config/IOCs are embedded in files or carved regions
  deep_sensor_ml      -- how processes are BEHAVING over time (velocity, entropy, lineage)
  Windows event log   -- what HAPPENED (process create, logon, service install, WMI)

An adversary blending into normal admin activity may show nothing suspicious in any
single source.  The combination reveals the deception:

  Example A -- Admin-blending beacon:
    - Event log: WMI subscription installed at 02:14 by SYSTEM (could be admin)
    - Memory:    svchost.exe has UNIFORM encrypted 64KB RW region (anomalous for svchost)
    - EDR:       svchost.exe made 1 external connection at 02:14 then went silent (beacon pattern)
    - mwcp:      C2URL extracted from carved memory region in that svchost PID
    - Alone: each finding is ambiguous. Together: near-certain C2 implant.

  Example B -- LOLBin stealth:
    - Event log: wmic.exe spawned by SYSTEM at 03:00 (might be legit)
    - Memory:    parent process (services.exe) has injected anonymous exec VAD
    - EDR:       wmic.exe executed an unusual query 4.2 sigma outside baseline
    - mwcp:      no extraction (living off the land, no embedded config)
    - Verdict: process tree context + memory anomaly + temporal Z-score = TP

  Example C -- False positive closed:
    - Event log: taskhostw.exe ran a scheduled task (expected)
    - Memory:    high-entropy RW regions in taskhostw.exe (non-uniform, no AdjAnonExec)
    - EDR:       taskhostw.exe shows normal, low velocity, no network
    - mwcp:      no extraction
    - Verdict: NOISE_CLOSED -- all sources benign, task scheduler work items confirmed.

Input schema for correlate():

  findings:    List[dict]   -- memory_forensic.py findings (Memory_Findings_*.json)
  mwcp_hits:   List[dict]   -- mwcp_scan.py results per-file/carved-region
  edr_events:  List[dict]   -- process/network events (deep_sensor_ml or Sysmon)
  event_logs:  List[dict]   -- parsed Windows event log entries (4688, 4624, 7045 etc.)

Output: List[CorrelationVerdict] -- one per unique PID with all-source evidence assembled.
"""
from __future__ import annotations
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .engine import investigate, _parse_pid_process
from .verdict import Verdict, VerdictLabel, Dimension, TP_DIMENSION_THRESHOLD
from .fp_closure import build_fp_closure


@dataclass
class CrossSourceSignal:
    source: str       # 'memory', 'mwcp', 'edr', 'eventlog'
    positive: bool
    weight: float     # 1.0 = full dimension, 0.5 = corroborating
    description: str


@dataclass
class CorrelationVerdict:
    pid: int
    process: str
    label: VerdictLabel
    memory_verdict: Optional[Verdict]
    signals: List[CrossSourceSignal]
    positive_weight: float
    rationale: str
    all_evidence: Dict[str, List[dict]] = field(default_factory=dict)


# Weight thresholds for cross-source TP/FP
_TP_WEIGHT = 3.0   # same as TP_DIMENSION_THRESHOLD
_FP_WEIGHT = 0.0


def _extract_pid_from_mwcp(hit: dict) -> int:
    """mwcp hits reference a file path; match to PID via carved-region filename.

    Prefer an explicit 'pid' key when the caller already resolved it (e.g. from
    a carved-region filename convention the generic 'pid_NNN' regex can't parse).
    """
    if hit.get('pid'):
        return int(hit['pid'])
    fname = hit.get('file', '')
    m = re.search(r'pid[_-]?(\d+)', fname, re.IGNORECASE)
    return int(m.group(1)) if m else 0


def _extract_pid_from_edr(event: dict) -> int:
    return event.get('pid', 0) or event.get('PID', 0)


def _extract_pid_from_eventlog(entry: dict) -> int:
    return entry.get('SubjectProcessId', 0) or entry.get('NewProcessId', 0) or entry.get('pid', 0)


def _score_mwcp(hit: dict) -> List[CrossSourceSignal]:
    """mwcp extracted config from a file/carved region.

    Address extraction (network-shaped: IP, URL, or host:port) is the only mwcp
    signal treated as independent positive evidence. mwcp's generic mutex parser
    run against managed-code (.NET/PowerShell) memory routinely collects import
    names and heap padding rather than genuine mutex handles -- observed on real
    scan data: WinAPI function names and repeated hex/digit strings reported as
    "mutex" against PowerShell-hosted regions. Mutex hits are kept as non-scored
    context rather than dropped, so the analyst still sees them without the
    engine treating scanner noise as corroborating evidence.
    """
    sigs = []
    address  = hit.get('address') or []
    mutex    = hit.get('mutex') or []
    password = hit.get('password') or []

    if address:
        sigs.append(CrossSourceSignal(
            source='mwcp', positive=True, weight=1.0,
            description=(f'mwcp extracted network-shaped indicator(s) from '
                         f'{hit.get("file", "carved region")}: address={address}')
        ))
    if mutex:
        sigs.append(CrossSourceSignal(
            source='mwcp', positive=False, weight=0.0,
            description=(f'mwcp mutex/string artifacts from {hit.get("file", "carved region")}: '
                         f'{mutex[:5]}{"..." if len(mutex) > 5 else ""} -- context only, not scored '
                         '(generic mutex parser is unreliable over managed-code memory)')
        ))
    if password:
        sigs.append(CrossSourceSignal(
            source='mwcp', positive=True, weight=0.5,
            description=f'mwcp extracted credentials/keys: password={password}')
        )
    return sigs


def _score_edr(event: dict) -> Optional[CrossSourceSignal]:
    """Parse an EDR event for behavioral anomalies.

    Anomaly indicators (from deep_sensor_ml design):
      - z_score high (LotL temporal anomaly)
      - isolation_forest_score high (behavioral outlier)
      - velocity anomaly (machine-speed execution)
      - high entropy command line
      - unusual parent-child tuple
    """
    z     = event.get('z_score', 0.0) or 0.0
    score = event.get('isolation_score', 0.0) or event.get('anomaly_score', 0.0) or 0.0
    vel   = event.get('velocity', 0.0) or 0.0
    ent   = event.get('entropy', 0.0) or 0.0
    alert_reason = event.get('alert_reason', '') or event.get('reason', '')
    confidence   = event.get('confidence', 0.0) or 0.0
    event_type   = event.get('event_type', '') or event.get('Type', '')

    # High-confidence EDR alert
    if confidence >= 85.0 or alert_reason:
        return CrossSourceSignal(
            source='edr', positive=True, weight=1.0,
            description=(f'EDR alert: {alert_reason or event_type} '
                         f'confidence={confidence:.0f}% '
                         f'z_score={z:.2f} iso_score={score:.2f}')
        )
    # LotL Z-score anomaly
    if z >= 4.0:
        return CrossSourceSignal(
            source='edr', positive=True, weight=0.5,
            description=f'EDR LotL temporal anomaly: Z-score={z:.2f} for {event.get("process", "?")} '
                        f'-- execution timing 4+ stddev outside baseline'
        )
    # Isolation forest behavioral outlier
    if score >= 0.60:
        return CrossSourceSignal(
            source='edr', positive=True, weight=0.5,
            description=f'EDR isolation forest outlier: score={score:.2f} for {event.get("process", "?")} '
                        f'-- behavioral profile anomalous vs. system baseline'
        )
    # Machine-speed velocity
    if vel > 10.0 and ent > 4.5:
        return CrossSourceSignal(
            source='edr', positive=True, weight=0.5,
            description=f'EDR burst + high entropy: velocity={vel:.1f}/s entropy={ent:.2f} '
                        f'-- programmatic execution of obfuscated content (T1027/T1059)'
        )
    # Benign baseline confirmed by EDR
    if confidence == 0.0 and z < 2.0 and score < 0.3:
        return CrossSourceSignal(
            source='edr', positive=False, weight=0.5,
            description=f'EDR baseline confirms normal behavior: Z={z:.2f} iso={score:.2f} vel={vel:.1f}/s'
        )
    return None


def _score_eventlog(entry: dict) -> Optional[CrossSourceSignal]:
    """Parse a Windows event log entry for suspicious indicators.

    Key events:
      4688 (process creation): unusual parent, suspicious command line, off-hours
      4624 (logon): unusual logon type/time/source for service accounts
      7045 (service install): new service installed outside maintenance windows
      1 (Sysmon process create): same as 4688 with more data
    """
    event_id  = entry.get('EventID', 0) or entry.get('event_id', 0)
    cmd       = entry.get('CommandLine', '') or entry.get('cmd', '') or ''
    parent    = entry.get('ParentProcessName', '') or entry.get('parent', '') or ''
    user      = entry.get('SubjectUserName', '') or entry.get('user', '') or ''
    logon_t   = entry.get('LogonType', 0) or 0
    svc_name  = entry.get('ServiceName', '') or ''
    svc_path  = entry.get('ServiceFileName', '') or ''

    # Service installed from unusual path
    if event_id == 7045 and svc_path:
        suspicious_path = any(p in svc_path.lower() for p in
                              ['temp', 'appdata', 'public', 'download', 'programdata\\microsoft\\'])
        if suspicious_path:
            return CrossSourceSignal(
                source='eventlog', positive=True, weight=1.0,
                description=f'Event 7045: Service [{svc_name}] installed from suspicious path: {svc_path}'
            )

    # Process creation with obfuscated command line or unusual parent
    if event_id in (4688, 1):
        enc = bool(re.search(r'-enc|-EncodedCommand|frombase64string|iex\s*\(', cmd, re.IGNORECASE))
        hidden = bool(re.search(r'-w\s*h|-windowstyle\s*hid', cmd, re.IGNORECASE))
        dl = bool(re.search(r'DownloadString|WebClient|Invoke-WebRequest|curl\s', cmd, re.IGNORECASE))
        unusual_parent = bool(re.search(
            r'winword|excel|powerpnt|outlook|mshta|wscript|cscript', parent, re.IGNORECASE
        ))
        if (enc and hidden) or (dl and hidden) or unusual_parent:
            return CrossSourceSignal(
                source='eventlog', positive=True, weight=1.0,
                description=(f'Event {event_id}: suspicious process creation -- '
                             f'encoded={enc} hidden={hidden} download={dl} '
                             f'parent={parent} cmd={cmd[:150]}')
            )

    # Network logon to non-interactive service account at unusual hour
    if event_id == 4624 and logon_t == 3:
        if '$' not in user and 'SYSTEM' not in user.upper():
            return CrossSourceSignal(
                source='eventlog', positive=False, weight=0.3,
                description=f'Event 4624: network logon by {user} (logon_type=3) -- '
                            'possible lateral movement if combined with other signals; '
                            'alone: normal admin network logon'
            )

    return None


def correlate(findings: List[dict],
              mwcp_hits: Optional[List[dict]] = None,
              edr_events: Optional[List[dict]] = None,
              event_logs: Optional[List[dict]] = None) -> List[CorrelationVerdict]:
    """
    Multi-source correlation pass.

    1. Run per-PID memory investigation (engine.investigate())
    2. For each PID: layer in mwcp, EDR, and event log signals
    3. Weight the combined evidence and emit CorrelationVerdict
    """
    mwcp_hits  = mwcp_hits  or []
    edr_events = edr_events or []
    event_logs = event_logs or []

    # --- Memory investigation (base layer) ---
    mem_verdicts: Dict[int, Verdict] = {
        v.pid: v for v in investigate(findings)
    }

    # --- Map non-memory signals to PIDs ---
    mwcp_by_pid:  Dict[int, List[dict]] = defaultdict(list)
    edr_by_pid:   Dict[int, List[dict]] = defaultdict(list)
    log_by_pid:   Dict[int, List[dict]] = defaultdict(list)

    for h in mwcp_hits:
        pid = _extract_pid_from_mwcp(h)
        if pid:
            mwcp_by_pid[pid].append(h)

    for e in edr_events:
        pid = _extract_pid_from_edr(e)
        if pid:
            edr_by_pid[pid].append(e)

    for l in event_logs:
        pid = _extract_pid_from_eventlog(l)
        if pid:
            log_by_pid[pid].append(l)

    # --- All known PIDs across sources ---
    all_pids = (set(mem_verdicts.keys()) |
                set(mwcp_by_pid.keys()) |
                set(edr_by_pid.keys()) |
                set(log_by_pid.keys()))

    results: List[CorrelationVerdict] = []

    for pid in sorted(all_pids):
        mem_v = mem_verdicts.get(pid)
        signals: List[CrossSourceSignal] = []

        # Memory signals (from Verdict dimensions)
        if mem_v:
            for dim in mem_v.dimensions:
                signals.append(CrossSourceSignal(
                    source='memory', positive=dim.positive,
                    weight=1.0 if dim.positive else 0.5,
                    description=f'M{dim.source_module} {dim.name}: {dim.rationale[:120]}'
                ))

        # mwcp signals
        for hit in mwcp_by_pid.get(pid, []):
            signals.extend(_score_mwcp(hit))

        # EDR signals
        for evt in edr_by_pid.get(pid, []):
            sig = _score_edr(evt)
            if sig:
                signals.append(sig)

        # Event log signals
        for entry in log_by_pid.get(pid, []):
            sig = _score_eventlog(entry)
            if sig:
                signals.append(sig)

        # A PID with no memory verdict and nothing but zero-weight context signals
        # (e.g. an mwcp mutex-only hit, kept for visibility but not scored) has no
        # forensic content -- skip it rather than emit an empty UNDETERMINED shell.
        if mem_v is None and all(s.weight == 0.0 for s in signals):
            continue

        # --- Cross-source verdict ---
        pos_weight = sum(s.weight for s in signals if s.positive)
        neg_weight = sum(s.weight for s in signals if not s.positive)
        process = mem_v.process if mem_v else f'PID {pid}'

        if pos_weight >= _TP_WEIGHT:
            label = VerdictLabel.TRUE_POSITIVE
        elif pos_weight == 0.0:
            # No positive signals from ANY source -- inherit memory verdict.
            # A memory FP with zero dims loses its FP classification if we only
            # check neg_weight (empty dims -> neg_weight=0 -> falls to UNDETERMINED).
            # Always preserve the memory layer verdict when no external signal contradicts it.
            if mem_v and mem_v.label == VerdictLabel.NOISE_CLOSED:
                label = VerdictLabel.NOISE_CLOSED
            elif mem_v and mem_v.label == VerdictLabel.FALSE_POSITIVE:
                label = VerdictLabel.FALSE_POSITIVE
            elif neg_weight > 0.0:
                label = VerdictLabel.FALSE_POSITIVE
            else:
                # No memory verdict, no signals at all -- truly unknown
                label = VerdictLabel.UNDETERMINED
        else:
            # pos_weight > 0 but below TP threshold
            label = VerdictLabel.UNDETERMINED

        rationale_lines = [
            f'Cross-source verdict for PID {pid} ({process}): {label.value}',
            f'  Positive weight: {pos_weight:.1f} / Threshold: {_TP_WEIGHT:.1f}',
            f'  Sources contributing: memory={bool(mem_v)} mwcp={bool(mwcp_by_pid.get(pid))} '
            f'edr={bool(edr_by_pid.get(pid))} eventlog={bool(log_by_pid.get(pid))}',
            '',
        ]
        for s in signals:
            tag = 'TP' if s.positive else 'FP'
            rationale_lines.append(f'  [{tag}:{s.source}:{s.weight:.1f}] {s.description}')

        results.append(CorrelationVerdict(
            pid=pid, process=process, label=label,
            memory_verdict=mem_v, signals=signals,
            positive_weight=pos_weight,
            rationale='\n'.join(rationale_lines),
            all_evidence={
                'memory':   [f for f in findings if _parse_pid_process(f.get('Target', ''))[0] == pid],
                'mwcp':     mwcp_by_pid.get(pid, []),
                'edr':      edr_by_pid.get(pid, []),
                'eventlog': log_by_pid.get(pid, []),
            }
        ))

    return results
