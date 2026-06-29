"""
egress_monitor.py -- C2 beacon detection daemon.

Polls live process network connections via MemProcFS or falls back to
Get-NetTCPConnection (via subprocess) when the memory driver is unavailable.

On beacon confirmation:
  1. Carves memory of the suspect PID (VAD scan)
  2. Runs mwcp (CobaltStrikeConfig, GenericC2, PowerShellDecoder)
  3. Extracts config: C2 host, SpawnTo, PipeName, KillDate, UserAgent
  4. Hunts persistence tied to SpawnTo / PipeName
  5. Blackholes the specific confirmed C2 IP via Windows Firewall outbound block
  6. Writes detailed JSON evidence log

Runs for --duration-hours (default 24, configurable up to 72 or indefinitely).
All activity appended to egress_evidence.jsonl and summarised in egress_report.json.

Usage:
  python egress_monitor.py
      --out-dir     <path>            evidence output directory
      --tool-dir    <path>            staged tools/ directory
      --duration    <hours>           0 = run until killed
      --poll-sec    <seconds>         connection poll interval (default 5)
      --mgmt-ip     <ip,ip,...>       IPs to exclude from external classification
      --flagged-pid <pid,pid,...>     PIDs pre-flagged by enrichment (Layer 0)
      --incident-id <id>             incident identifier
      --blackhole-on-confirm          block confirmed C2 IPs immediately
      --no-memprocfs                  force netstat fallback (no MemProcFS)
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
import socket
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

# Local modules (same directory)
sys.path.insert(0, str(Path(__file__).parent))
from beacon_classifier import (
    ConnectionEvent, classify, is_external, BeaconScore
)
import carve_and_scan

log = logging.getLogger('egress')


# --------------------------------------------------------------------------
# Logging helpers
# --------------------------------------------------------------------------

def _ts() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _setup_logging(out_dir: Path):
    fmt = logging.Formatter('%(asctime)s %(levelname)s %(name)s %(message)s',
                            datefmt='%Y-%m-%dT%H:%M:%SZ')
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    # Console
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)
    root.addHandler(ch)
    # File
    fh = logging.FileHandler(out_dir / 'egress_monitor.log', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)
    root.addHandler(fh)


# --------------------------------------------------------------------------
# Network polling
# --------------------------------------------------------------------------

def _poll_memprocfs(vmm, mgmt_ips: set, t: float) -> list[ConnectionEvent]:
    """Poll all process network connections via MemProcFS."""
    events = []
    try:
        for proc in vmm.process_list():
            pid  = proc.pid
            name = proc.name.rstrip('\x00')
            try:
                nets = vmm.process(pid).maps.net()
                for conn in nets:
                    ip   = conn.get('RemoteIp', '') or conn.get('dst', '') or ''
                    port = conn.get('RemotePort', 0) or conn.get('dport', 0) or 0
                    state = conn.get('State', '') or ''
                    if state not in ('ESTABLISHED', 'ESTAB', ''):
                        continue
                    if not is_external(ip, mgmt_ips):
                        continue
                    events.append(ConnectionEvent(
                        timestamp=t, pid=pid, process_name=name,
                        remote_ip=ip, remote_port=int(port)
                    ))
            except Exception:
                pass
    except Exception as e:
        log.debug(f'MemProcFS net poll error: {e}')
    return events


def _poll_netstat(mgmt_ips: set, t: float) -> list[ConnectionEvent]:
    """Fallback: parse Get-NetTCPConnection via PowerShell."""
    events = []
    try:
        cmd = (
            'powershell.exe -NoProfile -NonInteractive -Command "'
            'Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | '
            'Select-Object OwningProcess,RemoteAddress,RemotePort | '
            'ConvertTo-Json -Compress"'
        )
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, shell=True)
        if r.returncode != 0 or not r.stdout.strip():
            return events
        rows = json.loads(r.stdout.strip())
        if isinstance(rows, dict):
            rows = [rows]
        # Get process names separately
        pid_names: dict[int, str] = {}
        try:
            plist = subprocess.run(
                'powershell.exe -NoProfile -NonInteractive -Command "'
                'Get-Process | Select-Object Id,ProcessName | ConvertTo-Json -Compress"',
                capture_output=True, text=True, timeout=10, shell=True
            )
            if plist.returncode == 0:
                procs = json.loads(plist.stdout.strip())
                if isinstance(procs, dict):
                    procs = [procs]
                for p in procs:
                    pid_names[p.get('Id', 0)] = p.get('ProcessName', '')
        except Exception:
            pass

        for row in rows:
            ip   = row.get('RemoteAddress', '')
            port = row.get('RemotePort', 0)
            pid  = row.get('OwningProcess', 0)
            if not is_external(ip, mgmt_ips):
                continue
            events.append(ConnectionEvent(
                timestamp=t, pid=pid,
                process_name=pid_names.get(pid, f'pid{pid}'),
                remote_ip=ip, remote_port=int(port)
            ))
    except Exception as e:
        log.debug(f'Netstat fallback error: {e}')
    return events


# --------------------------------------------------------------------------
# Firewall blackhole
# --------------------------------------------------------------------------

def _blackhole_ip(ip: str, incident_id: str, out_dir: Path):
    """Block outbound to a confirmed C2 IP via Windows Firewall."""
    rule_name = f'IR-EgressBlock-{incident_id}-{ip.replace(".", "-")}'
    cmd = (
        f'netsh advfirewall firewall add rule '
        f'name="{rule_name}" '
        f'dir=out action=block protocol=any '
        f'remoteip={ip} enable=yes'
    )
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15, shell=True)
        if r.returncode == 0:
            log.warning(f'[BLACKHOLE] Outbound to {ip} blocked (rule: {rule_name})')
            _append_evidence(out_dir, {
                'timestamp': _ts(), 'event': 'BLACKHOLE_APPLIED',
                'ip': ip, 'rule': rule_name
            })
        else:
            log.error(f'[BLACKHOLE] Failed to block {ip}: {r.stderr.strip()}')
    except Exception as e:
        log.error(f'[BLACKHOLE] Exception blocking {ip}: {e}')


# --------------------------------------------------------------------------
# Evidence log
# --------------------------------------------------------------------------

def _append_evidence(out_dir: Path, record: dict):
    """Append one JSONL record to the evidence log."""
    line = json.dumps(record, default=str)
    with open(out_dir / 'egress_evidence.jsonl', 'a', encoding='utf-8') as f:
        f.write(line + '\n')


def _write_summary(out_dir: Path, state: dict):
    """Overwrite the live summary JSON (read by Watch-Egress -Status)."""
    with open(out_dir / 'egress_report.json', 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, default=str)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out-dir',            required=True)
    ap.add_argument('--tool-dir',           required=True)
    ap.add_argument('--duration',           type=float, default=24.0,
                    help='Hours to run (0 = run until killed)')
    ap.add_argument('--poll-sec',           type=float, default=5.0)
    ap.add_argument('--mgmt-ip',            default='')
    ap.add_argument('--flagged-pid',        default='')
    ap.add_argument('--incident-id',        default='egress')
    ap.add_argument('--blackhole-on-confirm', action='store_true')
    ap.add_argument('--no-memprocfs',       action='store_true')
    args = ap.parse_args()

    out_dir  = Path(args.out_dir);  out_dir.mkdir(parents=True, exist_ok=True)
    tool_dir = Path(args.tool_dir)

    _setup_logging(out_dir)
    log.info(f'Egress monitor starting | incident={args.incident_id} '
             f'duration={args.duration}h poll={args.poll_sec}s')

    mgmt_ips: set[str] = {
        ip.strip() for ip in args.mgmt_ip.split(',') if ip.strip()
    }
    pre_flagged: set[int] = {
        int(p.strip()) for p in args.flagged_pid.split(',') if p.strip().isdigit()
    }

    # MemProcFS init
    vmm = None
    if not args.no_memprocfs:
        try:
            mpc_dir = tool_dir / 'memprocfs'
            if mpc_dir.exists():
                os.add_dll_directory(str(mpc_dir))
                sys.path.insert(0, str(mpc_dir))
                import vmmpyc
                # Live host: use winpmem kernel driver (loaded by go-winpmem or pre-staged).
                # '-device' 'winpmem' = read live process memory via driver.
                # Falls back to netstat if driver not loaded (error caught below).
                vmm = vmmpyc.Vmm(['-device', 'winpmem', '-disable-python',
                                   '-disable-symbolserver'])
                log.info('MemProcFS live mode active (vmmpyc)')
        except Exception as e:
            log.info(f'MemProcFS unavailable ({e}); using netstat fallback')

    # State
    all_events: list[ConnectionEvent] = []
    confirmed_ips:  set[str] = set()   # already blackholed
    carved_pids:    set[int] = set()   # already carved this session
    carve_results:  dict     = {}      # pid -> CarveResult (for blackhole gate)
    beacon_count   = 0
    start_time     = time.time()
    deadline       = start_time + args.duration * 3600 if args.duration > 0 else float('inf')

    summary = {
        'incident_id':       args.incident_id,
        'started':           _ts(),
        'duration_hours':    args.duration,
        'poll_sec':          args.poll_sec,
        'mgmt_ips':          list(mgmt_ips),
        'pre_flagged_pids':  list(pre_flagged),
        'blackhole_enabled': args.blackhole_on_confirm,
        'connections_seen':  0,
        'beacons_confirmed': 0,
        'beacons_suspected': 0,
        'ips_blackholed':    [],
        'carves_completed':  0,
        'status':            'running',
    }
    _write_summary(out_dir, summary)

    log.info(f'Monitoring started. Duration: '
             f'{"indefinite" if args.duration == 0 else f"{args.duration}h"}')

    try:
        while time.time() < deadline:
            t = time.time()

            # Poll connections
            if vmm:
                new_events = _poll_memprocfs(vmm, mgmt_ips, t)
            else:
                new_events = _poll_netstat(mgmt_ips, t)

            for ev in new_events:
                _append_evidence(out_dir, {
                    'timestamp': _ts(), 'event': 'CONNECTION',
                    'pid': ev.pid, 'process': ev.process_name,
                    'remote_ip': ev.remote_ip, 'remote_port': ev.remote_port,
                    'layer0_flagged': ev.pid in pre_flagged,
                })
            all_events.extend(new_events)
            summary['connections_seen'] += len(new_events)

            # Classify accumulated events
            scores: list[BeaconScore] = classify(
                all_events, mgmt_ips, pre_flagged_pids=pre_flagged
            )

            for score in scores:
                if score.verdict not in ('CONFIRMED_BEACON', 'SUSPECTED_BEACON'):
                    continue

                is_confirmed = score.verdict == 'CONFIRMED_BEACON'
                pid = score.pid
                ip  = score.remote_ip

                # Log the detection
                det_record = {
                    'timestamp':     _ts(),
                    'event':         'BEACON_DETECTED',
                    'verdict':       score.verdict,
                    'confidence':    round(score.confidence, 3),
                    'pid':           pid,
                    'process':       score.process_name,
                    'remote_ip':     ip,
                    'remote_port':   score.remote_port,
                    'family_hint':   score.family_hint,
                    'trigger_layer': score.trigger_layer,
                    'sample_count':  score.sample_count,
                    'median_interval_sec': round(score.median_interval_sec, 1),
                    'jitter_cv':     round(score.jitter_cv, 3) if score.jitter_cv < 999 else None,
                    'indicators':    score.indicators,
                }
                _append_evidence(out_dir, det_record)
                log.warning(
                    f'[{score.verdict}] PID {pid} ({score.process_name}) → '
                    f'{ip}:{score.remote_port}  confidence={score.confidence:.0%}  '
                    f'family={score.family_hint}  layer={score.trigger_layer}'
                )

                if is_confirmed:
                    summary['beacons_confirmed'] += 1
                else:
                    summary['beacons_suspected'] += 1

                # Memory carve + mwcp (once per PID per session)
                if score.immediate_action and pid not in carved_pids and vmm:
                    carved_pids.add(pid)
                    log.info(f'[CARVE] Triggering memory carve for PID {pid}')
                    try:
                        result = carve_and_scan.run(
                            vmm=vmm,
                            pid=pid,
                            process_name=score.process_name,
                            tool_dir=tool_dir,
                            out_dir=out_dir,
                        )
                        summary['carves_completed'] += 1
                        carve_record = {
                            'timestamp':         _ts(),
                            'event':             'CARVE_COMPLETE',
                            'pid':               pid,
                            'process':           score.process_name,
                            'regions_carved':    result.regions_carved,
                            'regions_findings':  result.regions_with_findings,
                            'c2_addresses':      result.c2_addresses,
                            'cs_config':         result.cs_config,
                            'spawn_to':          result.spawn_to,
                            'pipe_name':         result.pipe_name,
                            'kill_date':         result.kill_date,
                            'user_agent':        result.user_agent,
                            'host_header':       result.host_header,
                            'persistence_hints': result.persistence_hints,
                            'decoded_strings':   result.decoded_strings[:10],
                            'error':             result.error,
                        }
                        _append_evidence(out_dir, carve_record)
                        log.info(
                            f'[CARVE] Complete: {result.regions_carved} regions, '
                            f'{result.regions_with_findings} with findings, '
                            f'C2={result.c2_addresses[:3]}, '
                            f'SpawnTo={result.spawn_to!r}'
                        )
                        if result.persistence_hints:
                            log.warning(f'[PERSISTENCE] {result.persistence_hints}')
                        carve_results[pid] = result
                    except Exception as e:
                        log.error(f'[CARVE] Pipeline error for PID {pid}: {e}')

                # Blackhole gate: requires BOTH confirmation AND mwcp finding real config.
                # Score alone is NOT sufficient -- threat actors route through CDNs,
                # and periodic connections from telemetry processes are normal.
                # We must see actual malware evidence (C2 address, CS config, mutex)
                # extracted from the process memory before blocking its C2 IP.
                if args.blackhole_on_confirm and ip not in confirmed_ips:
                    carve = carve_results.get(pid)
                    has_real_config = (
                        carve is not None and (
                            carve.c2_addresses        # GenericC2 / CobaltStrikeConfig found IPs/URLs
                            or carve.cs_config        # Full CobaltStrike config extracted
                            or (carve.decoded_strings and
                                any('[CS-' in s or '[PS-Encoded' in s or '[LNK-' in s
                                    for s in carve.decoded_strings))
                        )
                    )
                    if has_real_config:
                        confirmed_ips.add(ip)
                        _blackhole_ip(ip, args.incident_id, out_dir)
                        summary['ips_blackholed'].append(ip)
                        log.warning(
                            f'[BLACKHOLE] {ip} blocked: mwcp confirmed malware config '
                            f'(C2={carve.c2_addresses[:2]}, CS={bool(carve.cs_config)})'
                        )
                    elif pid in carved_pids:
                        log.info(
                            f'[GATE] {ip} NOT blackholed: carve ran for PID {pid} '
                            f'but mwcp found no malware config (Ekko sleep or not C2)'
                        )

            _write_summary(out_dir, summary)

            elapsed = time.time() - start_time
            remaining = deadline - time.time() if args.duration > 0 else float('inf')
            log.debug(
                f'Poll complete: {len(new_events)} new conns, '
                f'{len(all_events)} total, elapsed={elapsed/3600:.2f}h'
            )

            time.sleep(args.poll_sec)

    except KeyboardInterrupt:
        log.info('Egress monitor interrupted by operator')
    finally:
        summary['status']  = 'completed'
        summary['stopped'] = _ts()
        _write_summary(out_dir, summary)
        _append_evidence(out_dir, {
            'timestamp': _ts(), 'event': 'MONITOR_STOPPED',
            'beacons_confirmed': summary['beacons_confirmed'],
            'beacons_suspected': summary['beacons_suspected'],
            'ips_blackholed':    summary['ips_blackholed'],
            'carves_completed':  summary['carves_completed'],
        })
        log.info(
            f'Monitor stopped. Confirmed: {summary["beacons_confirmed"]}, '
            f'Suspected: {summary["beacons_suspected"]}, '
            f'Blackholed: {len(summary["ips_blackholed"])}'
        )


if __name__ == '__main__':
    main()
