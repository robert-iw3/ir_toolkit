"""Investigation engine orchestrator (Linux).

Entry point: investigate(findings) -> List[Verdict]

Accepts the findings list from any Linux collector (EDR_Report_*.json /
Memory_Findings_*.json / Combined_Findings_*.json -- all share the common
{Timestamp, Severity, Type, Target, Details, MITRE} schema), groups by PID
(or the HOST_SCOPE_PID pseudo-PID for kernel/persistence/account findings
with no owning process), then for each group:

  1. Noise filter (models/noise_filter.py) -- deterministic rules, not ML
     (see that module's docstring for why Linux differs from the Windows
     engine here). If certain background: NOISE_CLOSED, no module investigation.

  2. Per-module investigation -- routes each finding Type to one of 19
     modules (deleted/memfd exec, hidden process, injected memory, shell
     tooling, kernel rootkit, credential/privesc, eBPF/io_uring,
     namespace/container, persistence, network, SSH hygiene, YARA/capa,
     linker/library hijack, masquerade, anti-forensics, ptrace, SUID/caps,
     recovered C2 config, remote access) and collects Dimension objects.

  3. Verdict assembly -- identical tiered-evidence model to the Windows
     engine (see verdict.py's Tier docstring): any Tier 1 (DEFINITIVE)
     positive settles TRUE_POSITIVE immediately; otherwise 3+ Tier 1/2
     positives reach the same floor; Tier 3 positives can never reach it
     alone; zero countable positives -> FALSE_POSITIVE; otherwise UNDETERMINED.

  4. Cross-PID shared-infrastructure propagation (_propagate_shared_infrastructure)
     -- pursues one more lead before any verdict is final: if two INDEPENDENT
     PIDs (each already suspicious on its own non-network merits) reach the
     exact same non-private destination endpoint, that shared infrastructure
     corroborates both rather than being evaluated per-PID in isolation.

  4b. Process-lineage propagation (_propagate_process_lineage) -- same pattern,
     different relationship: a direct parent/child pair where BOTH sides are
     ALREADY independently suspicious corroborates each other (a legitimate
     process tree's ubiquitous parent-child edges make "has a parent" alone
     worthless as a signal; only two INDEPENDENTLY-earned leads meeting at a
     direct edge counts). Requires process-tree data (Adjudication_*.json's
     ParentPid), so it runs from correlator.py rather than investigate()
     itself, which only ever sees the flat findings list.

  5. Hidden-process volume cross-check (_cross_validate_hidden_process_volume)
     -- a DEFINITIVE claim (module 2) assumes the underlying Volatility 3
     symbol/struct resolution for THIS image was correct; 3+ unrelated,
     mundane PIDs flagged "hidden" in one run is itself evidence against that
     assumption (a rootkit hides what it needs hidden, not an arbitrary
     handful of utilities), so it downgrades to STRONG_BEHAVIORAL rather than
     staying an unconditional single-fact TP.
"""
from __future__ import annotations
import re
from collections import defaultdict
from typing import Dict, List, Tuple

from .verdict import Verdict, VerdictLabel, Dimension, Tier, TP_DIMENSION_THRESHOLD, HOST_SCOPE_PID, HOST_SCOPE_NAME
from .fp_closure import build_fp_closure, build_noise_closure
from .models.noise_filter import classify_noise
from .modules import (
    deleted_binary, hidden_process, injected_memory, shell_tooling, kernel_rootkit,
    credential_privesc, ebpf_io_uring, namespace_container, persistence, network,
    ssh_hygiene, yara_capa, linker_library, masquerade, anti_forensics, ptrace,
    suid_caps, c2_config, remote_access,
)

# Map finding Type string -> module number for routing. Exact-match table
# first; dynamic/prefix-based families (Module 18's recovered-config Types)
# are handled by _route_dynamic() below.
_TYPE_TO_MODULE: Dict[str, int] = {
    # M1 -- deleted/memfd/writable-path execution
    'Process Running Deleted Binary (memory)': 1, 'Deleted Running Binary': 1,
    'Memory-Only Executable (memfd)': 1, 'Execution From Writable Path': 1,
    'High Entropy ELF': 1,
    # M2 -- hidden process
    'Hidden Process (memory)': 2, 'Hidden Process': 2,
    # M3 -- injected/anonymous-executable memory
    'Injected Memory (malfind)': 3, 'Implant-Backed Mapping (memory)': 3,
    'Anomalous Call Stack (memory)': 3, 'Injected Code (memory YARA)': 3,
    'Anonymous Exec Memory': 3,
    # M4 -- shell/offensive tooling
    'Reverse Shell (memory)': 4, 'Reverse Shell': 4, 'Reverse Shell Indicator': 4,
    'Offensive Tooling (memory)': 4, 'Service-Spawned Shell': 4,
    'Suspicious Process Execution': 4, 'Webshell': 4,
    'Suspicious Sudo Command': 4, 'Unauthorized Sudo Attempt': 4,
    'Sudo Authentication Failure': 4, 'Suspicious Shell History (memory)': 4,
    # M5 -- kernel rootkit signals
    'Hidden Kernel Module (memory)': 5, 'Hidden Kernel Module (carved)': 5,
    'Hidden Kernel Module': 5, 'IDT Hook (memory)': 5, 'Netfilter Hook (memory)': 5,
    'VFS fops Hook (memory)': 5, 'Kernel .text Inline Hook (memory)': 5,
    'Kernel Timer Hook (memory)': 5, 'Kernel Thread Hook (memory)': 5,
    'modprobe_path Hijack (memory)': 5, 'modprobe_path Hijack': 5,
    'uevent_helper Hijack (memory)': 5, 'uevent_helper Hijack': 5,
    'Kernel core_pattern Hijack (memory)': 5, 'Kernel core_pattern Hijack': 5,
    'Kernel-Thread Name Masquerade (memory)': 5, 'Fake Kernel Thread': 5,
    'Suspicious Kernel Module': 5, 'Kallsyms Pseudo-Module (verify)': 5,
    'Kernel Tainted By Unaccounted Module (verify)': 5, 'Unnamed Carved Module (verify)': 5,
    # M6 -- credential override / privesc residue / credential exposure
    'Credential Override (memory)': 6, 'Unauthorized UID0 Account': 6,
    'Empty Password Account': 6, 'Unsigned Kernel Module': 6,
    'Credential/Memory Access': 6, 'Shadow File World-Readable': 6,
    'Staged Credential Artifact': 6, 'Process Core Dump': 6,
    # M7 -- eBPF / io_uring anti-EDR
    'eBPF Network C2 Correlated (memory)': 7, 'eBPF Object Held By Implant': 7,
    'Pinned eBPF Objects (verify)': 7, 'io_uring Anti-EDR I/O (memory)': 7,
    'io_uring Anti-EDR I/O': 7, 'io_uring In Use (memory, verify)': 7,
    'io_uring In Use (verify)': 7, 'eBPF Program (memory)': 7,
    # M8 -- namespace escape / container breakout
    'Namespace Escape (memory)': 8, 'Bind Mount Over System Path (memory)': 8,
    'Container Host Namespace': 8, 'Docker Socket Mount': 8, 'Privileged Container': 8,
    'Sensitive Host Mount': 8, 'Dangerous Container Capabilities': 8,
    'Pod Host Namespace': 8, 'Pod hostPath Mount': 8, 'Privileged Pod Container': 8,
    'Pod Privilege Escalation Allowed': 8, 'Pod Dangerous Capabilities': 8,
    'ClusterAdmin Binding': 8,
    # M9 -- persistence quick-sweep
    'Cron Persistence': 9, 'Systemd Persistence': 9, 'udev Rule Persistence': 9,
    'rc.local Persistence': 9, 'Autostart Persistence': 9, 'Shell Init Backdoor': 9,
    'Recently Modified PAM Module (verify)': 9, 'SSH Forced-Command Backdoor': 9,
    'Scheduled at-job Present': 9, 'Suspicious Cron Job': 9, 'Suspicious Service Execution': 9,
    'New Account Created': 9, 'Remote Root Logon': 9, 'Remote-Access Service': 9,
    'PAM Module Tampering': 9,
    # M10 -- network connection triage
    'External Connection (memory)': 10, 'External Connection From Untrusted Binary': 10,
    'Network Listener From Untrusted Binary': 10, 'External Connection': 10,
    'Listening Service': 10, 'Suspicious Outbound Connection': 10,
    'Unexpected Network Listener': 10,
    # M11 -- SSH key & account hygiene
    'Many SSH Authorized Keys': 11, 'SSH Key Reused Across Accounts': 11,
    'SSH authorized_keys is a Symlink': 11, 'SSH Key File World-Writable': 11,
    'SSH Key File Group-Writable': 11, 'SSH Key File Owner Mismatch': 11,
    'root authorized_keys Recently Modified': 11, 'SSH Config Weakness': 11,
    'SSH Brute Force': 11, 'SSH Authorized Key': 11, 'Non-standard AuthorizedKeysFile': 11,
    # M12 -- YARA / capa memory match
    'YARA Memory Match': 12, 'Memory Capabilities (capa)': 12,
    # M13 -- linker/library hijack
    'Linker Hijack (memory)': 13, 'Linker Path in Implant Dir (memory)': 13,
    'Library Preload Hijack': 13, 'Suspicious Loaded Library (memory)': 13,
    'Process Preload (memory)': 13, 'Process Preload': 13,
    'GOT/PLT Overwrite (memory)': 13, 'GOT Entry Relocation (verify)': 13,
    # M14 -- masquerade
    'Process Name Mismatch': 14, 'Spoofed Process From Implant Dir (memory)': 14,
    'Implant-Path Execution (memory)': 14, 'MagicByte Mismatch': 14,
    # M15 -- anti-forensics / logging tamper
    'Audit Rules Cleared': 15, 'Log File Truncated': 15, 'Logging Service Not Running': 15,
    'Logging Service Disabled': 15,
    'Journald Persistence Disabled': 15, 'Shell History Disabled': 15,
    'Journal Log Truncation': 15, 'Audit Logging Disabled': 15,
    'Mandatory Access Control Disabled': 15,
    # M16 -- ptrace attachment
    'Ptrace Attachment (memory)': 16,
    'Ptrace Injection - Thread IP in Injected Memory (memory)': 16,
    'Traced Thread Detail (memory)': 16, 'Corroborated Injected Thread (memory+live)': 16,
    # M17 -- SUID/capability abuse
    'Unexpected SUID Binary': 17, 'Dangerous Capability (memory)': 17,
    'Dangerous File Capability': 17, 'Privileged Task Binary Missing': 17,
    'Privileged Task Non-Root Binary': 17, 'Privileged Task World-Writable Binary': 17,
    # M19 -- remote access tooling
    'Remote Access Tool': 19, 'Crypto Miner': 19,
    # Context-only, never scored (collector self-check / infrastructure errors,
    # not detections)
    'Hunt Error': 99, 'Triage Error': 99, 'YARA Self-Test FAILED': 99,
}

_MODULE_FN = {
    1: deleted_binary.investigate, 2: hidden_process.investigate,
    4: shell_tooling.investigate, 5: kernel_rootkit.investigate,
    6: credential_privesc.investigate, 7: ebpf_io_uring.investigate,
    8: namespace_container.investigate, 9: persistence.investigate,
    10: network.investigate, 11: ssh_hygiene.investigate, 12: yara_capa.investigate,
    13: linker_library.investigate, 14: masquerade.investigate,
    15: anti_forensics.investigate, 16: ptrace.investigate,
    17: suid_caps.investigate, 18: c2_config.investigate, 19: remote_access.investigate,
}

# Module 18's Types are dynamic (f'C2 Config Recovered ({family})') -- route by
# prefix rather than an exhaustive per-family literal table.
_M18_PREFIXES = (
    'C2 Config Recovered', 'BPFDoor Config Artifact', 'Botnet Config Recovered',
    'SSH Backdoor Artifact', 'Cryptominer Config Recovered', 'Cryptominer C2',
    'Cryptominer Wallet', 'Exfiltration Channel', 'Cloud Credential in Memory',
    'Private Key Material', 'Tor C2', 'C2 Endpoint',
)

# Findings with no owning process -- kernel/host-scope. Everything not routed
# to a PID-bearing module by _parse_pid_target() lands in the HOST_SCOPE_PID
# bucket, so these Types don't need to be enumerated separately here.

_PID_TARGET_PATTERNS = (
    re.compile(r'PID\s+(\d+)\s+\(([^)]+)\)'),          # analyze_memory_linux.py: "PID 1234 (comm)"
    re.compile(r'PID:\s*(\d+)\s*\(([^)]+)\)'),         # edr_hunt.py: "PID: 1234 (comm)"
    re.compile(r'PID:\s*(\d+)\b'),                     # edr_hunt.py: "PID: 1234"
    re.compile(r'\(PID\s+(\d+)\)'),                    # remote_access_triage.py: "tool (PID 1234)"
    re.compile(r'PID\s+(\d+)\b'),                      # analyze_memory_linux.py bare: "PID 1234 @ <time>"
)


def _parse_pid_target(target: str, details: str = '') -> Tuple[int, str]:
    """Extract (pid, process_name) from any of the Target shapes the Linux
    collectors use, or (HOST_SCOPE_PID, '') if the finding has no owning
    process (a path, IDT[idx], rule name, IP, username, unit name, ...)."""
    for pat in _PID_TARGET_PATTERNS:
        m = pat.search(target)
        if m:
            groups = m.groups()
            pid = int(groups[0])
            proc = groups[1] if len(groups) > 1 and groups[1] else ''
            if not proc:
                # remote_access_triage.py shape: "{tool} (PID 1234)" -- tool name precedes
                pre = target[:m.start()].strip()
                proc = pre or ''
            return pid, proc
    # Some Details strings carry comm= even when Target doesn't have a PID shape
    m = re.search(r'PID\s+(\d+)', details)
    if m:
        proc_m = re.search(r'comm=(\S+)', details)
        return int(m.group(1)), (proc_m.group(1) if proc_m else '')
    return HOST_SCOPE_PID, ''


def _group_by_pid(findings: List[dict]) -> Dict[int, List[dict]]:
    groups: Dict[int, List[dict]] = defaultdict(list)
    for f in findings:
        pid, _ = _parse_pid_target(f.get('Target', ''), f.get('Details', ''))
        groups[pid].append(f)
    return groups


def _get_process_info(pid: int, pid_findings: List[dict]) -> Tuple[str, str, str]:
    """Return (process_name, process_path, parent_name) from any finding for this PID."""
    if pid == HOST_SCOPE_PID:
        return HOST_SCOPE_NAME, '', ''
    for f in pid_findings:
        details = f.get('Details', '')
        _, proc = _parse_pid_target(f.get('Target', ''), details)
        if not proc:
            # Target carried the PID but not a name (e.g. edr_hunt.py's "PID: 900")
            # -- comm= is usually still present in Details.
            comm_m = re.search(r'comm=(\S+)', details)
            proc = comm_m.group(1) if comm_m else ''
        if not proc:
            continue
        path_m = re.search(r'(?:[Pp]ath|exe|ImagePath)[=:]\s*([^\s,;]+)', details)
        path = path_m.group(1) if path_m else ''
        parent_m = re.search(r'[Pp]arent(?:Name)?[=:]\s*([^\s,;]+)', details)
        parent = parent_m.group(1) if parent_m else ''
        return proc, path, parent
    return f'PID {pid}', '', ''


def _route_module(ftype: str) -> int:
    mod = _TYPE_TO_MODULE.get(ftype)
    if mod:
        return mod
    if ftype.startswith(_M18_PREFIXES):
        return 18
    return 0  # unmapped -- still scored, never silently dropped


def _dedup_dimensions(dims: List[Dimension]) -> List[Dimension]:
    """Collapse identical dimensions into one, preserving the observation count.
    Same rationale as the Windows engine: repetition is not independence."""
    merged: Dict[Tuple[str, bool, str], int] = {}
    first: Dict[Tuple[str, bool, str], Dimension] = {}
    order: List[Tuple[str, bool, str]] = []
    for d in dims:
        key = (d.name, d.positive, d.rationale)
        if key not in merged:
            merged[key] = 0
            first[key] = d
            order.append(key)
        merged[key] += 1
    out: List[Dimension] = []
    for key in order:
        d = first[key]
        n = merged[key]
        if n > 1:
            d = Dimension(name=d.name, positive=d.positive,
                          rationale=f'{d.rationale} [observed in {n} findings]',
                          source_module=d.source_module, tier=d.tier, mechanism_id=d.mechanism_id)
        out.append(d)
    return out


def _investigate_misc(finding: dict) -> List[Dimension]:
    ftype = finding.get('Type', '')
    details = finding.get('Details', '')
    return [Dimension(
        name='M0_Unmapped', positive=True, source_module=0, tier=Tier.WEAK_STRUCTURAL,
        rationale=f'{ftype}: {details[:200]} -- no dedicated module for this Type yet; scored '
                  'conservatively rather than dropped.'
    )]


def _investigate_correlated_threat(finding: dict) -> Dimension:
    """analyze_memory_linux.py's correlate() already requires >=1 inherently-
    strong signal PLUS >=1 other distinct signal on the same PID before
    emitting this -- it is a meta-finding layered ON TOP of the individual
    findings it summarizes (which are still present in the same finding set
    and separately scored by their own modules). Counting it as one more
    STRONG_BEHAVIORAL dimension reflects that the collector has already done
    real cross-signal correlation work, without double-counting: it is one
    dimension among the others, not a multiplier on them."""
    details = finding.get('Details', '')
    return Dimension(
        name='M_CorrelatedMemoryThreat', positive=True, source_module=0,
        tier=Tier.STRONG_BEHAVIORAL,
        rationale=(f'Correlated Memory Threat: {details[:220]} -- the collector itself has '
                   'already confirmed multiple independent memory signals converge on this PID.')
    )


def _investigate_pid(pid: int, pid_findings: List[dict], all_findings: List[dict]) -> Verdict:
    process, path, parent = _get_process_info(pid, pid_findings)

    # -------------------------------------------------------------------------
    # Step 1: noise filter (skip for host-scope -- there is no "known daemon
    # process" concept for kernel/persistence/account findings)
    # -------------------------------------------------------------------------
    if pid != HOST_SCOPE_PID and process:
        is_noise, noise_score, noise_rationale = classify_noise(process, path, parent, pid_findings)
        if is_noise:
            return build_noise_closure(pid, process, noise_rationale, pid_findings, noise_score)

    # -------------------------------------------------------------------------
    # Step 2: per-module investigation
    # -------------------------------------------------------------------------
    all_dims: List[Dimension] = []
    injected_findings: List[dict] = []

    for finding in pid_findings:
        ftype = finding.get('Type', '')
        if ftype in ('Hunt Error', 'Triage Error', 'YARA Self-Test FAILED',
                    'Process Thread Inventory (memory)', 'Package Manager Transaction'):
            continue  # context only, never scored -- collector self-check, not a detection

        if ftype == 'Correlated Memory Threat':
            all_dims.append(_investigate_correlated_threat(finding))
            continue

        mod_num = _route_module(ftype)

        if mod_num == 3:
            injected_findings.append(finding)
        elif mod_num == 0:
            all_dims.extend(_investigate_misc(finding))
        else:
            fn = _MODULE_FN.get(mod_num)
            if fn:
                all_dims.extend(fn(finding))

    for finding in injected_findings:
        all_dims.extend(injected_memory.investigate(finding, pid_findings=pid_findings))

    return _assemble_verdict(pid, process, all_dims, pid_findings)


def _assemble_verdict(pid: int, process: str, all_dims: List[Dimension],
                      pid_findings: List[dict]) -> Verdict:
    """Step 3: verdict assembly (tiered evidence model -- identical rules to
    the Windows engine; see verdict.py's Tier docstring for the rationale)."""
    all_dims = _dedup_dimensions(all_dims)
    all_dims = [d for d in all_dims if d.tier != Tier.INVALID]
    pos_dims = [d for d in all_dims if d.positive]
    neg_dims = [d for d in all_dims if not d.positive]

    tier1_pos = [d for d in pos_dims if d.tier == Tier.DEFINITIVE]
    if tier1_pos:
        rationale = (
            f'TRUE POSITIVE: PID {pid} ({process}) -- Tier 1 (DEFINITIVE) evidence: '
            f'a single structurally-unforgeable fact settles this.\n\n'
            + '\n'.join(f'  [TP-TIER1] M{d.source_module} {d.name}: {d.rationale}' for d in tier1_pos)
        )
        other_pos = [d for d in pos_dims if d not in tier1_pos]
        if other_pos:
            rationale += '\n\nOther positive dimensions:\n' + '\n'.join(
                f'  [TP] M{d.source_module} {d.name}: {d.rationale}' for d in other_pos)
        if neg_dims:
            rationale += '\n\nNegative dimensions (documented):\n' + '\n'.join(
                f'  [FP] M{d.source_module} {d.name}: {d.rationale}' for d in neg_dims)
        return Verdict(pid=pid, process=process, label=VerdictLabel.TRUE_POSITIVE,
                       dimensions=all_dims, positive_count=len(pos_dims),
                       negative_count=len(neg_dims), rationale=rationale, findings=pid_findings)

    countable_pos = [d for d in pos_dims if d.tier != Tier.WEAK_STRUCTURAL]
    tier3_only_pos = [d for d in pos_dims if d.tier == Tier.WEAK_STRUCTURAL]
    pos_count = len(countable_pos)

    # HOST_SCOPE_PID is not one actor: every finding with no owning process (kernel
    # hygiene, SUID baseline drift, a stray credential-shaped file, a cron job's file
    # owner, a pinned eBPF object -- typically from several completely unrelated
    # modules) gets bucketed here purely because none of them have a PID to attach to,
    # NOT because they're corroborating facts about one thread of activity. The N-
    # dimension threshold below exists to test "does this SAME actor's behavior
    # corroborate across independent angles" (the README's own worked example: a
    # deleted-binary PID ALSO making an external connection ALSO relaunched by cron).
    # Applying it to a bucket of unrelated host-wide observations instead tests "has
    # this host accrued at least N routine findings from different checks" -- which is
    # true of nearly any real, long-running Linux host and manufactures a TRUE POSITIVE
    # out of coincidence, not correlation. Confirmed live: this promoted host-scope
    # findings that included this session's OWN leftover test fixtures and the
    # toolkit's OWN legitimate egress-monitor cron job into "TRUE POSITIVE, weight
    # 22.0." Only a genuinely unforgeable Tier 1 fact (handled above) can close
    # HOST_SCOPE_PID as TP; below that it stays UNDETERMINED, same as any other
    # pid whose evidence doesn't clear the bar.
    if pid != HOST_SCOPE_PID and pos_count >= TP_DIMENSION_THRESHOLD:
        unique_mods = len({d.source_module for d in countable_pos})
        rationale = (
            f'TRUE POSITIVE: PID {pid} ({process}) -- '
            f'{pos_count} independent positive dimension(s) across {unique_mods} module(s).\n\n'
            + '\n'.join(f'  [TP] M{d.source_module} {d.name}: {d.rationale}' for d in countable_pos)
        )
        if neg_dims:
            rationale += '\n\nNegative dimensions (documented):\n' + '\n'.join(
                f'  [FP] M{d.source_module} {d.name}: {d.rationale}' for d in neg_dims)
        return Verdict(pid=pid, process=process, label=VerdictLabel.TRUE_POSITIVE,
                       dimensions=all_dims, positive_count=len(pos_dims),
                       negative_count=len(neg_dims), rationale=rationale, findings=pid_findings)

    if pos_count == 0 and not tier3_only_pos:
        return build_fp_closure(pid, process, all_dims, pid_findings)

    rationale = (
        f'UNDETERMINED: PID {pid} ({process}) -- '
        f'{pos_count} positive dimension(s), threshold={TP_DIMENSION_THRESHOLD}. '
        f'Insufficient for TP verdict; additional collection or correlation required.\n\n'
        + '\n'.join(f'  [{"TP" if d.positive else "FP"}] M{d.source_module} {d.name}: {d.rationale}'
                    for d in all_dims)
    )
    if tier3_only_pos:
        rationale += (f'\n\n{len(tier3_only_pos)} Tier-3 (weak/structural) positive dimension(s) '
                      'present -- capability without demonstrated use; cannot alone justify TP.')
    return Verdict(pid=pid, process=process, label=VerdictLabel.UNDETERMINED,
                   dimensions=all_dims, positive_count=len(pos_dims),
                   negative_count=len(neg_dims), rationale=rationale, findings=pid_findings)


_PRIVATE_IP_RE = re.compile(
    r'^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.0\.0\.0|::1|fe80:)')
_DEST_ENDPOINT_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})')
_NETWORK_FINDING_TYPES = frozenset({
    'External Connection (memory)', 'External Connection From Untrusted Binary',
    'External Connection', 'Suspicious Outbound Connection',
})


def _extract_dest_endpoint(finding: dict) -> str:
    """Destination ip:port from either Target (analyze_memory_linux.py's own
    convention: Target IS the endpoint) or Details (edr_hunt.py: "...to
    RIP:RPORT..." embedded in the text). Returns '' if none found or private."""
    target = finding.get('Target', '')
    m = _DEST_ENDPOINT_RE.search(target)
    if not m:
        m = _DEST_ENDPOINT_RE.search(finding.get('Details', ''))
    if not m:
        return ''
    ip = m.group(1)
    if _PRIVATE_IP_RE.match(ip):
        return ''
    return f'{ip}:{m.group(2)}'


def _has_independent_positive(dims: List[Dimension], exclude_prefix: str = '') -> bool:
    """A dimension counts as grounds for cross-PID corroboration only if it's
    positive, non-WEAK_STRUCTURAL (capability-without-demonstrated-use can't
    justify TP alone, so it can't justify corroborating another PID either),
    and not itself the dimension a propagation step would add (excluded by
    name prefix) -- otherwise two otherwise-clean PIDs could bootstrap into
    mutual corroboration from the same propagation pass that's deciding
    whether to fire."""
    return any(d.positive and d.tier != Tier.WEAK_STRUCTURAL and
              not (exclude_prefix and d.name.startswith(exclude_prefix))
              for d in dims)


def _propagate_shared_infrastructure(verdicts: List[Verdict], findings: List[dict]) -> List[Verdict]:
    """Step 4: cross-PID shared-infrastructure corroboration (single pass, not
    iterated to a fixed point -- same bounded-and-simple design as the Windows
    engine's cross-PID handle-corroboration propagation).

    Two INDEPENDENT processes reaching the exact same non-private destination
    endpoint is a real lead worth pursuing rather than evaluating each PID in
    isolation: shared C2 infrastructure is a coincidence no more plausible
    than two unrelated implants happening to beacon to the same IP:port by
    chance. Deliberately conservative to avoid manufacturing suspicion from
    ordinary shared-service traffic (two clients hitting the same CDN edge):
    only propagates to a PID that ALREADY has at least one other positive
    dimension of its own -- this corroborates an existing lead, it does not
    invent one from network coincidence alone.
    """
    endpoint_pids: Dict[str, set] = defaultdict(set)
    for f in findings:
        if f.get('Type', '') not in _NETWORK_FINDING_TYPES:
            continue
        endpoint = _extract_dest_endpoint(f)
        if not endpoint:
            continue
        pid, _ = _parse_pid_target(f.get('Target', ''), f.get('Details', ''))
        if pid != HOST_SCOPE_PID:
            endpoint_pids[endpoint].add(pid)

    shared = {ep: pids for ep, pids in endpoint_pids.items() if len(pids) >= 2}
    if not shared:
        return verdicts

    out = []
    for v in verdicts:
        already_suspicious = _has_independent_positive(v.dimensions, exclude_prefix='M10_Network')
        if not already_suspicious:
            out.append(v)
            continue
        peers_by_endpoint = {ep: (pids - {v.pid}) for ep, pids in shared.items() if v.pid in pids}
        peers_by_endpoint = {ep: p for ep, p in peers_by_endpoint.items() if p}
        if not peers_by_endpoint:
            out.append(v)
            continue
        corroborations = [
            Dimension(
                name='M_SharedInfrastructure', positive=True, source_module=0,
                tier=Tier.STRONG_BEHAVIORAL,
                rationale=(f'Shares destination endpoint {ep} with independently-flagged PID(s) '
                           f'{", ".join(str(p) for p in sorted(peers))} -- two unrelated processes '
                           'reaching the exact same non-private endpoint is not plausible '
                           'coincidence; corroborates this PID\'s existing suspicious finding(s).')
            )
            for ep, peers in peers_by_endpoint.items()
        ]
        out.append(_assemble_verdict(v.pid, v.process, v.dimensions + corroborations, v.findings))
    return out


def _propagate_process_lineage(verdicts: List[Verdict], tree: Dict[int, object]) -> List[Verdict]:
    """Step 4b: direct parent/child lineage corroboration (see module
    docstring). ``tree`` is a pid -> node mapping with a ``.ppid`` attribute
    (process_tree.py's ProcessNode); called from correlator.py, which is
    where Adjudication_*.json's ParentPid data is available to build it.
    A no-op if tree is empty -- lineage data is best-effort, not required.

    Deliberately restricted to DIRECT parent/child edges, not the full
    ancestor/descendant chain chain_builder.py walks for narrative purposes:
    a legitimate process tree's parent-child edges are ubiquitous (everything
    has a parent), so "related to a suspicious PID" is worthless as a signal
    on its own -- only a direct edge where BOTH sides independently earned
    suspicion on their own separate merits is treated as corroborating,
    mirroring _propagate_shared_infrastructure's same-shape safeguard.
    """
    if not tree:
        return verdicts

    verdict_by_pid = {v.pid: v for v in verdicts}
    edges = [
        (node.ppid, pid) for pid, node in tree.items()
        if getattr(node, 'ppid', 0) and pid in verdict_by_pid and node.ppid in verdict_by_pid
        and pid != HOST_SCOPE_PID and node.ppid != HOST_SCOPE_PID
    ]
    if not edges:
        return verdicts

    already_suspicious = {
        pid: _has_independent_positive(v.dimensions, exclude_prefix='M_ProcessLineage')
        for pid, v in verdict_by_pid.items()
    }

    corroborating_peers: Dict[int, set] = defaultdict(set)
    for ppid, cpid in edges:
        if already_suspicious.get(ppid) and already_suspicious.get(cpid):
            corroborating_peers[ppid].add(cpid)
            corroborating_peers[cpid].add(ppid)

    if not corroborating_peers:
        return verdicts

    out = []
    for v in verdicts:
        peers = corroborating_peers.get(v.pid)
        if not peers:
            out.append(v)
            continue
        corroborations = [
            Dimension(
                name='M_ProcessLineage', positive=True, source_module=0,
                tier=Tier.STRONG_BEHAVIORAL,
                rationale=(f'Direct process-lineage edge with independently-flagged PID {peer} -- '
                           'a parent/child relationship where BOTH sides earned suspicion on their '
                           'own separate merits is not plausible coincidence in a legitimate process '
                           'tree; corroborates this PID\'s existing suspicious finding(s).')
            )
            for peer in sorted(peers)
        ]
        out.append(_assemble_verdict(v.pid, v.process, v.dimensions + corroborations, v.findings))
    return out


_HIDDEN_PROCESS_VOLUME_THRESHOLD = 3


def _cross_validate_hidden_process_volume(verdicts: List[Verdict]) -> List[Verdict]:
    """M2's pidhashtable-vs-pslist asymmetry is DEFINITIVE because, for a single frozen
    memory snapshot, no benign mechanism produces it -- but that claim assumes the
    comparison itself resolved correctly, which depends on the ISF matching the captured
    kernel (verdict.py's own documented limitation: this engine doesn't independently
    re-verify that match). Confirmed live: a run where this fired for 3+ unrelated,
    mundane, short-lived PIDs at once (a shell invocation, `id`, `ubuntu-report`, an
    accessibility daemon) is far more consistent with a kernel-symbol/context problem
    for THIS analysis run than a rootkit selectively hiding processes it has no
    adversarial reason to touch -- a rootkit hides what it needs hidden, not an
    arbitrary handful of unrelated utilities. Downgrades M2_HiddenProcess to
    STRONG_BEHAVIORAL once volume alone is implausible; a single hidden process (the
    normal, actionable case) is untouched."""
    flagged_pids = {v.pid for v in verdicts
                    if any(d.name == 'M2_HiddenProcess' and d.positive for d in v.dimensions)}
    if len(flagged_pids) < _HIDDEN_PROCESS_VOLUME_THRESHOLD:
        return verdicts
    out = []
    for v in verdicts:
        if v.pid not in flagged_pids:
            out.append(v)
            continue
        new_dims = []
        for d in v.dimensions:
            if d.name == 'M2_HiddenProcess' and d.positive:
                d = Dimension(
                    name='M2_HiddenProcess_VolumeDowngraded', positive=True,
                    tier=Tier.STRONG_BEHAVIORAL, source_module=d.source_module,
                    rationale=(f'{d.rationale} DOWNGRADED from DEFINITIVE: '
                              f'{len(flagged_pids)} independent PIDs carried this same '
                              'single-mechanism signal in this run -- volume argues '
                              'against "no benign mechanism" holding here specifically; '
                              'needs corroboration.'))
            new_dims.append(d)
        out.append(_assemble_verdict(v.pid, v.process, new_dims, v.findings))
    return out


def investigate(findings: List[dict]) -> List[Verdict]:
    """Accept findings from any Linux collector, return one Verdict per unique
    PID plus one host-scope Verdict (HOST_SCOPE_PID) for findings with no
    owning process."""
    pid_groups = _group_by_pid(findings)
    verdicts = [_investigate_pid(pid, pid_findings, findings)
               for pid, pid_findings in sorted(pid_groups.items())]
    verdicts = _cross_validate_hidden_process_volume(verdicts)
    return _propagate_shared_infrastructure(verdicts, findings)
