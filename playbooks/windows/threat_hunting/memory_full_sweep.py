#!/usr/bin/env python3
"""
*Pending live test and benchmark against a real image before merging into toolkit.

Full Memory Sweep -- standalone, opt-in, uncapped second pass over an already-collected
Windows memory image.

The fast pipeline (memory_forensic.py) caps how much of each process it inspects
(_ANON_EXEC_PER_PROC_CAP, _SYSCALL_PER_PROC_CAP, etc.) -- the right default for routine
triage, but a hard ceiling on what ever gets *seen*: a region past the cap is never
inspected in that run, not downgraded, not noted, invisible. Several mwcp parsers
(QakBotConfig, EmotedConfig, IcedIDConfig, RemcosConfig, ...) need no YARA/heuristic hit
to fire at all, but today never see bytes unless something else already flagged the PID.

This script closes that gap for an analyst doing a complete forensic pass who is willing
to trade runtime (multi-hour budget, expected) for certainty nothing was missed. It adds
NO new detection technique -- it walks every VAD of every process and runs the SAME YARA
ruleset and mwcp parsers the fast pass already has, just without the caps and without
gating mwcp on a prior YARA/module hit:

  - YARA: reuses memory_yara_worker.py exactly as memory_forensic.py's Module 19 does
    (same crash-isolated subprocess worker), just with a longer per-process timeout and
    no YARA_MAX_HITS-style cap on how many findings get emitted.
  - mwcp: the actual new capability. Every VAD (bounded only by the same CARVE_MAX size
    ceiling memory_yara_worker.py already carves to) is carved and batch-scanned via
    mwcp_scan.py --filelist, independent of whether it triggered a YARA hit first.
  - Region carving reuses memory_yara_worker.carve_region()'s exact sidecar schema --
    nothing here invents a second carve format.
  - Output uses the same Timestamp/Severity/Type/Target/Details/MITRE finding schema, so
    it flows into adjudication -> Combined_Findings -> the ML investigation engine
    unchanged. Only genuinely NEW findings (no prior-run corroboration) are emitted --
    regions the fast pass already flagged are summarized in the report, not re-emitted.

Never invoked by Analyze-Memory.ps1's default path. Usage:
    python memory_full_sweep.py <image> <output_dir> [options]

See planning/archived/WINDOWS-FULL-SWEEP-DESIGN.md for the full design rationale
(performance/fidelity tradeoff, batching numbers, phased implementation plan) and
planning/BACKLOG.md Batch 6 for current status.
"""
import argparse
import glob as _glob
import json
import os
import re
import shutil
import subprocess as _sp
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Both imports are vmmpyc-free (vmmpyc is only imported inside _bootstrap_vmmpyc(), never
# at module load) -- this keeps every pure helper below importable/unit-testable without a
# memory image, mirroring memory_yara_worker.py's own established convention.
from memory_yara_worker import carve_region, CARVE_MAX  # noqa: E402
import memory_yara as myara  # noqa: E402

KERNEL_PROCS = {  # separate copy, same set memory_forensic.py/memory_yara_worker.py each keep
    'system', 'secure system', 'registry', 'memory compression',
    'interrupts', 'idle', 'mssmbios', 'memcompression',
}

DEFAULT_MWCP_CHUNK_SIZE = 250      # files per mwcp_scan.py --filelist manifest
DEFAULT_YARA_TIMEOUT = 60          # seconds/process -- longer than the fast pass's 15s
DEFAULT_YARA_MAX_CRASH = 25
DEFAULT_MWCP_TIMEOUT = 1800        # seconds per --filelist batch call

SWEEP_MWCP_NOVEL_TYPE = "mwcp Sweep-Only Config Extraction (Memory)"
SWEEP_YARA_NOVEL_TYPE = "YARA Sweep-Only Match (Memory)"

_MWCP_EXTRACTION_FIELDS = ("mutex", "address", "filename", "password", "decoded")
_PID_RE = re.compile(r'PID\s+(\d+)')


# ============================================================================
# Pure helpers -- no vmmpyc, no network. Unit-testable directly (test_65_memory_full_sweep.py).
# ============================================================================

def is_kernel_proc(name, pid):
    return (name or "").lower() in KERNEL_PROCS or pid <= 8


def region_key(pid, base):
    """Canonical (pid, base_address) key, matching carve_region()'s own sidecar field
    formats exactly (str(pid), hex(base)) so cross-referencing against a prior carve
    manifest is an exact-string match, not a numeric-vs-string mismatch."""
    return (str(pid), hex(base))


def load_prior_carved_keys(carve_dir):
    """Read every *.json carve sidecar already written under carve_dir (from a PRIOR
    fast-pass or sweep run) and return the set of (pid, base_address) keys it covers.
    Missing/unreadable directory -> empty set (nothing to cross-reference against;
    everything found this run is then, correctly, treated as novel)."""
    keys = set()
    if not carve_dir or not os.path.isdir(carve_dir):
        return keys
    for jf in _glob.glob(os.path.join(carve_dir, "*.json")):
        try:
            with open(jf, encoding="utf-8") as fh:
                meta = json.load(fh)
            keys.add((str(meta["pid"]), str(meta["base_address"])))
        except Exception:
            continue
    return keys


def find_latest_carve_dir(binja_data_root):
    """Auto-discover the most recently modified stamp subdir under tools/binja/data/, for
    cross-referencing when the analyst doesn't pass --prior-carve-dir explicitly. None if
    binja_data_root doesn't exist or has no subdirectories."""
    if not os.path.isdir(binja_data_root):
        return None
    subdirs = [os.path.join(binja_data_root, d) for d in os.listdir(binja_data_root)
               if os.path.isdir(os.path.join(binja_data_root, d))]
    if not subdirs:
        return None
    return max(subdirs, key=os.path.getmtime)


def find_latest_findings_file(output_dir, exclude_pattern="FullSweep"):
    """Auto-discover the most recently modified Memory_Findings_*.json in output_dir that
    ISN'T a prior full-sweep's own output (excludes filenames containing exclude_pattern)
    -- the fast pass's own findings file, for the YARA pass's PID cross-reference."""
    candidates = [f for f in _glob.glob(os.path.join(output_dir, 'Memory_Findings_*.json'))
                  if exclude_pattern not in os.path.basename(f)]
    if not candidates:
        return None
    return max(candidates, key=os.path.getmtime)


def load_prior_flagged_pids(memory_findings_path):
    """Extract every PID already mentioned in a prior run's Memory_Findings_*.json Target
    field (e.g. 'PID 1234 (name.exe)') -- broader than the carve manifest (also covers
    non-carved findings, e.g. a file-backed YARA hit or any other memory_forensic.py
    module finding). Missing/unreadable/malformed file -> empty set."""
    pids = set()
    if not memory_findings_path or not os.path.isfile(memory_findings_path):
        return pids
    try:
        with open(memory_findings_path, encoding='utf-8') as fh:
            data = json.load(fh)
    except Exception:
        return pids
    for finding in (data or []):
        m = _PID_RE.search(str(finding.get('Target', '')))
        if m:
            pids.add(m.group(1))
    return pids


def classify_novelty(key, prior_keys):
    return "confirmed" if key in prior_keys else "sweep_only"


def iter_vad_candidates(vads, max_size=CARVE_MAX):
    """Filter a process's raw VAD list (dicts with start/end/protection/type -- the exact
    shape p.maps.vad() returns) down to carve candidates: non-empty, within the size
    ceiling. Yields (base, size, perms, vad_type) tuples. Deliberately does NOT filter by
    anon-vs-file or exec-vs-not -- the whole point of an uncapped sweep is every VAD gets
    the chance, unlike the fast pass's targeted anon-exec/syscall caps."""
    for v in (vads or []):
        try:
            start, end = int(v["start"]), int(v["end"])
        except Exception:
            continue
        size = end - start
        if size <= 0 or size > max_size:
            continue
        perms = v.get("protection", "") or ""
        vtype = str(v.get("type", "") or "").strip()
        yield start, size, perms, vtype


def count_oversize_vads(vads, max_size=CARVE_MAX):
    """How many VADs in a raw VAD list exceed max_size (for the sweep's oversize-skip
    stat) -- degenerate (zero/negative-size, unparseable) entries are not counted here,
    only genuinely-too-large ones."""
    n = 0
    for v in (vads or []):
        try:
            start, end = int(v["start"]), int(v["end"])
        except Exception:
            continue
        if end - start > max_size:
            n += 1
    return n


def resolve_backing_path(base, mods):
    """Loaded-module path backing address `base`, if any -- module entries carry
    .base/.image_size/.fullname/.name, same shape memory_yara_worker._addr_context() uses.
    Empty string if `base` falls in no loaded module (i.e. an anonymous/private region)."""
    for m in (mods or []):
        try:
            if m.base <= base < m.base + m.image_size:
                return m.fullname or m.name or ""
        except Exception:
            continue
    return ""


def chunk_list(items, size):
    """Split items into consecutive chunks of at most `size` -- generic batching helper for
    the mwcp --filelist manifests (keeps any single manifest's carve-directory disk
    footprint bounded, per the design doc's chunking guidance)."""
    items = list(items)
    if size <= 0:
        return [items] if items else []
    return [items[i:i + size] for i in range(0, len(items), size)]


def write_filelist_manifest(paths, manifest_path):
    """Write a mwcp_scan.py --filelist manifest: UTF-8, no BOM, one path per line --
    matches the exact convention EDR_Toolkit.ps1's Invoke-MWCPFileScan already writes."""
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as fh:
        for p in paths:
            fh.write(str(p) + "\n")
    return manifest_path


def parse_mwcp_batch_output(stdout_text):
    """Parse mwcp_scan.py's stdout (a single JSON array, one entry per scanned file).
    Returns [] on empty/unparseable output rather than raising -- a full sweep across tens
    of thousands of regions must not abort the whole run over one bad batch."""
    if not (stdout_text or "").strip():
        return []
    try:
        data = json.loads(stdout_text)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def mwcp_result_has_extraction(result):
    """True if an mwcp_scan.py per-file result dict actually extracted something (vs.
    every parser running clean with nothing to report)."""
    return any(result.get(f) for f in _MWCP_EXTRACTION_FIELDS)


def aggregate_mwcp_hits(mwcp_results, region_meta_by_path):
    """Group mwcp extraction hits by owning PID -- the 'repetition is not independence'
    rule applied up front (Module 3/20/23 each had to retrofit this after a PID with many
    regions produced one dimension per region instead of one per PID; a full sweep at
    10k+ regions would reproduce that bug class at much larger scale if not designed
    against from the start). Returns {pid: {"name", "regions": [...],
    "extractions": {field: set()}, "novel": bool, "confirmed": bool}}. Only PIDs backed by
    a known carved region (present in region_meta_by_path) are aggregated."""
    agg = {}
    for result in mwcp_results:
        if result.get("error") or not mwcp_result_has_extraction(result):
            continue
        meta = region_meta_by_path.get(result.get("file", ""))
        if not meta:
            continue
        pid = meta["pid"]
        entry = agg.setdefault(pid, {"name": meta["name"], "regions": [],
                                      "extractions": {f: set() for f in _MWCP_EXTRACTION_FIELDS},
                                      "novel": False, "confirmed": False})
        entry["regions"].append(meta["base_address"])
        if meta["novelty"] == "sweep_only":
            entry["novel"] = True
        else:
            entry["confirmed"] = True
        for f in _MWCP_EXTRACTION_FIELDS:
            for v in (result.get(f) or []):
                entry["extractions"][f].add(v)
    return agg


def aggregate_yara_hits(finished, prior_keys, prior_pids=frozenset()):
    """Group the YARA worker's per-PID hit records into novel-vs-confirmed, same
    aggregation discipline as aggregate_mwcp_hits. `finished` is memory_yara's own
    parse_worker_jsonl()['finished'] shape: [(pid, name, hits), ...]. YARA scans live
    process memory directly (not per-VAD carved files), so there's no per-hit base
    address to cross-reference here -- novelty is PID-level: a PID counts as novel unless
    it appears either in the prior run's carve manifest (`prior_keys`, (pid, base) tuples)
    or its Memory_Findings_*.json (`prior_pids`, plain pid strings -- broader, also
    catches non-carved findings like a file-backed YARA hit)."""
    prior_pids_combined = {str(pid) for pid, _ in prior_keys} | {str(p) for p in prior_pids}
    agg = {}
    for pid, name, hits in finished:
        real_hits = [h for h in hits if not myara.is_noise_rule(h.get("rule", ""))]
        if not real_hits:
            continue
        novel = str(pid) not in prior_pids_combined
        entry = agg.setdefault(pid, {"name": name, "rules": set(), "novel": novel})
        entry["rules"].update(h.get("rule", "") for h in real_hits)
    return agg


def build_mwcp_findings(agg):
    """One finding per PID, novel (sweep-only) hits only -- a PID already confirmed by the
    fast pass is summarized in the report, not re-emitted as a duplicate finding."""
    out = []
    for pid, entry in sorted(agg.items(), key=lambda kv: int(kv[0])):
        if not entry["novel"]:
            continue
        details = []
        for f in _MWCP_EXTRACTION_FIELDS:
            vals = sorted(entry["extractions"][f])
            if vals:
                shown = vals[:5]
                more = f" (+{len(vals) - 5} more)" if len(vals) > 5 else ""
                details.append(f"{f}: {', '.join(shown)}{more}")
        regions = sorted(set(entry["regions"]))
        shown_regions = ', '.join(regions[:5]) + ('...' if len(regions) > 5 else '')
        out.append({
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Severity": "High",
            "Type": SWEEP_MWCP_NOVEL_TYPE,
            "Target": f"PID {pid} ({entry['name']})",
            "Details": (f"{len(regions)} region(s) not seen by the fast pass ({shown_regions}) | "
                        + (" | ".join(details) if details else "structural match, no fields decoded")),
            "MITRE": "T1055 (Process Injection), T1027 (Obfuscated Files)",
        })
    return out


def build_yara_findings(agg):
    """One finding per PID with a YARA hit that has no prior-run corroboration."""
    out = []
    for pid, entry in sorted(agg.items(), key=lambda kv: int(kv[0])):
        if not entry["novel"]:
            continue
        rules = sorted(entry["rules"])
        shown = ", ".join(rules[:10]) + ("..." if len(rules) > 10 else "")
        out.append({
            "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Severity": "High",
            "Type": SWEEP_YARA_NOVEL_TYPE,
            "Target": f"PID {pid} ({entry['name']})",
            "Details": f"{len(rules)} rule(s) matched with no prior-run corroboration: {shown}",
            "MITRE": "T1055 (Process Injection), T1027 (Obfuscated Files)",
        })
    return out


def write_findings_json(findings, output_dir, stamp):
    path = os.path.join(output_dir, f"Memory_Findings_FullSweep_{stamp}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    return path


def promote_novel_regions(region_meta_by_path, novel_pids, scratch_dir, carve_root):
    """Copy the carved .bin+.json pair for every region belonging to a PID that ended up
    in a novel (sweep-only) finding from scratch_dir into the permanent carve_root --
    confirmed-only regions stay scratch-only and are discarded at cleanup, matching the
    design doc's 'only promote genuinely new regions to tools/binja/data/' rule. Returns
    the list of promoted .bin basenames."""
    promoted = []
    if not novel_pids:
        return promoted
    for binp, meta in region_meta_by_path.items():
        if meta['pid'] not in novel_pids:
            continue
        os.makedirs(carve_root, exist_ok=True)
        for src in (binp, binp[:-4] + '.json'):
            if os.path.isfile(src):
                shutil.copy2(src, os.path.join(carve_root, os.path.basename(src)))
        promoted.append(os.path.basename(binp))
    return promoted


def render_summary_report(stats):
    """Markdown Full_Sweep_Report_<stamp>.md body. Pure string-building, no I/O -- caller
    writes it out, keeping this testable by asserting on the returned string."""
    lines = [
        f"# Full Memory Sweep Report -- {stats.get('stamp', '')}",
        "",
        f"- Image: `{stats.get('image', '?')}`",
        f"- Processes scanned: {stats.get('processes_scanned', 0)}"
        + (f" ({stats['kernel_excluded']} kernel/system excluded)" if stats.get('kernel_excluded') else ""),
        f"- VADs enumerated: {stats.get('regions_enumerated', 0)}",
        f"- Regions carved for mwcp: {stats.get('regions_carved', 0)}"
        + (f" ({stats['regions_oversize_skipped']} skipped, over the "
           f"{stats.get('carve_max_mb', 64)}MB cap)" if stats.get('regions_oversize_skipped') else ""),
        "",
        "## YARA",
        f"- PIDs with hits already confirmed by the fast pass: {stats.get('yara_confirmed_pids', 0)}",
        f"- PIDs with hits found ONLY by this sweep: {stats.get('yara_sweep_only_pids', 0)}",
        "",
        "## mwcp",
        f"- PIDs with extractions already confirmed by the fast pass: {stats.get('mwcp_confirmed_pids', 0)}",
        f"- PIDs with extractions found ONLY by this sweep: {stats.get('mwcp_sweep_only_pids', 0)}",
        "",
        "## Findings written",
        f"- {stats.get('findings_written', 0)} new finding(s) -> `{stats.get('findings_path', '(none)')}`",
        "",
        f"Elapsed: {stats.get('elapsed_seconds', 0):.1f}s",
    ]
    if stats.get('yara_trust_message'):
        lines += ["", f"YARA self-test: {stats['yara_trust_message']}"]
    return "\n".join(lines) + "\n"


def write_summary_report(path, stats):
    body = render_summary_report(stats)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path


# ============================================================================
# Orchestration -- touches vmmpyc/subprocess. Not unit tested directly (same convention
# as memory_yara_worker.main()/memory_forensic.py's top-level flow); exercised by a live
# image run instead, per planning/BACKLOG.md Batch 6's phased plan.
# ============================================================================

def _bootstrap_vmmpyc():
    mpc_dir = str(Path(__file__).parent.parent.parent.parent / 'tools' / 'memprocfs')
    py_dir = os.path.join(mpc_dir, 'python')
    os.add_dll_directory(mpc_dir)
    sys.path.insert(0, mpc_dir)
    for z in _glob.glob(os.path.join(py_dir, 'python3*.zip')):
        if z not in sys.path:
            sys.path.insert(0, z)
    if py_dir not in sys.path:
        sys.path.append(py_dir)
    import vmmpyc
    return vmmpyc, mpc_dir


def _find_python_and_mwcp_lib(mpc_dir, mwcp_lib_override=None):
    repo_root = Path(mpc_dir).parent.parent
    py_exe = os.path.join(mpc_dir, 'python', 'python.exe')
    if not os.path.isfile(py_exe):
        py_exe = sys.executable
    lib_path = mwcp_lib_override or str(repo_root / 'tools' / 'mwcp' / 'lib')
    return py_exe, lib_path


def run_sweep(args):
    """Full orchestration: opens the image, walks every process/VAD, runs the uncapped
    YARA pass (via the existing crash-isolated memory_yara_worker.py subprocess) and the
    mwcp pass (carve every VAD, batch-scan via mwcp_scan.py --filelist), cross-references
    against a prior carve manifest + findings file, aggregates per-PID, and writes
    findings + a summary report. Returns a process exit code (0 = ran to completion)."""
    t0 = datetime.now()
    stamp = t0.strftime('%Y%m%d_%H%M%S')
    os.makedirs(args.output_dir, exist_ok=True)

    log_path = os.path.join(args.output_dir, f'_FullSweep_{stamp}.log')

    def log(msg, lvl='INFO'):
        ts = datetime.now().strftime('%H:%M:%S')
        line = f'[{ts}] [{lvl}] {msg}'
        print(line)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(line + '\n')

    log(f'Full Memory Sweep starting: {args.image}')
    vmmpyc, mpc_dir = _bootstrap_vmmpyc()
    try:
        vmm = vmmpyc.Vmm(['-device', args.image, '-disable-symbolserver', '-disable-python'])
    except Exception as e:
        log(f'Failed to open image: {e}', 'ERROR')
        return 1

    procs = vmm.process_list()
    kernel_excluded = 0
    scannable = []
    for p in procs:
        if not args.include_kernel and is_kernel_proc(p.name, p.pid):
            kernel_excluded += 1
            continue
        scannable.append(p)
    log(f'Processes: {len(procs)} total, {len(scannable)} scannable'
        + (f' ({kernel_excluded} kernel/system excluded)' if kernel_excluded else ''))

    carve_root = args.carve_dir or os.environ.get('IR_CARVE_DIR') \
        or str(Path(mpc_dir).parent.parent / 'tools' / 'binja' / 'data' / stamp)
    prior_carve_dir = args.prior_carve_dir or find_latest_carve_dir(str(Path(carve_root).parent))
    prior_keys = load_prior_carved_keys(prior_carve_dir) if prior_carve_dir else set()
    prior_findings_path = args.prior_findings or find_latest_findings_file(args.output_dir)
    prior_pids = load_prior_flagged_pids(prior_findings_path)
    log(f'Cross-referencing against: carve manifest {prior_carve_dir or "(none found)"} '
        f'({len(prior_keys)} region(s)), findings {prior_findings_path or "(none found)"} '
        f'({len(prior_pids)} PID(s))')

    scratch_dir = args.scratch_dir or tempfile.mkdtemp(prefix='ir_fullsweep_')
    region_meta_by_path = {}
    regions_enumerated = 0
    regions_carved = 0
    regions_oversize = 0

    for p in scannable:
        try:
            vads = p.maps.vad()
        except Exception:
            vads = []
        try:
            mods = p.module_list()
        except Exception:
            mods = []
        regions_enumerated += len(vads or [])
        regions_oversize += count_oversize_vads(vads, args.max_region_size)
        for base, size, perms, vtype in iter_vad_candidates(vads, args.max_region_size):
            try:
                data = p.memory.read(base, size)
            except Exception:
                data = b''
            if not data:
                continue
            path = resolve_backing_path(base, mods)
            region = myara.vad_region(vtype, path)
            binp = carve_region(scratch_dir, args.image, p.pid, p.name, base, data,
                                 perms, region, vtype, path, [])
            if not binp:
                continue
            regions_carved += 1
            key = region_key(p.pid, base)
            region_meta_by_path[binp] = {
                'pid': str(p.pid), 'name': p.name, 'base_address': hex(base),
                'novelty': classify_novelty(key, prior_keys),
            }

    log(f'VADs enumerated: {regions_enumerated}, carved for mwcp: {regions_carved} '
        f'({regions_oversize} skipped over the {args.max_region_size // (1024 * 1024)}MB cap)')

    # ---- mwcp pass: batch-scan every carved region ----
    py_exe, mwcp_lib = _find_python_and_mwcp_lib(mpc_dir, args.mwcp_lib)
    mwcp_scan_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'mwcp_scan.py')
    mwcp_agg = {}
    if os.path.isdir(mwcp_lib) and os.path.isfile(mwcp_scan_py) and region_meta_by_path:
        all_paths = list(region_meta_by_path.keys())
        mwcp_results = []
        for i, chunk in enumerate(chunk_list(all_paths, args.mwcp_chunk_size)):
            manifest = os.path.join(scratch_dir, f'_mwcp_manifest_{i}.txt')
            write_filelist_manifest(chunk, manifest)
            try:
                r = _sp.run([py_exe, mwcp_scan_py, mwcp_lib, '-', '--filelist', manifest],
                            stdout=_sp.PIPE, stderr=_sp.PIPE, timeout=args.mwcp_timeout)
                mwcp_results.extend(parse_mwcp_batch_output(r.stdout.decode('utf-8', errors='replace')))
            except Exception as e:
                log(f'  mwcp batch {i} failed: {e}', 'WARN')
        mwcp_agg = aggregate_mwcp_hits(mwcp_results, region_meta_by_path)
        log(f'mwcp: {len(mwcp_results)} region(s) scanned, {len(mwcp_agg)} PID(s) with extractions')
    else:
        log('  SKIP mwcp pass: lib not staged, worker missing, or nothing carved', 'WARN')

    # ---- YARA pass: reuse the same crash-isolated worker the fast pass uses, uncapped ----
    yara_agg = {}
    yara_trust_message = None
    yarac_exe = args.yarac or str(Path(mpc_dir).parent / 'yarac64.exe')
    rules_dir = args.rules_dir or str(Path(mpc_dir).parent / 'yara_rules')
    yara_worker = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'memory_yara_worker.py')
    if os.path.isdir(rules_dir) and os.path.isfile(yarac_exe) and os.path.isfile(yara_worker):
        all_rules = myara.filter_windows_rules(myara.exclude_memory_noise(
            myara.collect_rule_files(rules_dir)))
        canary_src = os.path.join(args.output_dir, f'_yara_canary_fullsweep_{stamp}.yar')
        with open(canary_src, 'w', encoding='utf-8') as cf:
            cf.write(myara.canary_rule_source())
        yac = os.path.join(args.output_dir, f'_yara_fullsweep_{stamp}.yac')
        yac_path, n_ok, n_fail = myara.compile_ruleset(all_rules + [canary_src], yarac_exe, yac)
        if yac_path:
            results_path = os.path.join(args.output_dir, f'_yara_fullsweep_results_{stamp}.jsonl')
            open(results_path, 'w').close()
            skip, crashes, summary = set(), 0, None
            for _attempt in range(args.yara_max_crash + 1):
                _sp.call([sys.executable, yara_worker, args.image, yac_path, results_path,
                          ','.join(str(s) for s in sorted(skip)), mpc_dir, str(args.yara_timeout)])
                with open(results_path, encoding='utf-8') as rf:
                    summary = myara.parse_worker_jsonl(rf.read().splitlines())
                if summary['done']:
                    break
                bad = myara.crashing_pid(summary['started_pids'], summary['finished_pids'] | skip)
                if bad is None:
                    break
                skip.add(bad)
                skip |= summary['finished_pids']
                crashes += 1
                log(f'  YARA worker crashed on PID {bad} -- skipping and resuming', 'WARN')
            if summary is not None:
                yara_agg = aggregate_yara_hits(summary['finished'], prior_keys, prior_pids)
                verdict = myara.yara_trust_verdict(len(summary['finished_pids']),
                                                    summary['canary_hits'], crashes)
                yara_trust_message = verdict['message']
                log(f'  {yara_trust_message}', 'INFO' if verdict['trusted'] else 'ERROR')
            for f in (yac_path, canary_src):
                try:
                    os.unlink(f)
                except OSError:
                    pass
        else:
            log('  SKIP YARA pass: ruleset failed to compile', 'WARN')
    else:
        log('  SKIP YARA pass: rules dir, yarac64.exe, or worker not staged', 'WARN')

    # ---- Aggregate, promote novel carves, write output ----
    findings = build_mwcp_findings(mwcp_agg) + build_yara_findings(yara_agg)
    findings_path = write_findings_json(findings, args.output_dir, stamp) if findings else None

    novel_pids = {pid for pid, e in mwcp_agg.items() if e['novel']}
    promoted = promote_novel_regions(region_meta_by_path, novel_pids, scratch_dir, carve_root)
    if promoted:
        log(f'Promoted {len(promoted)} sweep-only region(s) to {carve_root}')

    elapsed = (datetime.now() - t0).total_seconds()
    stats = {
        'stamp': stamp, 'image': args.image, 'processes_scanned': len(scannable),
        'kernel_excluded': kernel_excluded, 'regions_enumerated': regions_enumerated,
        'regions_carved': regions_carved, 'regions_oversize_skipped': regions_oversize,
        'carve_max_mb': args.max_region_size // (1024 * 1024),
        'yara_confirmed_pids': sum(1 for e in yara_agg.values() if not e['novel']),
        'yara_sweep_only_pids': sum(1 for e in yara_agg.values() if e['novel']),
        'mwcp_confirmed_pids': sum(1 for e in mwcp_agg.values() if e['confirmed'] and not e['novel']),
        'mwcp_sweep_only_pids': sum(1 for e in mwcp_agg.values() if e['novel']),
        'findings_written': len(findings), 'findings_path': findings_path or '(none)',
        'elapsed_seconds': elapsed, 'yara_trust_message': yara_trust_message,
    }
    report_path = os.path.join(args.output_dir, f'Full_Sweep_Report_{stamp}.md')
    write_summary_report(report_path, stats)
    log(f'Report: {report_path}')
    log(f'Done in {elapsed:.1f}s. {len(findings)} new finding(s) written'
        + (f' -> {findings_path}' if findings_path else ' (nothing novel found).'))

    if not args.keep_scratch and not args.scratch_dir:
        shutil.rmtree(scratch_dir, ignore_errors=True)

    return 0


def build_arg_parser():
    p = argparse.ArgumentParser(
        prog='memory_full_sweep.py',
        description="Opt-in, uncapped second pass over an already-collected memory image: "
                    "every VAD, same YARA ruleset + mwcp parsers as the fast pass, no caps. "
                    "Analyst-initiated final-verification step -- never run by default.")
    p.add_argument('image', help='Path to the memory image (.aff4/.raw/.mem/.dmp)')
    p.add_argument('output_dir', help='Directory for findings/report/log output')
    p.add_argument('--rules-dir', default=None, help='Override YARA rules dir (default: tools/yara_rules)')
    p.add_argument('--yarac', default=None, help='Override yarac64.exe path')
    p.add_argument('--mwcp-lib', default=None, help='Override mwcp lib path (default: tools/mwcp/lib)')
    p.add_argument('--carve-dir', default=None,
                    help="This run's permanent carve output for novel regions "
                         "(default: $IR_CARVE_DIR or tools/binja/data/<stamp>)")
    p.add_argument('--prior-carve-dir', default=None,
                    help="Directory of a prior run's carve sidecars to cross-reference against "
                         "(default: auto-detect the most recently modified tools/binja/data/<stamp>)")
    p.add_argument('--prior-findings', default=None,
                    help='Prior Memory_Findings_*.json to cross-reference PIDs against '
                         '(default: auto-detect the most recent one in output_dir)')
    p.add_argument('--scratch-dir', default=None,
                    help='Scratch carve staging dir (default: a temp dir, deleted at the end '
                         'unless --keep-scratch)')
    p.add_argument('--keep-scratch', action='store_true', help='Do not delete the scratch carve dir')
    p.add_argument('--include-kernel', action='store_true',
                    help='Also scan kernel/system pseudo-processes (System, Registry, ...) '
                         '-- low value, off by default')
    p.add_argument('--max-region-size', type=int, default=CARVE_MAX,
                    help=f'Per-VAD size ceiling in bytes for carving (default: {CARVE_MAX})')
    p.add_argument('--mwcp-chunk-size', type=int, default=DEFAULT_MWCP_CHUNK_SIZE,
                    help='Files per mwcp_scan.py --filelist manifest (default: %(default)s)')
    p.add_argument('--mwcp-timeout', type=int, default=DEFAULT_MWCP_TIMEOUT,
                    help='Timeout in seconds for each mwcp --filelist batch call (default: %(default)s)')
    p.add_argument('--yara-timeout', type=int, default=DEFAULT_YARA_TIMEOUT,
                    help="Per-process YARA scan abort timeout in seconds "
                         "(default: %(default)s, longer than the fast pass's 15s)")
    p.add_argument('--yara-max-crash', type=int, default=DEFAULT_YARA_MAX_CRASH,
                    help='Crash-retry budget for the YARA worker (default: %(default)s)')
    return p


def main():
    args = build_arg_parser().parse_args()
    sys.exit(run_sweep(args))


if __name__ == '__main__':
    main()
