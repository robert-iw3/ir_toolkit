#!/usr/bin/env python3
"""
DC3-MWCP file scanner helper.

Invoked by memory_enrich.py (carved injected regions) and by the PowerShell
Invoke-MWCPFileScan function (flagged on-disk files). Handles:
  - Parser registration and file-type detection
  - Running appropriate parsers based on file type magic bytes
  - Correct mwcp 3.x API: mwcp.run(parser_name, file_path=path)
  - Tailing log appended to <out_dir>/mwcp_scan_log.txt after each file
  - JSON result output for caller consumption

Usage:
    python mwcp_scan.py <mwcp_lib_path> <file_path> [out_dir]

Output (stdout): JSON {"mutex":[...],"address":[...],"filename":[...],"password":[...]}
Tailing log: <out_dir>/mwcp_scan_log.txt (appended, never truncated)
"""

import sys, os, json, pkgutil
from datetime import datetime, timezone

def _setup(lib_path):
    if lib_path not in sys.path:
        sys.path.insert(0, lib_path)
    import mwcp
    mwcp.register_entry_points()
    return mwcp


def _detect_type(path):
    """Detect file type from magic bytes + extension."""
    try:
        with open(path, 'rb') as f:
            h = f.read(16)
    except Exception:
        return 'UNKNOWN'
    if h[:2] == b'MZ':                     return 'PE'
    if h[:4] == b'%PDF':                   return 'PDF'
    if h[:2] == b'PK':                     return 'ZIP'
    if h[:2] == b'\x1f\x8b':              return 'GZIP'
    if h[:4] in (b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe',
                 b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe'):
        return 'MACHO'
    ext = os.path.splitext(path)[1].lower()
    ext_map = {'.ps1': 'PS1', '.psm1': 'PS1', '.psd1': 'PS1',
               '.vbs': 'VBS', '.vbe': 'VBS', '.js': 'JS',
               '.hta': 'HTA', '.bat': 'BAT', '.cmd': 'BAT',
               '.wsf': 'WSF', '.wsh': 'WSF',
               '.lnk': 'LNK',
               '.py':  'PY',  '.rb':  'RB',  '.pl': 'PL',
               '.iso': 'ISO', '.img': 'ISO'}
    return ext_map.get(ext, 'UNKNOWN')


def _select_parsers(file_type, available):
    """Return ordered list of parsers to try for this file type.
    Generic parsers always run; type-specific parsers run first."""
    available_set = set(available)
    type_specific = {
        'PE':      ['CobaltStrikeConfig', 'Executable', 'GenericDropper'],
        'UNKNOWN': ['CobaltStrikeConfig'],  # carved memory regions (no MZ header)
        'PDF':     ['PDF'],
        'ZIP':     ['Archive'],
        'GZIP':    ['Archive'],
        'ISO':     ['ISO'],
        'PS1':     ['PowerShell', 'PowerShellDecoder'],
        'VBS':     ['VisualBasic', 'PowerShellDecoder'],
        'HTA':     ['PowerShellDecoder'],
        'BAT':     ['PowerShellDecoder'],
        'WSF':     ['PowerShellDecoder'],
        'LNK':     ['LNKParser', 'PowerShellDecoder'],
        'PY':      ['Python'],
        'MACHO':   ['MachO'],
    }
    # PowerShellDecoder also runs on all PE/script types that may embed PS stagers
    _ps_decoder_types = {'PE', 'PS1', 'VBS', 'HTA', 'BAT', 'WSF', 'LNK', 'UNKNOWN'}
    selected = []
    # 1. type-specific structural parsers
    for p in type_specific.get(file_type, []):
        if p in available_set:
            selected.append(p)
    # 2. generic parsers (always)
    for p in ('GenericMutex', 'GenericC2'):
        if p in available_set and p not in selected:
            selected.append(p)
    # 3. remaining family-specific parsers not yet in the list
    # Add PowerShellDecoder for types that commonly embed PS stagers
    if file_type in ('PE', 'HTA', 'BAT', 'WSF', 'UNKNOWN'):
        if 'PowerShellDecoder' in available and 'PowerShellDecoder' not in selected:
            selected.append('PowerShellDecoder')
    # Add LNKParser for LNK files (explicitly identified by magic bytes in detect_type)
    if file_type == 'LNK':
        if 'LNKParser' in available and 'LNKParser' not in selected:
            selected.append('LNKParser')
    known_generic = {'CobaltStrikeConfig','Executable','GenericDropper','PDF','Archive','ISO',
                     'PowerShell','VisualBasic','Python','MachO','RSA',
                     'GenericMutex','GenericC2','Decoy','Quarantined',
                     'PowerShellDecoder','LNKParser'}
    for p in available:
        if p not in known_generic and p not in selected:
            selected.append(p)
    return selected


def _extract_metadata(report_dict, out):
    """Pull fields from a mwcp as_dict() metadata list into our aggregated out dict."""
    for item in report_dict.get('metadata', []):
        t = item.get('type', '')
        tags = item.get('tags', [])

        # Mutexes
        if t == 'mutex':
            v = item.get('value', '')
            if v and v not in out['mutex']:
                out['mutex'].append(v)

        # C2 network indicators: socket (ip:port or domain), url, network (wrapper)
        elif t in ('socket', 'c2_address', 'c2_socketaddress', 'socketaddress'):
            v = item.get('address', '')
            if v and v not in out['address']:
                out['address'].append(v)
        elif t in ('url', 'c2_url', 'urlpath'):
            v = item.get('url', '')
            if v and v not in out['address']:
                out['address'].append(v)
        elif t == 'network':
            # network wraps both a socket and a url — extract the url
            url_obj = item.get('url') or {}
            if isinstance(url_obj, dict):
                v = url_obj.get('url', '')
                if v and v not in out['address']:
                    out['address'].append(v)

        # Filenames / file paths
        elif t in ('filename', 'filepath', 'path', 'file'):
            v = item.get('value', '') or item.get('path', '') or item.get('name', '')
            if v and v not in out['filename']:
                out['filename'].append(v)

        # Passwords / credentials
        elif t in ('password', 'credential'):
            pw = item.get('password', '') or item.get('value', '')
            if pw and pw not in out['password']:
                out['password'].append(pw)

        # Decoded strings (PowerShellDecoder output, future decoders)
        elif t == 'decoded_string':
            v = item.get('value', '')[:2000]
            if v and v not in out['decoded']:
                out['decoded'].append(v)

        # Other (registry paths, etc.) -- captured as address if it looks like an IOC
        elif t == 'registry':
            v = item.get('value', '')
            if v and v not in out['address']:
                out['address'].append(v)


def _run(mwcp_mod, meta, parsers_to_run, file_path):
    """Run each parser and aggregate results. Returns merged dict.
    Uses report.as_dict()['metadata'] -- the only stable extraction API in mwcp 3.x.
    report.metadata is a dict (iterating gives keys), report.get() silently drops items
    if the parser is not registered in parser_config.yml."""
    out = {'mutex': [], 'address': [], 'filename': [], 'password': [], 'decoded': []}

    for pname in parsers_to_run:
        try:
            report = mwcp_mod.run(pname, file_path=file_path)
            _extract_metadata(report.as_dict(), out)
        except Exception:
            continue  # parser didn't match this file type -- expected behaviour
    return out


def _append_log(out_dir, file_path, file_type, parsers_run, result):
    """Append one line to the tailing log so an interrupted scan is auditable."""
    if not out_dir:
        return
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, 'mwcp_scan_log.txt')
    ts   = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    fname = os.path.basename(file_path)
    has_finds = any(result.get(k) for k in result if k != 'decoded')
    # decoded strings are always noted but don't trigger MATCH unless combined with other finds
    has_decoded = bool(result.get('decoded'))
    status = 'MATCH' if has_finds else ('DECODED' if has_decoded else 'CLEAN')
    summary = ' | '.join(f'{k}={v}' for k, v in result.items() if v) or 'no config'
    line = f'[{ts}] [{status}] {fname} ({file_type}) parsers={",".join(parsers_run)} {summary}\n'
    try:
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(line)
    except Exception:
        pass


def main():
    """Batch mode: accepts one or more file paths.

    Usage (single file -- legacy):
        mwcp_scan.py <lib_path> <out_dir> <file_path>

    Usage (batch -- preferred, single Python process for many files):
        mwcp_scan.py <lib_path> <out_dir> <file1> <file2> <file3> ...

    Output: JSON array, one entry per file:
        [{"file": "path", "mutex": [...], "address": [...], ...}, ...]
    """
    if len(sys.argv) < 4:
        print(json.dumps([{'file': '', 'error':
              'Usage: mwcp_scan.py <lib_path> <out_dir> <file1> [file2 ...]\n'
              '       mwcp_scan.py <lib_path> <out_dir> --filelist <listfile>'}]))
        sys.exit(1)

    lib_path = sys.argv[1]
    out_dir  = sys.argv[2] if sys.argv[2] != '-' else None

    # --filelist <file> avoids Windows command-line length limit (32KB) for large directories.
    # The list file contains one file path per line (UTF-8, no extra whitespace).
    if sys.argv[3] == '--filelist' and len(sys.argv) == 5:
        list_file = sys.argv[4]
        try:
            with open(list_file, encoding='utf-8') as fh:
                file_paths = [l.strip() for l in fh if l.strip()]
        except Exception as e:
            print(json.dumps([{'file': '', 'error': f'Cannot read filelist {list_file}: {e}'}]))
            sys.exit(1)
    else:
        # Direct paths on argv (small batches where total length fits in the OS limit)
        file_paths = sys.argv[3:]

    try:
        mwcp = _setup(lib_path)
        import mwcp.metadata as meta
        import mwcp.parsers as mp_mod

        # Enumerate available parsers ONCE -- shared across all files in this batch
        available = [n for _, n, _ in pkgutil.iter_modules(mp_mod.__path__)
                     if not n.startswith('_') and n not in ('tests', 'foo')]

        results = []
        for file_path in file_paths:
            try:
                file_type      = _detect_type(file_path)
                parsers_to_run = _select_parsers(file_type, available)
                result         = _run(mwcp, None, parsers_to_run, file_path)
                _append_log(out_dir, file_path, file_type, parsers_to_run, result)
                results.append({'file': file_path, **result})
            except Exception as e:
                err = {'file': file_path, 'error': str(e)}
                _append_log(out_dir, file_path, 'ERROR', [], err)
                results.append(err)

        print(json.dumps(results))

    except Exception as e:
        print(json.dumps([{'file': '', 'error': str(e)}]))
        sys.exit(1)


if __name__ == '__main__':
    main()
