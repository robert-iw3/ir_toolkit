"""00_Collect-Forensics.ps1 -- structural tests (admin-gated live-host script, same
testing convention as Invoke-Eradication.ps1/EDR_Toolkit.ps1: text/regex assertions
against the source, since it cannot be safely dot-sourced or run without elevation).

Batch 3 item 6 (planning/CURRENT-STATE-AND-OPEN-ITEMS.md): re-auditing ground truth
found event-log collection was ~90% already done (4688/4624/4625/4648/4698/4702/4720/
1102/7045/104/4104/RDP all already exported and consumed) -- the one real gap was
4656/4663 (LSASS handle-open / object-access, the credential-theft detector): the
analysis logic in Invoke-EventLogAnalysis.ps1 already existed and was tested, but the
underlying events were never collected, so that branch could never fire on a real host.
"""
import re

from conftest import FORENSICS_PS1, read_text


def _src():
    return read_text(FORENSICS_PS1)


def test_forensics_script_exists_and_parses():
    import subprocess
    r = subprocess.run(
        ["pwsh", "-NoProfile", "-Command",
         f"$e=$null;$t=$null;[System.Management.Automation.Language.Parser]::ParseFile("
         f"'{FORENSICS_PS1}',[ref]$t,[ref]$e)|Out-Null;if($e.Count -eq 0){{'OK'}}else{{$e}}"],
        capture_output=True, text=True, timeout=30,
    )
    assert "OK" in r.stdout, f"Parse errors: {r.stdout}{r.stderr}"


def test_requires_admin():
    """Same admin-gate convention as Invoke-Eradication.ps1/EDR_Toolkit.ps1."""
    src = _src()
    assert "#Requires -RunAsAdministrator" in src


def test_is_read_only_by_design():
    src = _src()
    assert "Read-only" in src or "read-only" in src


def test_collects_all_event_ids_invoke_eventloganalysis_expects():
    """Every Read-EventCsv filename in Invoke-EventLogAnalysis.ps1 must have a
    corresponding Export-Csv (or equivalently-named) producer here -- a collection
    gap silently disables an otherwise fully-built, tested analysis branch."""
    from conftest import WIN_HUNT
    import os
    analysis_src = read_text(os.path.join(WIN_HUNT, "Invoke-EventLogAnalysis.ps1"))
    expected_files = set(re.findall(r"Read-EventCsv '([^']+)'", analysis_src))
    assert expected_files, "No Read-EventCsv calls found -- test itself is broken"

    src = _src()
    produced_files = set(re.findall(r'Export-Csv "\$WorkDir\\([^"]+\.csv)"', src))
    # events_$eid.csv is a variable-interpolated filename covering multiple IDs
    eid_loop_m = re.search(r'@\(([\d,\s]+)\)\s*\|\s*ForEach-Object\s*\{\s*\$eid\s*=\s*\$_', src)
    assert eid_loop_m, "Per-event-ID Security log collection loop not found"
    eids_collected = {int(x.strip()) for x in eid_loop_m.group(1).split(',')}

    missing = []
    for f in expected_files:
        if f in produced_files:
            continue
        eid_m = re.match(r'events_(\d+)\.csv', f)
        if eid_m and int(eid_m.group(1)) in eids_collected:
            continue
        missing.append(f)
    assert not missing, (
        f"Invoke-EventLogAnalysis.ps1 expects these event CSVs but 00_Collect-Forensics.ps1 "
        f"never produces them: {missing}"
    )


def test_lsass_handle_access_events_collected():
    """4656/4663 (LSASS handle-open / object-access) must be in the collected event
    ID set -- this was the confirmed gap disabling the credential-theft detector."""
    src = _src()
    eid_loop_m = re.search(r'@\(([\d,\s]+)\)\s*\|\s*ForEach-Object\s*\{\s*\$eid\s*=\s*\$_', src)
    assert eid_loop_m, "Per-event-ID Security log collection loop not found"
    eids = {int(x.strip()) for x in eid_loop_m.group(1).split(',')}
    assert 4656 in eids, "4656 (object access) missing from collected event IDs"
    assert 4663 in eids, "4663 (object access attempt) missing from collected event IDs"


def test_event_collection_is_count_bounded():
    """Every Get-WinEvent call in the event-log snapshot section must be bounded
    (-MaxEvents) -- unbounded collection on a busy Security log could be enormous."""
    src = _src()
    m = re.search(r'# -- Event log snapshot.*?(?=\n# -- [A-Z])', src, re.DOTALL)
    assert m, "Event log snapshot section not found"
    section = m.group(0)
    # Each Get-WinEvent...Export-Csv pair is one collection block; a call can span
    # multiple lines via backtick continuation OR a naturally-multi-line @{...}
    # hashtable (no backtick needed), so bound the search by the block's own
    # Export-Csv terminator rather than trying to regex a single call's extent.
    blocks = re.split(r'Export-Csv', section)[:-1]  # drop the tail after the last Export-Csv
    checked = 0
    for block in blocks:
        if 'Get-WinEvent' not in block:
            continue
        checked += 1
        assert '-MaxEvents' in block, f"Unbounded Get-WinEvent call in block: {block[-200:]}"
    assert checked, "No Get-WinEvent calls found in event log snapshot section"


def test_event_collection_never_clears_or_writes_logs():
    """Read-only by design -- must never call log-clearing or log-writing cmdlets."""
    src = _src()
    for forbidden in ('Clear-EventLog', 'wevtutil cl', 'Remove-EventLog', 'Write-EventLog'):
        assert forbidden not in src, f"Forbidden log-mutating call found: {forbidden}"


# ---------------------------------------------------------------------------
# Batch 3 item 7 -- ProcessTree_*.json snapshot
#
# process_tree.py / live_runner.py both already expected and consumed a dedicated
# 'ProcessTree_*.json' snapshot (Win32_Process: ProcessId/Name/ParentProcessId/
# CommandLine/ExecutablePath/CreationDate) at the report root -- confirmed nothing
# produced it. process_commandlines.csv already collects the exact same fields, just
# as CSV inside the zipped forensics-*.zip staging dir, not as JSON at the report root.
# ---------------------------------------------------------------------------

def test_processtree_json_written_to_outputdir_not_workdir():
    """Must land at $OutputDir (the report root process_tree.py/live_runner.py scan),
    NOT $WorkDir (the staging folder that gets zipped and Remove-Item'd)."""
    src = _src()
    m = re.search(r'\$procTreePath\s*=\s*Join-Path\s+(\$\w+)\s+"ProcessTree_', src)
    assert m, "ProcessTree_*.json path construction not found"
    assert m.group(1) == '$OutputDir', (
        f"ProcessTree_*.json must be joined under $OutputDir, not {m.group(1)} "
        "-- $WorkDir is zipped and deleted before the script exits"
    )


def test_processtree_json_uses_win32_process_field_names():
    """Field names must match process_tree.py's load_from_snapshot exactly
    (ProcessId, Name, ParentProcessId, CommandLine, ExecutablePath, CreationDate)."""
    src = _src()
    m = re.search(r'\$procSnapshot\s*=\s*Get-CimInstance Win32_Process.*?\n(?:.*\n){0,3}', src)
    assert m, "Win32_Process snapshot capture not found"
    block = m.group(0)
    for field in ('ProcessId', 'Name', 'ParentProcessId', 'CommandLine', 'ExecutablePath', 'CreationDate'):
        assert field in block, f"Field '{field}' missing from Win32_Process snapshot"


def test_processtree_json_force_wrapped_as_array():
    """PowerShell's ConvertTo-Json collapses a single-element array to a bare object --
    the exact bug fixed earlier in memory_enrich.py's load_usb_devices(). Must wrap in
    @(...) so a single-process result still serializes as a JSON array."""
    src = _src()
    assert '@($procSnapshot) | ConvertTo-Json' in src, (
        "ProcessTree_*.json must wrap the snapshot in @(...) before ConvertTo-Json to "
        "avoid the single-item-array-collapse bug (see load_usb_devices fix)"
    )


def test_processtree_json_named_with_incident_id():
    src = _src()
    assert 'ProcessTree_$IncidentId.json' in src


def test_process_tree_py_loader_still_matches_these_field_names():
    """Guard the other side of the contract: if process_tree.py's expected field names
    ever change, this collection code must change with it."""
    from conftest import PLAYBOOKS
    import os
    pt_src = read_text(os.path.join(PLAYBOOKS, "windows", "investigation", "process_tree.py"))
    for field in ("ProcessId", "ParentProcessId", "Name", "ExecutablePath", "CommandLine", "CreationDate"):
        assert field in pt_src, f"process_tree.py no longer references '{field}'"


# ---------------------------------------------------------------------------
# Batch 3 item 8 (named-pipe half) -- read-only pipe-name inventory.
#
# [[project-network-stack-incident]] (2026-06-26): 06_Network.ps1's live pipe
# enumeration via Get-ChildItem '\\.\pipe\' is the leading suspect for wedging a
# host's entire network stack; fixed there via [System.IO.Directory]::GetFiles
# (FindFirstFile/FindNextFile -- lists names without opening/connecting to any
# pipe). This is a different codepath (forensics snapshot, not the live hunt
# module) but touches the same OS surface, so it MUST reuse the identical
# proven-safe primitive and must never use Get-ChildItem on the pipe namespace.
# ---------------------------------------------------------------------------

def test_named_pipe_inventory_uses_directory_getfiles_not_get_childitem():
    src = _src()
    m = re.search(r'# -- Named pipe inventory.*?(?=\n# -- [A-Z])', src, re.DOTALL)
    assert m, "Named pipe inventory section not found"
    section = m.group(0)
    assert "[System.IO.Directory]::GetFiles(" in section, (
        "Named pipe inventory must use [System.IO.Directory]::GetFiles, the same "
        "FindFirstFile/FindNextFile primitive already proven safe in 06_Network.ps1"
    )
    assert r"pipe" in section.lower() and section.count("\\") >= 4, (
        "Expected a \\\\.\\pipe\\ style path literal in the GetFiles call"
    )
    code_lines = [ln for ln in section.splitlines() if not ln.strip().startswith('#')]
    assert not any('Get-ChildItem' in ln for ln in code_lines), (
        "Named pipe inventory must NEVER use Get-ChildItem on the pipe namespace -- "
        "this is the exact pattern implicated in the 2026-06-26 network-stack incident "
        "(a comment may reference it for context; actual code must not)"
    )


def test_named_pipe_inventory_is_names_only_no_content_read():
    """Must only extract the pipe NAME (Split-Path -Leaf), never attempt to open,
    read from, or write to the pipe itself."""
    src = _src()
    m = re.search(r'# -- Named pipe inventory.*?(?=\n# -- [A-Z])', src, re.DOTALL)
    assert m, "Named pipe inventory section not found"
    section = m.group(0)
    assert 'Split-Path -Leaf' in section
    for forbidden in ('Get-Content', 'New-Object System.IO.Pipes', 'NamedPipeClientStream', 'NamedPipeServerStream'):
        assert forbidden not in section, f"Named pipe inventory must not open pipes: found '{forbidden}'"


def test_named_pipe_inventory_wrapped_in_try_catch():
    """A pipe-namespace enumeration failure must never abort the whole collection run."""
    src = _src()
    m = re.search(r'# -- Named pipe inventory.*?(?=\n# -- [A-Z])', src, re.DOTALL)
    assert m, "Named pipe inventory section not found"
    assert 'try {' in m.group(0) and 'catch' in m.group(0)
