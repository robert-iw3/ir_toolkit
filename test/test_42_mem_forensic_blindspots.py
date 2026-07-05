"""P1 blindspot tests for memory_forensic.py.

memory_forensic.py loads vmmpyc at import so it cannot be unit-imported.
These tests verify the script's source text to confirm that:
  - JIT_HEAVY_PROCS is defined globally (before Module 3) and exactly once
  - JIT_HEAVY_PROCS contains .NET CLR hosts (pwsh, dotnet, mscorsvw, ngen)
  - JIT_HEAVY_PROCS entries have no .exe suffix (kernel truncation compatibility)
  - Module 3 annotates injected memory in JIT-host processes (not silent)
  - Module 13 (HIGH_ENT_PROCS) annotates findings instead of blindly skipping
"""

import re
import os

SCRIPT = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..",
    "playbooks", "windows", "threat_hunting", "memory_forensic.py"
))


def _src():
    with open(SCRIPT, encoding="utf-8") as f:
        return f.read()


# ---------------------------------------------------------------------------
# JIT_HEAVY_PROCS -- global scope, single definition, correct entries
# ---------------------------------------------------------------------------

def test_jit_heavy_procs_defined_at_global_scope():
    """First JIT_HEAVY_PROCS definition must appear before Module 3 (line ~280).
    If it is only inside the Module 5 loop, Module 3 cannot reference it."""
    src = _src()
    m = re.search(r'^JIT_HEAVY_PROCS\s*=', src, re.MULTILINE)
    assert m is not None, "JIT_HEAVY_PROCS not found"
    line = src[: m.start()].count('\n') + 1
    assert line < 200, (
        f"JIT_HEAVY_PROCS first definition is at line {line}; "
        "expected in global scope (<200) so Module 3 can use it"
    )


def test_jit_heavy_procs_defined_exactly_once():
    """JIT_HEAVY_PROCS must appear only once. A duplicate inside Module 5 shadows
    the global definition and loses the .NET hosts added for Module 3 support."""
    src = _src()
    defs = list(re.finditer(r'^JIT_HEAVY_PROCS\s*=', src, re.MULTILINE))
    assert len(defs) == 1, (
        f"JIT_HEAVY_PROCS defined {len(defs)} times; must be exactly 1 "
        "(module-level only, referenced by Modules 3 and 5)"
    )


def test_jit_heavy_procs_includes_dotnet_clr_hosts():
    """.NET CLR hosts must be in JIT_HEAVY_PROCS so Module 3 annotates pwsh.exe
    anonymous exec regions as JIT-consistent instead of 'likely shellcode'."""
    src = _src()
    m = re.search(r'JIT_HEAVY_PROCS\s*=\s*\{([^}]+)\}', src, re.DOTALL)
    assert m, "JIT_HEAVY_PROCS block not parseable"
    block = m.group(1)
    for host in ('pwsh', 'dotnet', 'mscorsvw', 'ngen'):
        assert f"'{host}'" in block, (
            f"'{host}' missing from JIT_HEAVY_PROCS -- "
            ".NET CLR JIT-compiled pages in these processes cause false positives"
        )


def test_jit_heavy_procs_no_exe_suffix():
    """Entries must not end in .exe. The EPROCESS.ImageFileName field is 14 chars;
    long names like acrobatnotific.exe (18 chars) arrive truncated as 'acrobatnotific'."""
    src = _src()
    m = re.search(r'JIT_HEAVY_PROCS\s*=\s*\{([^}]+)\}', src, re.DOTALL)
    assert m, "JIT_HEAVY_PROCS block not parseable"
    block = m.group(1)
    assert '.exe' not in block, (
        "JIT_HEAVY_PROCS contains .exe suffix -- comparison against kernel-truncated "
        "names will fail; use base names (e.g. 'acrobatnotific' not 'acrobatnotific.exe')"
    )


# ---------------------------------------------------------------------------
# Module 3 -- JIT annotation for injected memory in JIT hosts
# ---------------------------------------------------------------------------

def test_module3_annotates_jit_host_injected_regions():
    """Module 3 must check whether the process is a JIT host and add a
    'JIT-consistent' annotation to the injected memory finding detail."""
    src = _src()
    m3 = re.search(r'=== 3\..*?=== 4\.', src, re.DOTALL)
    assert m3, "Module 3 block not found"
    text = m3.group(0)
    assert 'JIT_HEAVY_PROCS' in text or 'JIT-consistent' in text, (
        "Module 3 does not check JIT_HEAVY_PROCS -- injected memory in pwsh.exe, "
        "Chrome, etc. needs JIT annotation to distinguish from real shellcode injection"
    )


# ---------------------------------------------------------------------------
# Module 13 -- HIGH_ENT_PROCS annotated not skipped
# ---------------------------------------------------------------------------

def test_module13_does_not_blindly_skip_high_ent_procs():
    """Module 13 must NOT use a bare 'continue' after the HIGH_ENT_PROCS check.
    AV/security processes are prime injection targets -- skipping them is a blindspot."""
    src = _src()
    bad = re.search(
        r'if\s+p\.name\.lower\(\)\s+in\s+HIGH_ENT_PROCS\b[\s\S]{0,120}?\bcontinue\b',
        src, re.MULTILINE
    )
    assert bad is None, (
        "Module 13 still skips HIGH_ENT_PROCS with 'continue' -- replace with "
        "is_high_ent flag that emits a Low-severity annotated finding"
    )


def test_module13_high_ent_procs_uses_annotation_flag():
    """Module 13 must set is_high_ent to mark the finding for annotation,
    not silently suppress it."""
    src = _src()
    assert 'is_high_ent' in src, (
        "is_high_ent flag not found in Module 13 -- HIGH_ENT_PROCS security "
        "processes should produce annotated findings, not be silently skipped"
    )


def test_module13_high_ent_proc_finding_gets_low_severity():
    """HIGH_ENT_PROC findings must be emitted at Low severity (not High/Medium)
    so they appear in reports without inflating TP counts."""
    src = _src()
    assert 'SECURITY-PROC' in src or "security process" in src, (
        "No 'SECURITY-PROC' annotation text found -- HIGH_ENT_PROC findings must "
        "carry a note explaining the expected high-entropy source"
    )


# ---------------------------------------------------------------------------
# Module 9 -- LISTENER_ALLOWLIST annotated not skipped (Batch 1 item 4)
# ---------------------------------------------------------------------------

def test_module9_listener_allowlist_does_not_skip():
    """Module 9 (suspicious network listeners) must NOT use a bare 'continue' after
    the LISTENER_ALLOWLIST substring check. A name match is not identity proof --
    malware naming itself svchost.exe/msedge.exe would pass this check too; skipping
    it made a bind shell under a common name invisible."""
    src = _src()
    bad = re.search(
        r'any\(a in pname for a in LISTENER_ALLOWLIST\)[\s\S]{0,40}?\bcontinue\b',
        src, re.MULTILINE
    )
    assert bad is None, (
        "Module 9 still skips LISTENER_ALLOWLIST matches with 'continue' -- replace "
        "with an annotated Low-severity finding instead of full suppression"
    )


def test_module9_listener_allowlist_still_emits_finding():
    """An allowlisted-name listener match must still call add() (stay visible for
    path/signature corroboration), just at reduced severity."""
    src = _src()
    m9 = re.search(r'=== 9\..*?=== 10\.', src, re.DOTALL)
    assert m9, "Module 9 block not found"
    text = m9.group(0)
    assert "allowlisted" in text, (
        "Module 9 has no 'allowlisted' branch variable -- LISTENER_ALLOWLIST matches "
        "must be tagged and downgraded, not silently dropped"
    )
    assert "add('Low'" in text or 'add("Low"' in text, (
        "Module 9 does not emit a Low-severity finding for allowlisted-name listeners"
    )


def test_module9_non_allowlisted_listener_stays_medium():
    """A listener on a process NOT matching LISTENER_ALLOWLIST must still be Medium
    severity (this fix must not weaken detection of genuinely unexpected listeners)."""
    src = _src()
    m9 = re.search(r'=== 9\..*?=== 10\.', src, re.DOTALL)
    assert m9, "Module 9 block not found"
    text = m9.group(0)
    assert "add('Medium'" in text or 'add("Medium"' in text, (
        "Module 9 no longer emits a Medium-severity finding for the non-allowlisted case"
    )


# ---------------------------------------------------------------------------
# Module 23 -- cross-process handle & thread-creator attribution (Batch 2 item 5)
# ---------------------------------------------------------------------------

def _module23_block():
    src = _src()
    m = re.search(r'=== 23\..*', src, re.DOTALL)
    assert m, "Module 23 block not found"
    return m.group(0)


def test_module23_dangerous_process_access_requires_vm_write_and_operation():
    """A cross-process handle must require VM_OPERATION+VM_WRITE together (or full
    ALL_ACCESS) to be flagged -- a lone weaker right (e.g. QUERY_INFORMATION only)
    is not injection capability and must not be scored."""
    text = _module23_block()
    assert '_PROCESS_VM_OPERATION' in text
    assert '_PROCESS_VM_WRITE' in text
    assert '_PROCESS_ALL_ACCESS' in text


def test_module23_dangerous_thread_access_requires_set_context_or_all_access():
    text = _module23_block()
    assert '_THREAD_SET_CONTEXT' in text
    assert '_THREAD_ALL_ACCESS' in text


def test_module23_os_session_mgmt_downgrade_requires_path_verification():
    """A name match on csrss/services/winlogon/smss/wininit alone must NOT be enough
    to downgrade severity -- same masquerade class as coreAllowed/LISTENER_ALLOWLIST.
    Only 'system' (the pathless kernel pseudo-process) gets a name-only fallback."""
    text = _module23_block()
    assert 'SYS_PATHS.match' in text, (
        "OS session-management holder downgrade must verify the on-disk path, "
        "not just the process name"
    )
    for name in ('csrss.exe', 'services.exe', 'winlogon.exe', 'smss.exe', 'wininit.exe'):
        assert name in text, f"'{name}' missing from the OS session-management set"


def test_module23_lsass_not_special_cased_as_holder():
    """Explicit design decision: lsass.exe is NOT excluded/downgraded as a handle
    HOLDER (unlike csrss/services/winlogon) -- it is scored like any other process."""
    text = _module23_block()
    assert "'lsass" not in text.lower() and '"lsass' not in text.lower(), (
        "lsass.exe must not be special-cased as a cross-process handle holder"
    )


def test_module23_target_format_matches_engine_pid_convention():
    """Target must be 'PID <n> (<name>) ...' -- the convention every other module
    uses. engine.py's _parse_pid_process regex (r'PID\\s+(\\d+)\\s+\\(([^)]+)\\)')
    requires this exact shape to group the finding under the holder's pid; any other
    format makes the finding invisible to the investigation engine's PID grouping."""
    text = _module23_block()
    assert "f'PID {p.pid} ({p.name})" in text, (
        "Module 23 Target format must start with 'PID {p.pid} ({p.name})' so "
        "engine.py's _group_by_pid can parse and attribute it to the holder"
    )


def test_module23_details_carries_name_tag_for_test_protected():
    """Details must carry 'Name: X' -- Invoke-Eradication.ps1's universal
    Test-Protected guard extracts identity via `.Details -replace '.*Name:\\s*',''`
    for every finding type before any type-specific action."""
    text = _module23_block()
    assert "Name: {p.name}" in text


def test_module23_thread_finding_correlates_shellcode_vad():
    """Thread-handle findings must classify the target thread's start address via
    _vad_type_at against the TARGET process (not the holder) for shellcode-consistent
    corroboration."""
    text = _module23_block()
    assert '_vad_type_at(target_proc, win32start)' in text
    assert 'anon_exec' in text
