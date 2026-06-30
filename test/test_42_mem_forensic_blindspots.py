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
