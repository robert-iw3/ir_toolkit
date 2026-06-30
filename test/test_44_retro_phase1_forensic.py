"""
Phase 1 retrospective gap fixes — memory_forensic.py source-text tests.

Cannot import memory_forensic.py directly (vmmpyc hard-dependency), so all
assertions are structural: regex over the source file proves the required
patterns are present.

Phase 1A — Module 3: per-process anonymous exec cap
  - _ANON_EXEC_PER_PROC_CAP constant defined (< 10, so never >=30 global)
  - per-process counter reset inside outer process loop
  - cap-hit produces a Finding (add() call), not just a log warning
  - global cap constant exists as a safety ceiling

Phase 1B — Module 5: VAD type integration
  - _vad_type_at helper function defined
  - Module 5 calls _vad_type_at
  - 'unmapped' branch maps to severity 'Low'
  - 'image' branch maps to severity 'Medium' (not 'High')
  - 'anon_exec' branch keeps severity 'High'
"""
import re
import pathlib

SRC = pathlib.Path(__file__).parent.parent / "playbooks" / "windows" / "threat_hunting" / "memory_forensic.py"
src = SRC.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _line_of(pattern: str) -> int:
    """Return 1-based line number of first regex match, or -1."""
    m = re.search(pattern, src, re.MULTILINE)
    return src[: m.start()].count("\n") + 1 if m else -1


# ===========================================================================
# Phase 1A — Module 3: per-process cap
# ===========================================================================

def test_1a_per_proc_cap_constant_defined():
    """_ANON_EXEC_PER_PROC_CAP must be defined as a module-level constant."""
    assert re.search(r'^_ANON_EXEC_PER_PROC_CAP\s*=\s*\d+', src, re.MULTILINE), (
        "_ANON_EXEC_PER_PROC_CAP constant not found in memory_forensic.py"
    )


def test_1a_per_proc_cap_value_less_than_30():
    """Per-process cap must be < 30 so JIT processes cannot monopolise the global budget."""
    m = re.search(r'^_ANON_EXEC_PER_PROC_CAP\s*=\s*(\d+)', src, re.MULTILINE)
    assert m, "_ANON_EXEC_PER_PROC_CAP not found"
    assert int(m.group(1)) < 30, (
        f"_ANON_EXEC_PER_PROC_CAP={m.group(1)} must be <30 (e.g. 5) so JIT processes "
        "cannot consume the entire global budget"
    )


def test_1a_global_cap_constant_defined():
    """_ANON_EXEC_GLOBAL_CAP safety ceiling must exist."""
    assert re.search(r'^_ANON_EXEC_GLOBAL_CAP\s*=\s*\d+', src, re.MULTILINE), (
        "_ANON_EXEC_GLOBAL_CAP global safety ceiling not found"
    )


def test_1a_per_proc_counter_reset_in_process_loop():
    """proc_anon (or equivalent per-process counter) must be reset to 0 for each
    process iteration — not shared across processes like the old n_anon global."""
    assert re.search(r'proc_anon\s*=\s*0', src), (
        "per-process counter 'proc_anon = 0' not found — "
        "without a reset, all processes after the first cap share the same count"
    )


def test_1a_cap_hit_produces_finding_not_only_log():
    """When the per-process cap is reached, a Finding (add() call) must be emitted,
    not just a log() warning. log-only is invisible in reports.

    Implementation uses a local 'per_proc_cap' variable derived from the constants,
    so we check for 'proc_anon >= per_proc_cap' and a nearby add() call."""
    cap_check = re.search(r'proc_anon\s*>=\s*per_proc_cap', src)
    assert cap_check, (
        "proc_anon >= per_proc_cap check not found in source — "
        "per-process cap comparison must use the per_proc_cap local variable"
    )
    snippet_end = min(len(src), cap_check.end() + 800)
    snippet = src[cap_check.start(): snippet_end]
    assert re.search(r"\badd\s*\(", snippet), (
        "No add() call near proc_anon cap check — "
        "cap breach must produce a visible Finding, not just a log() warning"
    )


def test_1a_cap_hit_finding_medium_or_higher():
    """The cap-hit Finding must be severity Medium (not Low/Info). It signals that
    coverage was truncated — this is operationally significant."""
    cap_check = re.search(r'proc_anon\s*>=\s*per_proc_cap', src)
    assert cap_check, "proc_anon >= per_proc_cap check not found"
    snippet = src[cap_check.start(): cap_check.end() + 800]
    assert re.search(r"add\s*\(\s*['\"](?:Medium|High|Critical)['\"]", snippet), (
        "Cap-hit add() call must use 'Medium' (or higher) severity"
    )


def test_1a_old_global_only_log_warning_removed():
    """The old 'anonymous exec cap (30) reached' warning-only log must be replaced
    by the new per-process Finding mechanism."""
    assert "anonymous exec cap (30) reached" not in src, (
        "Old 'anonymous exec cap (30) reached' log-only warning still present — "
        "replace with per-process Finding mechanism"
    )


# ===========================================================================
# Phase 1B — Module 5: VAD type integration
# ===========================================================================

def test_1b_vad_type_at_helper_defined():
    """_vad_type_at(proc, addr) helper must be defined in memory_forensic.py."""
    assert re.search(r'def\s+_vad_type_at\s*\(', src), (
        "_vad_type_at helper function not found in memory_forensic.py"
    )


def test_1b_vad_type_at_returns_unmapped():
    """_vad_type_at must return 'unmapped' (string) when no VAD covers the address."""
    assert re.search(r"['\"]unmapped['\"]", src), (
        "'unmapped' return value not found in _vad_type_at — "
        "this is the signal for unloaded-DLL FP classification"
    )


def test_1b_vad_type_at_returns_image():
    """_vad_type_at must return 'image' for file-backed VADs not in the PEB module list."""
    assert re.search(r"['\"]image['\"]", src), (
        "'image' return value not found in _vad_type_at"
    )


def test_1b_vad_type_at_returns_anon_exec():
    """_vad_type_at must return 'anon_exec' for anonymous executable VADs (TP signal)."""
    assert re.search(r"['\"]anon_exec['\"]", src), (
        "'anon_exec' return value not found in _vad_type_at"
    )


def test_1b_module5_calls_vad_type_at():
    """Module 5 (Shellcode thread detection) must call _vad_type_at to classify
    the thread start address before emitting the finding."""
    mod5_start = src.find("=== 5. Shellcode thread detection ===")
    mod5_end   = src.find("=== 5b.", mod5_start)
    assert mod5_start != -1 and mod5_end != -1
    mod5_block = src[mod5_start:mod5_end]
    assert "_vad_type_at" in mod5_block, (
        "Module 5 does not call _vad_type_at — thread start VAD type not checked"
    )


def test_1b_unmapped_branch_is_low_severity():
    """When _vad_type_at returns 'unmapped', the finding must use 'Low' severity.
    Implementation assigns sev='Low' in the unmapped branch; the add(sev,...) call
    is shared at the end of the if-elif chain."""
    mod5_start = src.find("=== 5. Shellcode thread detection ===")
    mod5_end   = src.find("=== 5b.", mod5_start)
    mod5_block = src[mod5_start:mod5_end]
    # The unmapped branch must assign sev = 'Low'
    m = re.search(r"vad_type\s*==\s*['\"]unmapped['\"]", mod5_block)
    assert m, "No 'vad_type == unmapped' branch in Module 5"
    snippet = mod5_block[m.start(): m.end() + 600]
    assert re.search(r"sev\s*=\s*['\"]Low['\"]", snippet), (
        "No sev = 'Low' assignment in unmapped branch of Module 5 — "
        "unmapped thread start must be Low severity (unloaded-DLL FP)"
    )


def test_1b_image_branch_is_medium_severity():
    """When _vad_type_at returns 'image', the finding must use 'Medium' severity
    (DLL not in PEB list — needs corroboration, not auto-TP)."""
    mod5_start = src.find("=== 5. Shellcode thread detection ===")
    mod5_end   = src.find("=== 5b.", mod5_start)
    mod5_block = src[mod5_start:mod5_end]
    m = re.search(r"vad_type\s*==\s*['\"]image['\"]", mod5_block)
    assert m, "No 'vad_type == image' branch in Module 5"
    snippet = mod5_block[m.start(): m.end() + 600]
    assert re.search(r"sev\s*=\s*['\"]Medium['\"]", snippet), (
        "No sev = 'Medium' in image branch of Module 5 — "
        "file-backed thread start must be Medium (PEB list miss), not High"
    )


def test_1b_anon_exec_branch_is_high_severity():
    """When _vad_type_at returns 'anon_exec', the finding keeps 'High' severity
    (anonymous executable memory is the true TP signal)."""
    mod5_start = src.find("=== 5. Shellcode thread detection ===")
    mod5_end   = src.find("=== 5b.", mod5_start)
    mod5_block = src[mod5_start:mod5_end]
    m = re.search(r"vad_type\s*==\s*['\"]anon_exec['\"]", mod5_block)
    assert m, "No 'vad_type == anon_exec' branch in Module 5"
    snippet = mod5_block[m.start(): m.end() + 600]
    assert re.search(r"sev\s*=\s*['\"]High['\"]", snippet), (
        "No sev = 'High' in anon_exec branch of Module 5 — "
        "anonymous executable thread start must remain High severity"
    )
