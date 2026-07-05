"""Batch 5 -- detection breadth: TTP-010 (DLL sideloading), Heaven's Gate
(WOW64 far transition), and the documented-coverage-gap notes for
TTP-006/007/015/016.

memory_forensic.py loads vmmpyc at import so it cannot be unit-imported (same
constraint as the rest of this file's tests) -- structural assertions over the
source text for wiring/exclusions, plus behavioral extraction of the pure
regex/byte-pattern logic (no vmmpyc dependency) for genuine coverage.
"""
import re
import pathlib

SRC = pathlib.Path(__file__).parent.parent / 'playbooks' / 'windows' / 'threat_hunting' / 'memory_forensic.py'
src = SRC.read_text(encoding='utf-8')


def _block(start_marker, end_marker):
    s = src.find(start_marker)
    assert s != -1, f'{start_marker!r} not found'
    e = src.find(end_marker, s)
    if e == -1:
        e = len(src)
    return src[s:e]


# ---------------------------------------------------------------------------
# Module 24: DLL sideloading (TTP-010)
# ---------------------------------------------------------------------------

def test_module24_section_exists():
    assert re.search(r"=== 24\.", src)


def test_module24_reuses_sys_paths_not_a_new_regex():
    """Must reuse the existing SYS_PATHS system-path regex (Module 7) rather
    than duplicating a second, possibly-inconsistent system-path check."""
    block = _block('=== 24.', '=== 25.')
    assert 'SYS_PATHS' in block


def test_module24_checks_exe_dir_or_suspicious_dir():
    block = _block('=== 24.', '=== 25.')
    assert 'in_exe_dir' in block and 'susp_dir' in block


def test_module24_finding_type():
    block = _block('=== 24.', '=== 25.')
    assert 'DLL Sideloading Candidate' in block


def test_module24_severity_downgrades_for_exe_dir_only():
    """Rule 2: same-directory-as-EXE alone (no suspicious path) must be Medium,
    not High -- many legit apps ship their own copy of a common DLL name."""
    block = _block('=== 24.', '=== 25.')
    assert re.search(r"sev\s*=\s*'High'\s+if\s+susp_dir\s+else\s+'Medium'", block)


def _extract_sideload_regex():
    m = re.search(r"^_SIDELOAD_NAMES = re\.compile\(\n(?:.*\n)*?    r'.*\.dll\$'\)\n", src, re.MULTILINE)
    assert m, '_SIDELOAD_NAMES regex not found'
    ns = {'re': re}
    exec(m.group(0), ns)
    return ns['_SIDELOAD_NAMES']


class TestSideloadNamesRegex:

    def test_matches_known_sideload_target(self):
        rx = _extract_sideload_regex()
        assert rx.match('version.dll')
        assert rx.match('DBGHELP.DLL')

    def test_does_not_match_unrelated_dll(self):
        rx = _extract_sideload_regex()
        assert not rx.match('mycompanyapp.dll')
        assert not rx.match('kernel32.dll')


# ---------------------------------------------------------------------------
# Module 25: Heaven's Gate (WOW64 far transition)
# ---------------------------------------------------------------------------

def test_module25_section_exists():
    assert re.search(r"=== 25\.", src)


def test_module25_checks_is_wow64():
    block = _block('=== 25.', '# ====')
    assert 'is_wow64' in block


def test_module25_restricts_to_private_exec_only():
    """Legitimate WOW64 transitions live in image-backed wow64*.dll thunks --
    only anonymous (private) exec memory is a signal."""
    block = _block('=== 25.', '# ====')
    assert "typ != 'private'" in block


def test_module25_finding_type():
    block = _block('=== 25.', '# ====')
    assert "Heaven's Gate" in block


def _extract_hg_patterns():
    m = re.search(
        r"^_HG_FAR_JMP.*\n_HG_FAR_CALL.*\n_HG_PUSH_SEL.*\n_HG_RETF.*$",
        src, re.MULTILINE,
    )
    assert m, 'Heaven'"'"'s Gate byte-pattern constants not found'
    ns = {'re': re}
    exec(m.group(0), ns)
    return ns['_HG_FAR_JMP'], ns['_HG_FAR_CALL'], ns['_HG_PUSH_SEL'], ns['_HG_RETF']


class TestHeavensGatePatterns:

    def test_far_jmp_to_selector_0x33_matches(self):
        far_jmp, far_call, push_sel, retf = _extract_hg_patterns()
        data = b'\x90\x90' + b'\xEA' + b'\xAA\xBB\xCC\xDD' + b'\x33\x00' + b'\x90'
        assert far_jmp.search(data)

    def test_far_call_to_selector_0x33_matches(self):
        far_jmp, far_call, push_sel, retf = _extract_hg_patterns()
        data = b'\x90' + b'\x9A' + b'\x11\x22\x33\x44' + b'\x33\x00'
        assert far_call.search(data)

    def test_far_jmp_to_other_selector_does_not_match(self):
        """Selector value IS the mechanism (Rule 3) -- a far jump to any
        selector other than 0x33 is not a WOW64-to-long-mode transition."""
        far_jmp, far_call, push_sel, retf = _extract_hg_patterns()
        data = b'\xEA' + b'\xAA\xBB\xCC\xDD' + b'\x28\x00'   # selector 0x28, not 0x33
        assert not far_jmp.search(data)

    def test_push_sel_then_retf_within_window_is_the_idiom(self):
        far_jmp, far_call, push_sel, retf = _extract_hg_patterns()
        data = b'\x90' + push_sel + b'\x68\x11\x22\x33\x44' + retf + b'\x90'
        push_off = data.find(push_sel)
        assert push_off != -1
        assert data.find(retf, push_off + 2, push_off + 32) != -1

    def test_push_sel_without_nearby_retf_is_not_the_idiom(self):
        far_jmp, far_call, push_sel, retf = _extract_hg_patterns()
        data = push_sel + b'\x90' * 40 + retf   # retf far outside the 32-byte window
        push_off = data.find(push_sel)
        assert data.find(retf, push_off + 2, push_off + 32) == -1


# ---------------------------------------------------------------------------
# Documented coverage gaps: TTP-006/007/015/016
# ---------------------------------------------------------------------------

def test_coverage_gap_section_exists():
    assert 'Documented coverage gaps' in src


def test_all_four_blocked_ttps_documented():
    block = _block('Documented coverage gaps', 'Summary')
    for ttp in ('TTP-006', 'TTP-007', 'TTP-015', 'TTP-016'):
        assert ttp in block, f'{ttp} not mentioned in the documented-coverage-gaps section'


def test_ttp015_016_point_to_analyze_memory_volatility_route():
    """TTP-015/016 ARE automatable, just not by this engine -- the message
    must point at the concrete alternative (Analyze-Memory.ps1 + Volatility
    plugin names), not a generic 'not supported'."""
    block = _block('Documented coverage gaps', 'Summary')
    assert 'Analyze-Memory.ps1' in block
    assert 'windows.privileges' in block
    assert 'windows.callbacks' in block


def test_ttp006_007_have_no_false_promise_of_a_volatility_route():
    """Unlike TTP-015/016, TTP-006/007 have no plugin anywhere -- the message
    must not claim Analyze-Memory.ps1 as a workaround for these two."""
    block = _block('Documented coverage gaps', 'Summary')
    ttp006_line = re.search(r'TTP-006.*', block)
    ttp007_line = re.search(r'TTP-007.*', block)
    assert ttp006_line and 'Analyze-Memory' not in ttp006_line.group(0)
    assert ttp007_line and 'Analyze-Memory' not in ttp007_line.group(0)
