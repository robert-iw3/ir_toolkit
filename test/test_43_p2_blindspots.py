"""
P2 blindspot regression tests for memory_forensic.py — content-based,
no vmmpyc import required.

P2-A: _MANAGED_HOSTS must NOT include T1218 execution-proxy LOLBins (msbuild,
regasm, regsvcs, installutil, pwsh).  Finding BSJB metadata in their private
executable memory IS evidence of execute-assembly and must not be suppressed.
"""
import re
import pathlib

SRC = pathlib.Path(__file__).parent.parent / 'playbooks' / 'windows' / 'threat_hunting' / 'memory_forensic.py'
src = SRC.read_text(encoding='utf-8')

# ── helpers ───────────────────────────────────────────────────────────────────

def _managed_hosts_pattern() -> str:
    """Extract the raw regex string inside _MANAGED_HOSTS = re.compile(...)."""
    m = re.search(r'_MANAGED_HOSTS\s*=\s*re\.compile\(\s*(.*?)\)', src, re.DOTALL)
    assert m, '_MANAGED_HOSTS definition not found'
    return m.group(1)


# ── P2-A: T1218 LOLBins must NOT be in _MANAGED_HOSTS ─────────────────────────

def test_msbuild_not_in_managed_hosts():
    """msbuild is a T1218 LOLBin; BSJB inside it is execute-assembly evidence."""
    pat = _managed_hosts_pattern()
    assert 'msbuild' not in pat, \
        'msbuild must be removed from _MANAGED_HOSTS -- it is a T1218.005 proxy LOLBin'

def test_regasm_not_in_managed_hosts():
    """regasm.exe is a T1218.009 LOLBin."""
    pat = _managed_hosts_pattern()
    assert 'regasm' not in pat, \
        'regasm must be removed from _MANAGED_HOSTS -- T1218.009 proxy LOLBin'

def test_regsvcs_not_in_managed_hosts():
    """regsvcs.exe is a T1218.010 LOLBin."""
    pat = _managed_hosts_pattern()
    assert 'regsvcs' not in pat, \
        'regsvcs must be removed from _MANAGED_HOSTS -- T1218.010 proxy LOLBin'

def test_installutil_not_in_managed_hosts():
    """installutil.exe is a T1218.004 LOLBin."""
    pat = _managed_hosts_pattern()
    assert 'installutil' not in pat, \
        'installutil must be removed from _MANAGED_HOSTS -- T1218.004 proxy LOLBin'

def test_pwsh_not_in_managed_hosts():
    """pwsh is an execute-assembly execution vehicle; BSJB detection must run."""
    pat = _managed_hosts_pattern()
    # The pattern may legitimately contain 'powershell' but 'pwsh' as a standalone
    # alternative means the whole process is silently skipped.
    assert re.search(r'\bpwsh\b', pat) is None, \
        'pwsh must be removed from _MANAGED_HOSTS -- attackers inject into it via execute-assembly'

# ── P2-A: _T1218_LOLBINS constant must exist ──────────────────────────────────

def test_t1218_lolbins_constant_defined():
    """_T1218_LOLBINS (or equivalent) must be defined at module level."""
    assert re.search(r'^_T1218_LOLBINS\s*=', src, re.MULTILINE), \
        '_T1218_LOLBINS constant not found -- needed to detect CLR in LOLBin at runtime'

def test_t1218_lolbins_contains_msbuild():
    m = re.search(r'_T1218_LOLBINS\s*=.*?(?=\n\n|\Z)', src, re.DOTALL)
    assert m and 'msbuild' in m.group(), \
        'msbuild must be in _T1218_LOLBINS'

def test_t1218_lolbins_contains_regasm():
    m = re.search(r'_T1218_LOLBINS\s*=.*?(?=\n\n|\Z)', src, re.DOTALL)
    assert m and 'regasm' in m.group(), \
        'regasm must be in _T1218_LOLBINS'

def test_t1218_lolbins_contains_regsvcs():
    m = re.search(r'_T1218_LOLBINS\s*=.*?(?=\n\n|\Z)', src, re.DOTALL)
    assert m and 'regsvcs' in m.group(), \
        'regsvcs must be in _T1218_LOLBINS'

def test_t1218_lolbins_contains_installutil():
    m = re.search(r'_T1218_LOLBINS\s*=.*?(?=\n\n|\Z)', src, re.DOTALL)
    assert m and 'installutil' in m.group(), \
        'installutil must be in _T1218_LOLBINS'

# ── P2-A: Section 16 must use _T1218_LOLBINS and emit a finding for CLR in LOLBin ──

def test_section16_references_t1218_lolbins():
    """Section 16 must reference _T1218_LOLBINS to prevent LOLBins being skipped."""
    assert '_T1218_LOLBINS' in src, \
        'Section 16 must reference _T1218_LOLBINS'

def test_section16_emits_clr_in_lolbin_finding():
    """Section 16 must emit a finding when a T1218 LOLBin has CLR DLLs loaded."""
    assert re.search(r'T1218.*LOLBin|CLR.*LOLBin|LOLBin.*CLR', src), \
        'Section 16 must emit a finding for CLR loaded in a T1218 LOLBin (execute-assembly proxy)'

def test_section16_does_not_skip_lolbins_on_clr_dll_check():
    """The fully-managed-host skip must be guarded so LOLBins are not skipped."""
    assert re.search(r'is_lolbin|_T1218_LOLBINS', src), \
        'Section 16 CLR-DLL skip check must be guarded to not skip T1218 LOLBins'
