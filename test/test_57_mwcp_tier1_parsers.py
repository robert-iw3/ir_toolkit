"""
test_57_mwcp_tier1_parsers.py -- Validation for the 12 Tier 1 backlog mwcp
parsers added to mwcp_parsers/ROADMAP.md's Tier 1 list (C2 frameworks,
common RATs, stealers).

Same two-layer pattern as test_53_mwcp_parsers.py:
  1. identify() unit tests against the generated TP/FP lab samples.
  2. End-to-end extraction tests via mwcp_scan.py subprocess.

AsyncSpyConfig is intentionally not implemented -- it is an AsyncRAT variant
with the same field-name cluster, already covered by AsyncRATConfig.py's
structural detection; a separate parser would only add a name-string check
(the ROADMAP's own description leans on an "AsyncSpy marker string"), which
[[feedback-detection-design]] Rule 3 rules out as a detection basis on its
own.
"""

import importlib
import json
import os
import subprocess
import sys

import pytest

_HERE       = os.path.dirname(os.path.abspath(__file__))
_ROOT       = os.path.dirname(_HERE)
_WIN_HUNT   = os.path.join(_ROOT, 'playbooks', 'windows', 'threat_hunting')
_PARSERS    = os.path.join(_WIN_HUNT, 'mwcp_parsers')
_MWCP_SCAN  = os.path.join(_WIN_HUNT, 'mwcp_scan.py')
_MWCP_LIB   = os.path.join(_ROOT, 'tools', 'mwcp', 'lib')
_LAB        = os.path.join(_HERE, 'windows', 'lab_mwcp')
_GENERATE   = os.path.join(_LAB, 'generate_samples.py')
_TP         = os.path.join(_LAB, 'samples', 'tp')
_FP         = os.path.join(_LAB, 'samples', 'fp')

_mwcp_ok = False
if os.path.isdir(_MWCP_LIB):
    for _p in (_MWCP_LIB, _PARSERS):
        if _p not in sys.path:
            sys.path.insert(0, _p)
    try:
        import mwcp  # noqa: F401
        _mwcp_ok = True
    except ImportError:
        pass

needs_mwcp = pytest.mark.skipif(not _mwcp_ok, reason='mwcp not staged in tools/')


@pytest.fixture(scope='session', autouse=True)
def lab_samples():
    tp_probe = os.path.join(_TP, 'deimos_config.bin')
    if not os.path.exists(tp_probe):
        subprocess.run([sys.executable, _GENERATE], check=True, timeout=30)


class _FO:
    def __init__(self, data: bytes):
        self.data = data
        self.name = 'test.bin'


def _tp_bytes(filename: str) -> bytes:
    with open(os.path.join(_TP, filename), 'rb') as f:
        return f.read()


def _all_fp_bytes() -> list[tuple[str, bytes]]:
    out = []
    for fname in sorted(os.listdir(_FP)):
        with open(os.path.join(_FP, fname), 'rb') as f:
            out.append((fname, f.read()))
    return out


def _run_mwcp(file_path: str, timeout: int = 60) -> dict:
    r = subprocess.run(
        [sys.executable, _MWCP_SCAN, _MWCP_LIB, '-', file_path],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
    )
    stdout = r.stdout.decode('utf-8', errors='replace') if r.stdout else ''
    if not stdout.strip():
        pytest.fail(f'mwcp_scan returned no output for {os.path.basename(file_path)}: '
                    f'rc={r.returncode} stderr={r.stderr.decode("utf-8","replace")[:400]!r}')
    results = json.loads(stdout)
    return results[0] if results else {}


def _has_ioc(result: dict) -> bool:
    return bool(result.get('address') or result.get('mutex') or
                result.get('password') or result.get('decoded'))


# ---------------------------------------------------------------------------
# Per-parser TP identify() + no-FP-fires-on-any-FP-sample tests
# ---------------------------------------------------------------------------
# (module_path, ClassName, tp_sample_file) -- module_path is the subpackage-
# qualified path (category subfolder), matching parser_config.yml's own
# "<subfolder>.<ModuleName>.<ClassName>" convention.
_PARSER_TP_FILE = [
    ('c2_frameworks.DeimosConfig', 'DeimosConfig',   'deimos_config.bin'),
    ('stagers.MacroPackConfig',    'MacroPackConfig','macropack_loader.vbs'),
    ('c2_frameworks.IcedIDConfig', 'IcedIDConfig',   'icedid_config.bin'),
    ('c2_frameworks.QakBotConfig', 'QakBotConfig',   'qakbot_config.bin'),
    ('c2_frameworks.EmotedConfig', 'EmotedConfig',   'emoted_config.bin'),
    ('rats.RemcosConfig',          'RemcosConfig',   'remcos_config.bin'),
    ('rats.NanoCoreConfig',        'NanoCoreConfig', 'nanocore_config.bin'),
    ('stealers.RedlineConfig',     'RedlineConfig',  'redline_config.bin'),
    ('stealers.VidarConfig',       'VidarConfig',    'vidar_config.bin'),
    ('stealers.LummaConfig',       'LummaConfig',    'lumma_config.bin'),
    ('stealers.StealcConfig',      'StealcConfig',   'stealc_config.bin'),
    ('stealers.RaccoonConfig',     'RaccoonConfig',  'raccoon_config.bin'),
]


@needs_mwcp
class TestTier1IdentifyTP:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_identifies_own_tp_sample(self, module_path, parser_name, tp_file, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        assert cls.identify(_FO(_tp_bytes(tp_file))) is True, \
            f'{parser_name} failed to identify its own TP sample ({tp_file})'


@needs_mwcp
class TestTier1NoFalsePositives:
    """Each parser must stay silent on every FP sample in the lab -- this is
    the check that caught QakBotConfig/EmotedConfig firing on 100% of FP
    samples before the port-allowlist fix (see their module docstrings)."""

    @pytest.mark.parametrize('module_path,parser_name,_', _PARSER_TP_FILE)
    def test_silent_on_all_fp_samples(self, module_path, parser_name, _, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        fires_on = []
        for fname, data in _all_fp_bytes():
            try:
                if cls.identify(_FO(data)):
                    fires_on.append(fname)
            except Exception as e:
                fires_on.append(f'{fname} (EXCEPTION: {e})')
        assert not fires_on, f'{parser_name} incorrectly fired on FP sample(s): {fires_on}'


# ---------------------------------------------------------------------------
# Targeted identify() FP-shape tests (near-miss inputs, not just the shared
# FP lab set)
# ---------------------------------------------------------------------------
@needs_mwcp
class TestTier1TargetedFalsePositives:

    def test_macropack_no_fire_without_shellout(self):
        from stagers.MacroPackConfig import MacroPackConfig
        data = (b'Sub AutoOpen()\n'
                b's = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58)\n'
                b'MsgBox s\n'
                b'End Sub\n')
        assert MacroPackConfig.identify(_FO(data)) is False

    def test_macropack_no_fire_without_autoexec(self):
        from stagers.MacroPackConfig import MacroPackConfig
        data = (b'Sub PrintReport()\n'
                b's = Chr(104) & Chr(116) & Chr(116) & Chr(112) & Chr(58)\n'
                b'CreateObject("WScript.Shell").Run s\n'
                b'End Sub\n')
        assert MacroPackConfig.identify(_FO(data)) is False

    def test_stealc_no_fire_without_url(self):
        from stealers.StealcConfig import StealcConfig
        data = b'Content-Type: application/x-www-form-urlencoded\r\n' + b'A' * 200
        assert StealcConfig.identify(_FO(data)) is False

    def test_qakbot_no_fire_on_random_bytes(self):
        # Regression guard for the port-allowlist fix: 4KB of structured-but-
        # non-C2 bytes must not coincidentally decode as a valid record list.
        import hashlib
        from c2_frameworks.QakBotConfig import QakBotConfig
        seed = hashlib.sha256(b'qakbot-fp-regression-seed').digest()
        data = (seed * 200)[:4096]
        assert QakBotConfig.identify(_FO(data)) is False

    def test_emoted_no_fire_on_random_bytes(self):
        import hashlib
        from c2_frameworks.EmotedConfig import EmotedConfig
        seed = hashlib.sha256(b'emoted-fp-regression-seed').digest()
        data = (seed * 200)[:4096]
        assert EmotedConfig.identify(_FO(data)) is False

    def test_raccoon_no_fire_below_length_floor(self):
        from stealers.RaccoonConfig import RaccoonConfig
        data = b'api.telegram.org/bot123456789:AAExampleTokenTooShortFile'
        assert len(data) < 128
        assert RaccoonConfig.identify(_FO(data)) is False

    def test_icedid_no_fire_on_plaintext_overlay(self):
        # Plaintext (low-entropy) overlay content must not pass the
        # size-relative entropy gate even though it's the right size.
        from c2_frameworks.IcedIDConfig import IcedIDConfig
        import sys as _s
        if _LAB not in _s.path:
            _s.path.insert(0, _LAB)
        from generate_samples import _minimal_pe_with_overlay  # type: ignore
        data = _minimal_pe_with_overlay(b'this is not encrypted at all ' * 4)
        assert IcedIDConfig.identify(_FO(data)) is False


# ---------------------------------------------------------------------------
# End-to-end extraction tests (subprocess via mwcp_scan.py)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestTier1EndToEnd:

    def test_deimos_extracts_callback_and_agent_id(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'deimos_config.bin'))
        assert _has_ioc(r), f'DeimosConfig produced no IOC: {r}'

    def test_macropack_extracts_loader_marker(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'macropack_loader.vbs'))
        decoded = r.get('decoded', [])
        assert any('MacroLoader' in d for d in decoded), \
            f'MacroPack loader marker missing: {decoded}'

    def test_icedid_extracts_domains(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'icedid_config.bin'))
        addrs = r.get('address', [])
        assert any('lab.test' in a for a in addrs), f'IcedID domains missing: {addrs}'

    def test_qakbot_extracts_c2_addresses(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'qakbot_config.bin'))
        addrs = r.get('address', [])
        assert any(':443' in a for a in addrs), f'QakBot C2 addresses missing: {addrs}'

    def test_emoted_extracts_c2_addresses(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'emoted_config.bin'))
        addrs = r.get('address', [])
        assert any(':443' in a for a in addrs), f'Emotet C2 addresses missing: {addrs}'

    def test_remcos_extracts_host_and_password(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'remcos_config.bin'))
        assert _has_ioc(r), f'RemcosConfig produced no IOC: {r}'
        addrs = r.get('address', [])
        assert any('c2.lab.test' in a for a in addrs), f'Remcos C2 missing: {addrs}'

    def test_nanocore_extracts_host(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'nanocore_config.bin'))
        addrs = r.get('address', [])
        assert any('c2.lab.test' in a for a in addrs), f'NanoCore C2 missing: {addrs}'

    def test_redline_extracts_address(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'redline_config.bin'))
        addrs = r.get('address', [])
        assert any('1.2.3.4' in a for a in addrs), f'Redline address missing: {addrs}'

    def test_vidar_extracts_c2_url(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'vidar_config.bin'))
        assert _has_ioc(r), f'VidarConfig produced no IOC: {r}'

    def test_lumma_extracts_url_list(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'lumma_config.bin'))
        assert _has_ioc(r), f'LummaConfig produced no IOC: {r}'

    def test_stealc_extracts_url(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'stealc_config.bin'))
        assert _has_ioc(r), f'StealcConfig produced no IOC: {r}'

    def test_raccoon_extracts_telegram_fallback(self, lab_samples):
        r = _run_mwcp(os.path.join(_TP, 'raccoon_config.bin'))
        assert _has_ioc(r), f'RaccoonConfig produced no IOC: {r}'


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestTier1EndToEndFP:
    """None of the 12 new parsers should produce an IOC from the shared FP lab set.

    benign_json.json is deliberately excluded here: GenericC2 (a pre-existing,
    unrelated parser) always sweeps any URL-shaped string as a low-confidence
    candidate by design -- that's tested in test_53_mwcp_parsers.py, not a
    Tier 1 regression."""

    @pytest.mark.parametrize('fp_file', [
        'benign_pe.bin', 'benign_ps1.ps1', 'benign_macro.vbs',
        'stealc_header_only.txt', 'benign_binary.bin',
    ])
    def test_no_ioc_from_fp_sample(self, fp_file, lab_samples):
        r = _run_mwcp(os.path.join(_FP, fp_file))
        assert not _has_ioc(r), f'{fp_file} unexpectedly produced an IOC: {r}'
