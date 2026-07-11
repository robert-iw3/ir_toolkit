"""
test_58_mwcp_ransomware_parsers.py -- Validation for the 7 Tier 2 ransomware
mwcp parsers (RansomwareIndicators + 6 family-specific detectors).

Every identify() here requires 2+ independent structural/behavioral signals
-- never a single indicator alone -- per [[feedback-detection-design]]:
a single flag/string is not evidence on its own across a large search space
or a common string; only a genuine cluster is.
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
    tp_probe = os.path.join(_TP, 'lockbit_config.bin')
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


_PARSER_TP_FILE = [
    ('ransomware.RansomwareIndicators', 'RansomwareIndicators', 'ransomware_indicators.bin'),
    ('ransomware.LockBitConfig',        'LockBitConfig',        'lockbit_config.bin'),
    ('ransomware.BlackCatConfig',       'BlackCatConfig',       'blackcat_config.bin'),
    ('ransomware.REvil_SodinokibiConfig','REvil_SodinokibiConfig', 'revil_config.bin'),
    ('ransomware.ContiConfig',          'ContiConfig',          'conti_config.bin'),
    ('ransomware.AkiraConfig',          'AkiraConfig',          'akira_config.bin'),
    ('ransomware.BlackBastaConfig',     'BlackBastaConfig',     'blackbasta_config.bin'),
]


@needs_mwcp
class TestRansomwareIdentifyTP:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_identifies_own_tp_sample(self, module_path, parser_name, tp_file, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        assert cls.identify(_FO(_tp_bytes(tp_file))) is True, \
            f'{parser_name} failed to identify its own TP sample ({tp_file})'


@needs_mwcp
class TestRansomwareNoFalsePositives:
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


@needs_mwcp
class TestRansomwareSingleIndicatorNotEnough:
    """Each parser must require its documented CLUSTER of signals -- a lone
    signal (one field name, one flag, one string) must not be sufficient."""

    def test_lockbit_needs_4_not_1_field(self):
        from ransomware.LockBitConfig import LockBitConfig
        data = b'\x00' * 64 + b'{"encrypt_filename": true}' + b'\x00' * 64
        assert LockBitConfig.identify(_FO(data)) is False

    def test_blackcat_needs_4_not_1_field(self):
        from ransomware.BlackCatConfig import BlackCatConfig
        data = b'{"config_id": "x"}'
        assert BlackCatConfig.identify(_FO(data)) is False

    def test_revil_needs_4_not_1_field(self):
        from ransomware.REvil_SodinokibiConfig import REvil_SodinokibiConfig
        data = b'{"pk": "x"}' + b'A' * 128
        assert REvil_SodinokibiConfig.identify(_FO(data)) is False

    def test_conti_needs_mode_and_sibling_flag(self):
        from ransomware.ContiConfig import ContiConfig
        # mode flag alone, no sibling flag present
        assert ContiConfig.identify(_FO(b'somebinary -m local' + b'\x00' * 32)) is False

    def test_akira_needs_percent_and_sibling_flag(self):
        from ransomware.AkiraConfig import AkiraConfig
        # the distinctive flag alone, no sibling flag present
        data = b'akira.exe --encryption_percent 50' + b'\x00' * 32
        assert AkiraConfig.identify(_FO(data)) is False

    def test_blackbasta_needs_key_and_ransomware_marker(self):
        from ransomware.BlackBastaConfig import BlackBastaConfig
        # -key argument alone, no RSA/VSS corroboration anywhere in the file
        key = b'-key ' + b'A' * 32
        data = b'\x00' * 32 + key + b'\x00' * 32
        assert BlackBastaConfig.identify(_FO(data)) is False

    def test_ransomware_indicators_needs_2_of_3_not_1(self):
        from ransomware.RansomwareIndicators import RansomwareIndicators
        # RSA pubkey alone (from generate_samples' helper), no VSS/ext cluster
        sys.path.insert(0, _LAB)
        from generate_samples import _rsa_pubkey_der  # type: ignore
        data = _rsa_pubkey_der() + b'\x00' * 64
        assert RansomwareIndicators.identify(_FO(data)) is False


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestRansomwareEndToEnd:

    @pytest.mark.parametrize('parser_name,tp_file,expect_substr', [
        ('RansomwareIndicators', 'ransomware_indicators.bin', 'Ransomware-Indicators'),
        ('LockBitConfig',        'lockbit_config.bin',        'LockBit'),
        ('BlackCatConfig',       'blackcat_config.bin',       'BlackCat'),
        ('REvil_SodinokibiConfig', 'revil_config.bin',        'REvil'),
        ('ContiConfig',          'conti_config.bin',          'Conti-Args'),
        ('AkiraConfig',          'akira_config.bin',          'Akira-Args'),
        ('BlackBastaConfig',     'blackbasta_config.bin',     'BlackBasta'),
    ])
    def test_extracts_via_mwcp_scan(self, parser_name, tp_file, expect_substr, lab_samples):
        r = _run_mwcp(os.path.join(_TP, tp_file))
        assert _has_ioc(r), f'{parser_name} produced no IOC: {r}'
        decoded = ' '.join(r.get('decoded', []))
        assert expect_substr in decoded, f'{parser_name}: expected {expect_substr!r} in {decoded!r}'


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestRansomwareEndToEndFP:
    @pytest.mark.parametrize('fp_file', [
        'benign_pe.bin', 'benign_ps1.ps1', 'benign_macro.vbs', 'benign_binary.bin',
    ])
    def test_no_ioc_from_fp_sample(self, fp_file, lab_samples):
        r = _run_mwcp(os.path.join(_FP, fp_file))
        assert not _has_ioc(r), f'{fp_file} unexpectedly produced an IOC: {r}'
