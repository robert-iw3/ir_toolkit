"""
test_62_mwcp_tier3_specialized_parsers.py -- Validation for the 6 Tier 3
specialized / post-compromise mwcp parsers.

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
        mwcp.register_entry_points()
        _mwcp_ok = True
    except ImportError:
        pass

needs_mwcp = pytest.mark.skipif(not _mwcp_ok, reason='mwcp not staged in tools/')


@pytest.fixture(scope='session', autouse=True)
def lab_samples():
    tp_probe = os.path.join(_TP, 'cryptominer.bin')
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


def _run_mwcp_errors(parser_name: str, file_path: str):
    result = mwcp.run(parser_name, file_path=file_path)
    d = result.as_dict()
    return d.get('metadata', []), d.get('errors', [])


_PARSER_TP_FILE = [
    ('specialized.CryptoMinerConfig',            'CryptoMinerConfig',            'cryptominer.bin'),
    ('specialized.CryptoMinerConfig',            'CryptoMinerConfig',            'cryptominer_cli.bin'),
    ('specialized.MetasploitPayload',            'MetasploitPayload',            'metasploit_payload.bin'),
    ('specialized.BitsadminPersistenceConfig',   'BitsadminPersistenceConfig',   'bitsadmin_persistence.bat'),
    ('specialized.KerberoastConfig',             'KerberoastConfig',             'kerberoast.ps1'),
    ('specialized.DCsyncConfig',                 'DCsyncConfig',                 'dcsync.txt'),
    ('specialized.AntiAnalysisStrings',          'AntiAnalysisStrings',          'anti_analysis.bin'),
]


@needs_mwcp
class TestTier3IdentifyTP:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_identifies_own_tp_sample(self, module_path, parser_name, tp_file, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        assert cls.identify(_FO(_tp_bytes(tp_file))) is True, \
            f'{parser_name} failed to identify its own TP sample ({tp_file})'


@needs_mwcp
class TestTier3NoRunExceptions:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_run_produces_metadata_without_errors(self, module_path, parser_name, tp_file, lab_samples):
        metadata, errors = _run_mwcp_errors(parser_name, os.path.join(_TP, tp_file))
        assert not errors, f'{parser_name}.run() raised: {errors}'
        assert metadata, f'{parser_name}.run() produced no metadata for {tp_file}'


@needs_mwcp
class TestTier3NoFalsePositives:
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
class TestTier3SingleIndicatorNotEnough:
    """Each parser must require its documented pair of signals -- a lone
    signal (one URL scheme, one byte pattern, one GUID) must not fire."""

    def test_cryptominer_needs_url_and_rpc_method(self):
        from specialized.CryptoMinerConfig import CryptoMinerConfig
        url_only = b'stratum+tcp://pool.minexmr.com:4444' + b'\x00' * 16
        rpc_only = b'{"id":1,"method":"mining.subscribe","params":[]}' + b'\x00' * 16
        assert CryptoMinerConfig.identify(_FO(url_only)) is False
        assert CryptoMinerConfig.identify(_FO(rpc_only)) is False

    def test_metasploit_needs_prologue_and_sockaddr(self):
        from specialized.MetasploitPayload import MetasploitPayload
        prologue = b'\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xd2\x64\x8b\x52\x30'
        sockaddr = b'\x02\x00\x11\x5c\x0a\x00\x00\x05'
        assert MetasploitPayload.identify(_FO(prologue + b'\x90' * 80)) is False
        assert MetasploitPayload.identify(_FO(b'\x90' * 80 + sockaddr)) is False

    def test_bitsadmin_needs_notifycmdline_and_target(self):
        from specialized.BitsadminPersistenceConfig import BitsadminPersistenceConfig
        # /SetNotifyCmdLine targeting an ordinary installed-software path
        data = (b'bitsadmin /SetNotifyCmdLine myjob '
                b'C:\\Program Files\\Vendor\\update.exe NULL')
        assert BitsadminPersistenceConfig.identify(_FO(data)) is False

    def test_kerberoast_needs_token_and_ldap_filter(self):
        from specialized.KerberoastConfig import KerberoastConfig
        token_only = b'System.IdentityModel.Tokens.KerberosRequestorSecurityToken' + b'\x00' * 16
        filter_only = b'(&(objectClass=user)(servicePrincipalName=*))' + b'\x00' * 16
        assert KerberoastConfig.identify(_FO(token_only)) is False
        assert KerberoastConfig.identify(_FO(filter_only)) is False

    def test_dcsync_needs_interface_and_rights_guid(self):
        from specialized.DCsyncConfig import DCsyncConfig
        iface_only = b'e3514235-4b06-11d1-ab04-00c04fc2dcd2' + b'\x00' * 16
        rights_only = b'1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' + b'\x00' * 16
        assert DCsyncConfig.identify(_FO(iface_only)) is False
        assert DCsyncConfig.identify(_FO(rights_only)) is False

    def test_antianalysis_needs_2_categories_not_1(self):
        from specialized.AntiAnalysisStrings import AntiAnalysisStrings
        vm_only = b'VBoxService.exe' + b' padding padding padding padding'
        assert AntiAnalysisStrings.identify(_FO(vm_only)) is False


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestTier3EndToEnd:

    @pytest.mark.parametrize('parser_name,tp_file,expect_substr', [
        ('CryptoMinerConfig',          'cryptominer.bin',            'CryptoMiner'),
        ('MetasploitPayload',          'metasploit_payload.bin',     'Metasploit-Stager'),
        ('BitsadminPersistenceConfig', 'bitsadmin_persistence.bat',  'BITS-Persistence'),
        ('KerberoastConfig',           'kerberoast.ps1',             'Kerberoast'),
        ('DCsyncConfig',               'dcsync.txt',                 'DCSync'),
        ('AntiAnalysisStrings',        'anti_analysis.bin',          'AntiAnalysis'),
    ])
    def test_extracts_via_mwcp_scan(self, parser_name, tp_file, expect_substr, lab_samples):
        r = _run_mwcp(os.path.join(_TP, tp_file))
        assert _has_ioc(r), f'{parser_name} produced no IOC: {r}'
        decoded = ' '.join(r.get('decoded', []))
        assert expect_substr in decoded, f'{parser_name}: expected {expect_substr!r} in {decoded!r}'


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestTier3EndToEndFP:
    @pytest.mark.parametrize('fp_file', [
        'benign_pe.bin', 'benign_ps1.ps1', 'benign_macro.vbs', 'benign_binary.bin',
    ])
    def test_no_ioc_from_fp_sample(self, fp_file, lab_samples):
        r = _run_mwcp(os.path.join(_FP, fp_file))
        assert not _has_ioc(r), f'{fp_file} unexpectedly produced an IOC: {r}'
