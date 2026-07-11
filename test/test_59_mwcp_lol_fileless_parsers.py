"""
test_59_mwcp_lol_fileless_parsers.py -- Validation for the 7 Tier 2
living-off-the-land/fileless persistence mwcp parsers.

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
    tp_probe = os.path.join(_TP, 'wmi_persistence.bin')
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
    ('lol_fileless.WMIPersistenceConfig',      'WMIPersistenceConfig',      'wmi_persistence.bin'),
    ('lol_fileless.ScheduledTaskConfig',       'ScheduledTaskConfig',       'scheduled_task.xml'),
    ('lol_fileless.RegistryPersistenceConfig', 'RegistryPersistenceConfig', 'registry_persistence.bin'),
    ('lol_fileless.DefenderExclusionConfig',   'DefenderExclusionConfig',   'defender_exclusion.bin'),
    ('lol_fileless.AMSIPatchConfig',           'AMSIPatchConfig',           'amsi_patch.bin'),
    ('lol_fileless.ETWPatchConfig',            'ETWPatchConfig',            'etw_patch.bin'),
    ('lol_fileless.COMHijackConfig',           'COMHijackConfig',           'com_hijack.bin'),
]


@needs_mwcp
class TestLOLFilelessIdentifyTP:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_identifies_own_tp_sample(self, module_path, parser_name, tp_file, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        assert cls.identify(_FO(_tp_bytes(tp_file))) is True, \
            f'{parser_name} failed to identify its own TP sample ({tp_file})'


@needs_mwcp
class TestLOLFilelessNoFalsePositives:
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
class TestLOLFilelessSingleIndicatorNotEnough:
    """Each parser must require its documented pair of signals -- a lone
    signal (one trigger clause, one flag, one key path) must not fire."""

    def test_wmi_needs_wql_and_consumer(self):
        from lol_fileless.WMIPersistenceConfig import WMIPersistenceConfig
        # WQL trigger alone, no consumer payload field
        data = b'SELECT * FROM __InstanceCreationEvent WITHIN 5' + b'\x00' * 32
        assert WMIPersistenceConfig.identify(_FO(data)) is False

    def test_scheduled_task_needs_hidden_and_encoded(self):
        from lol_fileless.ScheduledTaskConfig import ScheduledTaskConfig
        # Hidden window flag alone, no -EncodedCommand
        xml = (b'<Exec><Command>powershell.exe</Command>'
               b'<Arguments>-WindowStyle Hidden -File script.ps1</Arguments></Exec>')
        assert ScheduledTaskConfig.identify(_FO(xml)) is False

    def test_registry_persistence_needs_key_and_staging_path(self):
        from lol_fileless.RegistryPersistenceConfig import RegistryPersistenceConfig
        # Run key path alone, value targets Program Files (not a staging dir)
        data = (b'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00'
                b'C:\\Program Files\\Vendor\\app.exe\x00')
        assert RegistryPersistenceConfig.identify(_FO(data)) is False

    def test_defender_exclusion_needs_cmdlet_and_staging_path(self):
        from lol_fileless.DefenderExclusionConfig import DefenderExclusionConfig
        # Exclusion cmdlet alone, path is not a staging directory
        data = b'Add-MpPreference -ExclusionPath "C:\\Program Files\\Vendor\\"'
        assert DefenderExclusionConfig.identify(_FO(data)) is False

    def test_amsi_patch_needs_bytes_and_proximity(self):
        from lol_fileless.AMSIPatchConfig import AMSIPatchConfig
        # Patch bytes alone, no AmsiScanBuffer reference nearby
        data = b'\x00' * 200 + b'\xb8\x57\x00\x07\x80\xc3' + b'\x00' * 200
        assert AMSIPatchConfig.identify(_FO(data)) is False

    def test_etw_patch_needs_bytes_and_proximity(self):
        from lol_fileless.ETWPatchConfig import ETWPatchConfig
        # Patch bytes alone, no EtwEventWrite/NtTraceEvent reference nearby
        data = b'\x00' * 200 + b'\x33\xc0\xc3' + b'\x00' * 200
        assert ETWPatchConfig.identify(_FO(data)) is False

    def test_com_hijack_needs_clsid_and_staging_path(self):
        from lol_fileless.COMHijackConfig import COMHijackConfig
        # CLSID/InProcServer32 alone, DLL is not in a staging directory
        data = (b'CLSID\\{12345678-1234-1234-1234-1234567890AB}\\InProcServer32\x00'
                b'C:\\Program Files\\Vendor\\legit.dll\x00')
        assert COMHijackConfig.identify(_FO(data)) is False


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestLOLFilelessEndToEnd:

    @pytest.mark.parametrize('parser_name,tp_file,expect_substr', [
        ('WMIPersistenceConfig',      'wmi_persistence.bin',      'WMI-Persistence'),
        ('ScheduledTaskConfig',       'scheduled_task.xml',       'ScheduledTask-StealthAction'),
        ('RegistryPersistenceConfig', 'registry_persistence.bin', 'RegistryPersistence-StagingPath'),
        ('DefenderExclusionConfig',   'defender_exclusion.bin',   'DefenderExclusion-StagingPath'),
        ('AMSIPatchConfig',           'amsi_patch.bin',           'AMSI-Patch'),
        ('ETWPatchConfig',            'etw_patch.bin',            'ETW-Patch'),
        ('COMHijackConfig',           'com_hijack.bin',           'COMHijack-StagingPath'),
    ])
    def test_extracts_via_mwcp_scan(self, parser_name, tp_file, expect_substr, lab_samples):
        r = _run_mwcp(os.path.join(_TP, tp_file))
        assert _has_ioc(r), f'{parser_name} produced no IOC: {r}'
        decoded = ' '.join(r.get('decoded', []))
        assert expect_substr in decoded, f'{parser_name}: expected {expect_substr!r} in {decoded!r}'


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestLOLFilelessEndToEndFP:
    @pytest.mark.parametrize('fp_file', [
        'benign_pe.bin', 'benign_ps1.ps1', 'benign_macro.vbs', 'benign_binary.bin',
    ])
    def test_no_ioc_from_fp_sample(self, fp_file, lab_samples):
        r = _run_mwcp(os.path.join(_FP, fp_file))
        assert not _has_ioc(r), f'{fp_file} unexpectedly produced an IOC: {r}'
