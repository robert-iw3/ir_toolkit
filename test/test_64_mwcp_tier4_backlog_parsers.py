"""
test_64_mwcp_tier4_backlog_parsers.py -- Validation for the 7 Tier 4
post-exploitation/lateral-movement/commodity-crimeware mwcp parsers.

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
    tp_probe = os.path.join(_TP, 'lsass_dump.bin')
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
    ('specialized.LSASSDumpConfig',            'LSASSDumpConfig',            'lsass_dump.bin'),
    ('specialized.RubeusTicketConfig',         'RubeusTicketConfig',         'rubeus_ticket.bin'),
    ('specialized.PsExecServiceConfig',        'PsExecServiceConfig',        'psexec_service.bin'),
    ('specialized.BloodHoundCollectionConfig', 'BloodHoundCollectionConfig', 'bloodhound_collection.bin'),
    ('specialized.ClipboardHijackConfig',      'ClipboardHijackConfig',      'clipboard_hijack.bin'),
    ('specialized.DNSTunnelC2Config',          'DNSTunnelC2Config',          'dns_tunnel.bin'),
    ('cloud_saas.NgrokTunnelConfig',           'NgrokTunnelConfig',          'ngrok_tunnel.ps1'),
]


@needs_mwcp
class TestTier4IdentifyTP:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_identifies_own_tp_sample(self, module_path, parser_name, tp_file, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        assert cls.identify(_FO(_tp_bytes(tp_file))) is True, \
            f'{parser_name} failed to identify its own TP sample ({tp_file})'


@needs_mwcp
class TestTier4NoRunExceptions:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_run_produces_metadata_without_errors(self, module_path, parser_name, tp_file, lab_samples):
        metadata, errors = _run_mwcp_errors(parser_name, os.path.join(_TP, tp_file))
        assert not errors, f'{parser_name}.run() raised: {errors}'
        assert metadata, f'{parser_name}.run() produced no metadata for {tp_file}'


@needs_mwcp
class TestTier4NoFalsePositives:
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
class TestTier4SingleIndicatorNotEnough:
    """Each parser must require its documented pair of signals -- a lone
    signal (one API name, one flag, one OID) must not fire."""

    def test_lsass_dump_needs_api_and_target(self):
        from specialized.LSASSDumpConfig import LSASSDumpConfig
        api_only = b'MiniDumpWriteDump(hProcess, pid, hFile, 2, 0, 0, 0);' + b'\x00' * 16
        target_only = b'C:\\Windows\\System32\\lsass.exe' + b'\x00' * 16
        assert LSASSDumpConfig.identify(_FO(api_only)) is False
        assert LSASSDumpConfig.identify(_FO(target_only)) is False

    def test_rubeus_needs_ptt_and_krbcred(self):
        from specialized.RubeusTicketConfig import RubeusTicketConfig
        ptt_only = b'Rubeus.exe asktgt /user:admin /ptt' + b'\x00' * 16
        cred_only = b'\x76\x82\x05\x00' + b'\x00' * 16
        assert RubeusTicketConfig.identify(_FO(ptt_only)) is False
        assert RubeusTicketConfig.identify(_FO(cred_only)) is False

    def test_psexec_needs_pipe_and_staging_path(self):
        from specialized.PsExecServiceConfig import PsExecServiceConfig
        pipe_only = b'PSEXESVC' + b'\x00' * 16
        path_only = b'C:\\Users\\LabUser\\AppData\\Local\\Temp\\svc.exe' + b'\x00' * 16
        assert PsExecServiceConfig.identify(_FO(pipe_only)) is False
        assert PsExecServiceConfig.identify(_FO(path_only)) is False

    def test_bloodhound_needs_filter_and_oid(self):
        from specialized.BloodHoundCollectionConfig import BloodHoundCollectionConfig
        filter_only = b'(objectClass=*)' + b'\x00' * 16
        oid_only = b'1.2.840.113556.1.4.801' + b'\x00' * 16
        assert BloodHoundCollectionConfig.identify(_FO(filter_only)) is False
        assert BloodHoundCollectionConfig.identify(_FO(oid_only)) is False

    def test_clipboard_hijack_needs_apis_and_2_categories(self):
        from specialized.ClipboardHijackConfig import ClipboardHijackConfig
        # both APIs, only ONE address category (BTC) -- not enough
        one_cat = (b'SetClipboardData(CF_TEXT, hMem);GetClipboardData(CF_TEXT);'
                   b'1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa')
        assert ClipboardHijackConfig.identify(_FO(one_cat)) is False
        # 2 categories, only ONE API
        one_api = b'SetClipboardData(CF_TEXT, hMem);1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa0x' + b'a' * 40
        assert ClipboardHijackConfig.identify(_FO(one_api)) is False

    def test_dns_tunnel_needs_txt_query_and_encoded_label(self):
        from specialized.DNSTunnelC2Config import DNSTunnelC2Config
        query_only = b'Resolve-DnsName -Name example.com -Type TXT' + b'\x00' * 16
        label_only = (b'A' * 40) + b'.example.com' + b'\x00' * 16
        assert DNSTunnelC2Config.identify(_FO(query_only)) is False
        assert DNSTunnelC2Config.identify(_FO(label_only)) is False

    def test_ngrok_needs_domain_and_config_schema(self):
        from cloud_saas.NgrokTunnelConfig import NgrokTunnelConfig
        domain_only = b'https://a1b2c3d4.ngrok.io' + b'\x00' * 16
        config_only = b'proto: tcp\naddr: 127.0.0.1:4444' + b'\x00' * 16
        assert NgrokTunnelConfig.identify(_FO(domain_only)) is False
        assert NgrokTunnelConfig.identify(_FO(config_only)) is False


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestTier4EndToEnd:

    @pytest.mark.parametrize('parser_name,tp_file,expect_substr', [
        ('LSASSDumpConfig',            'lsass_dump.bin',             'LSASS-Dump'),
        ('RubeusTicketConfig',         'rubeus_ticket.bin',          'Rubeus-PTT'),
        ('PsExecServiceConfig',        'psexec_service.bin',         'PsExec-Staging'),
        ('BloodHoundCollectionConfig', 'bloodhound_collection.bin',  'AD-Collection'),
        ('ClipboardHijackConfig',      'clipboard_hijack.bin',       'Clipboard-Hijack'),
        ('DNSTunnelC2Config',          'dns_tunnel.bin',             'DNS-Tunnel'),
        ('NgrokTunnelConfig',          'ngrok_tunnel.ps1',           'Ngrok-C2'),
    ])
    def test_extracts_via_mwcp_scan(self, parser_name, tp_file, expect_substr, lab_samples):
        r = _run_mwcp(os.path.join(_TP, tp_file))
        assert _has_ioc(r), f'{parser_name} produced no IOC: {r}'
        decoded = ' '.join(r.get('decoded', []))
        assert expect_substr in decoded, f'{parser_name}: expected {expect_substr!r} in {decoded!r}'


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestTier4EndToEndFP:
    @pytest.mark.parametrize('fp_file', [
        'benign_pe.bin', 'benign_ps1.ps1', 'benign_macro.vbs', 'benign_binary.bin',
    ])
    def test_no_ioc_from_fp_sample(self, fp_file, lab_samples):
        r = _run_mwcp(os.path.join(_FP, fp_file))
        assert not _has_ioc(r), f'{fp_file} unexpectedly produced an IOC: {r}'
