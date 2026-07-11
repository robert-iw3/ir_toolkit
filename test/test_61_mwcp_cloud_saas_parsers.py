"""
test_61_mwcp_cloud_saas_parsers.py -- Validation for the 6 Tier 2
cloud/SaaS C2 mwcp parsers (legitimate cloud services abused as a
covert C2 channel).

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
    tp_probe = os.path.join(_TP, 'slack_c2.ps1')
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


def _run_mwcp_errors(module_path: str, parser_name: str, file_path: str):
    """Run a single parser directly via mwcp.run() and return (metadata, errors)
    -- catches exceptions inside run() (e.g. bad metadata kwargs) that identify()
    alone can't surface, since identify() and run() are separate code paths."""
    mod = importlib.import_module(module_path)
    result = mwcp.run(parser_name, file_path=file_path)
    d = result.as_dict()
    return d.get('metadata', []), d.get('errors', [])


_PARSER_TP_FILE = [
    ('cloud_saas.SlackC2Config',      'SlackC2Config',      'slack_c2.ps1'),
    ('cloud_saas.TeamsDriveC2Config', 'TeamsDriveC2Config', 'teams_c2.ps1'),
    ('cloud_saas.GoogleSheetC2Config','GoogleSheetC2Config','googlesheet_c2.ps1'),
    ('cloud_saas.DropboxC2Config',    'DropboxC2Config',    'dropbox_c2.ps1'),
    ('cloud_saas.GitHubC2Config',     'GitHubC2Config',     'github_c2.ps1'),
    ('cloud_saas.PastebinC2Config',   'PastebinC2Config',   'pastebin_c2.ps1'),
]


@needs_mwcp
class TestCloudSaaSIdentifyTP:
    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_identifies_own_tp_sample(self, module_path, parser_name, tp_file, lab_samples):
        mod = importlib.import_module(module_path)
        cls = getattr(mod, parser_name)
        assert cls.identify(_FO(_tp_bytes(tp_file))) is True, \
            f'{parser_name} failed to identify its own TP sample ({tp_file})'


@needs_mwcp
class TestCloudSaaSNoRunExceptions:
    """identify() passing is not enough -- run() must actually execute
    without exceptions and produce metadata (guards against constructor/
    kwarg mistakes on report.add() calls that identify() alone can't catch)."""

    @pytest.mark.parametrize('module_path,parser_name,tp_file', _PARSER_TP_FILE)
    def test_run_produces_metadata_without_errors(self, module_path, parser_name, tp_file, lab_samples):
        metadata, errors = _run_mwcp_errors(
            module_path, parser_name, os.path.join(_TP, tp_file))
        assert not errors, f'{parser_name}.run() raised: {errors}'
        assert metadata, f'{parser_name}.run() produced no metadata for {tp_file}'


@needs_mwcp
class TestCloudSaaSNoFalsePositives:
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
class TestCloudSaaSSingleIndicatorNotEnough:
    """Each parser must require its documented pair of signals -- a lone
    signal (one token format, one API endpoint) must not fire."""

    def test_slack_needs_token_and_api_target(self):
        from cloud_saas.SlackC2Config import SlackC2Config
        token_only = b'xoxb-1234567890-1234567890-abcdefghijklmnopqrstuvwx'
        api_only = b'https://slack.com/api/chat.postMessage'
        assert SlackC2Config.identify(_FO(token_only)) is False
        assert SlackC2Config.identify(_FO(api_only)) is False

    def test_teams_needs_webhook_and_card_schema(self):
        from cloud_saas.TeamsDriveC2Config import TeamsDriveC2Config
        webhook_only = b'https://contoso.webhook.office.com/webhookb2/abc@def/IncomingWebhook/xyz'
        card_only = b'"@type":"MessageCard"'
        assert TeamsDriveC2Config.identify(_FO(webhook_only)) is False
        assert TeamsDriveC2Config.identify(_FO(card_only)) is False

    def test_googlesheet_needs_api_and_key(self):
        from cloud_saas.GoogleSheetC2Config import GoogleSheetC2Config
        api_only = b'https://sheets.googleapis.com/v4/spreadsheets/1a2b3c4d5e'
        key_only = b'AIzaSyD1234567890abcdefghijklmnopqrstuv'
        assert GoogleSheetC2Config.identify(_FO(api_only)) is False
        assert GoogleSheetC2Config.identify(_FO(key_only)) is False

    def test_dropbox_needs_api_and_header(self):
        from cloud_saas.DropboxC2Config import DropboxC2Config
        api_only = b'https://content.dropboxapi.com/2/files/upload'
        header_only = b'Dropbox-API-Arg: {"path":"/x"}'
        assert DropboxC2Config.identify(_FO(api_only)) is False
        assert DropboxC2Config.identify(_FO(header_only)) is False

    def test_github_needs_pat_and_api_target(self):
        from cloud_saas.GitHubC2Config import GitHubC2Config
        pat_only = b'ghp_' + b'A' * 36
        api_only = b'https://api.github.com/gists'
        assert GitHubC2Config.identify(_FO(pat_only)) is False
        assert GitHubC2Config.identify(_FO(api_only)) is False

    def test_pastebin_needs_url_and_fetch_primitive(self):
        from cloud_saas.PastebinC2Config import PastebinC2Config
        url_only = b'https://pastebin.com/raw/aB3dE9fG'
        fetch_only = b'Invoke-WebRequest -Uri $url'
        assert PastebinC2Config.identify(_FO(url_only)) is False
        assert PastebinC2Config.identify(_FO(fetch_only)) is False


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestCloudSaaSEndToEnd:

    @pytest.mark.parametrize('parser_name,tp_file,expect_substr', [
        ('SlackC2Config',      'slack_c2.ps1',       'Slack-C2'),
        ('TeamsDriveC2Config', 'teams_c2.ps1',       'Teams-C2'),
        ('GoogleSheetC2Config','googlesheet_c2.ps1', 'GoogleSheets-C2'),
        ('DropboxC2Config',    'dropbox_c2.ps1',     'Dropbox-C2'),
        ('GitHubC2Config',     'github_c2.ps1',      'GitHub-C2'),
        ('PastebinC2Config',   'pastebin_c2.ps1',    'Pastebin-C2'),
    ])
    def test_extracts_via_mwcp_scan(self, parser_name, tp_file, expect_substr, lab_samples):
        r = _run_mwcp(os.path.join(_TP, tp_file))
        assert _has_ioc(r), f'{parser_name} produced no IOC: {r}'
        decoded = ' '.join(r.get('decoded', []))
        assert expect_substr in decoded, f'{parser_name}: expected {expect_substr!r} in {decoded!r}'


@pytest.mark.skipif(not (os.path.isfile(_MWCP_SCAN) and _mwcp_ok),
                    reason='mwcp_scan.py or mwcp not available')
class TestCloudSaaSEndToEndFP:
    @pytest.mark.parametrize('fp_file', [
        'benign_pe.bin', 'benign_ps1.ps1', 'benign_macro.vbs', 'benign_binary.bin',
    ])
    def test_no_ioc_from_fp_sample(self, fp_file, lab_samples):
        r = _run_mwcp(os.path.join(_FP, fp_file))
        assert not _has_ioc(r), f'{fp_file} unexpectedly produced an IOC: {r}'
