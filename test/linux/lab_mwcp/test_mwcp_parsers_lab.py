"""mwcp_parsers lab: TP/FP validation for every family across all 6 categories.

Every "mechanism-based, not signature-based" detector here is tested against (a) a
synthetic true-positive shape from generate_samples.py and (b) the shared FP sample
set (benign look-alikes each detector claims to distinguish from). A detector that
only passes (a) is not proven -- catching false positives on (b) is what "beyond a
shadow of a doubt" requires. Two real bugs were caught by exactly this process before
landing: a `\\b` word-boundary in telegram.py that could never match after "bot" (both
are word characters, so there's no boundary), and recovery_inhibition.py accepting a
bare `-f` flag as "forced bulk deletion" when that's standard practice in any
scripted/cron backup-rotation job -- a real routine `lvremove -f` cron sample tripped
it during FP-set validation.
"""
from __future__ import annotations

import glob
import os
import struct
import subprocess
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
_WIN_HUNT = os.path.join(_ROOT, "playbooks", "linux", "threat_hunting")
sys.path.insert(0, _WIN_HUNT)

from mwcp_parsers import driver  # noqa: E402
from mwcp_parsers.c2_frameworks import (adaptix, generic_go_c2, havoc, merlin,  # noqa: E402
                                        mythic, pupy, sliver)
from mwcp_parsers.native import bpfdoor, ebury, mirai_gafgyt, smtp_exfil, xmrig_miner  # noqa: E402
from mwcp_parsers.ransomware import (blackcat_linux, conti_linux, esxi_encryptor,  # noqa: E402
                                     generic_indicators, recovery_inhibition)
from mwcp_parsers.cloud_saas import (discord, dropbox, github, ngrok, pastebin,  # noqa: E402
                                     slack, telegram)
from mwcp_parsers.delivery import base64_elf_dropper, shell_pipeline_stager  # noqa: E402
from mwcp_parsers.specialized import anti_analysis, dns_tunnel  # noqa: E402
from mwcp_parsers._elf_utils import elf_dynamic_symbols  # noqa: E402

TP = os.path.join(_HERE, "samples", "tp")
FP = os.path.join(_HERE, "samples", "fp")
GENERATE = os.path.join(_HERE, "generate_samples.py")


@pytest.fixture(scope="session", autouse=True)
def lab_samples():
    if not os.path.isdir(TP) or not glob.glob(os.path.join(TP, "*.bin")):
        subprocess.run([sys.executable, GENERATE], check=True, timeout=30)


def _tp(name):
    with open(os.path.join(TP, name), "rb") as fh:
        return fh.read()


def _all_fp_samples():
    return [open(f, "rb").read() for f in sorted(glob.glob(os.path.join(FP, "*")))]


# ---------------------------------------------------------------------------
# One test covers every parser against the WHOLE shared FP set -- the strongest,
# cheapest regression guard: any new parser that starts firing on any FP sample fails
# this immediately, regardless of which category it lives in.
# ---------------------------------------------------------------------------
def test_no_parser_fires_on_any_fp_sample():
    for fp_bytes in _all_fp_samples():
        hits = driver.extract_all(fp_bytes)
        assert hits == [], f"unexpected hit(s) on an FP sample: {[h['family'] for h in hits]}"


# ---------------------------------------------------------------------------
# c2_frameworks
# ---------------------------------------------------------------------------
def test_sliver_identifies_tp():
    assert sliver.identify(_tp("sliver.bin")) is True


def test_sliver_requires_multiple_protocol_fields():
    assert sliver.identify(b'"implant_name": "x"') is False
    assert sliver.identify(b'"implant_name": "x", "reconnect_interval": 60, "c2s": []') is True


def test_sliver_does_not_key_on_brand_string():
    assert sliver.identify(b'sliver BishopFox sliver.implant') is False


def test_mythic_identifies_tp_and_requires_2_fields():
    assert mythic.identify(_tp("mythic.bin")) is True
    assert mythic.identify(b'{"PayloadUUID": "abc"}') is False


def test_merlin_identifies_tp_and_requires_2_fields():
    assert merlin.identify(_tp("merlin.bin")) is True
    assert merlin.identify(b'{"psk": "x"}') is False


def test_havoc_identifies_tp():
    assert havoc.identify(_tp("havoc.bin")) is True


def test_adaptix_identifies_tp_and_requires_both_fields():
    assert adaptix.identify(_tp("adaptix.bin")) is True
    assert adaptix.identify(b'{"agent_id": "x"}') is False


def test_pupy_identifies_tp_and_requires_2_markers():
    assert pupy.identify(_tp("pupy.bin")) is True
    assert pupy.identify(b'pupy.pupyimporter\x00') is False


def test_generic_go_c2_identifies_tp_and_requires_build_marker():
    assert generic_go_c2.identify(_tp("generic_go_c2.bin")) is True
    # heartbeat fields alone, no Go build marker -> not flagged
    assert generic_go_c2.identify(b'{"hostname":"x","interval":1,"task_id":"y"}') is False


# ---------------------------------------------------------------------------
# native
# ---------------------------------------------------------------------------
def _make_mirai_table(key: int = 0x37) -> bytes:
    strings = [b'GETLOCALIP', b'PING', b'REPORT', b'/bin/busybox', b'/dev/watchdog',
              b'KILLATTK', b'watchdog', b'HTTPFLOOD', b'UDPFLOOD', b'SYNFLOOD',
              b'attack.c', b'listener', b'scanner', b'telnet', b'admin', b'root',
              b'123456', b'password', b'default', b'enable', b'shell', b'busybox',
              b'STOMP', b'ACKFLOOD', b'GREIP', b'VSE', b'resolv.conf', b'/proc/net/route',
              b'passwordlist', b'joncrypt', b'anime', b'tcpflood', b'udpflood',
              b'dvrHelper', b'ackflood', b'synflood', b'greflood', b'dnsflood']
    blob = b'\x00'.join(strings) + b'\x00'
    return bytes(b ^ key for b in blob)


class TestMiraiXorMechanism:
    def test_detects_xor_obfuscated_table(self):
        blob = os.urandom(1000) + _make_mirai_table() + os.urandom(1000)
        assert mirai_gafgyt.identify(blob) is True
        result = mirai_gafgyt.extract(blob)
        assert result is not None
        assert result['family'] == 'Mirai/Gafgyt-class'
        assert result['decoded_token_count'] >= mirai_gafgyt._XOR_MIN_TOKENS

    def test_no_false_positive_on_random_noise(self):
        assert mirai_gafgyt.identify(os.urandom(70000)) is False

    def test_no_false_positive_on_plaintext_english(self):
        """Plaintext prose has plenty of printable tokens already -- the detector must
        require the XOR'd version to be a marked IMPROVEMENT over the raw baseline,
        not just 'some printable strings exist'."""
        prose = (b'The quick brown fox jumps over the lazy dog. ' * 200)
        assert mirai_gafgyt.identify(prose) is False

    def test_recovers_correct_key(self):
        blob = _make_mirai_table(key=0x54)
        result = mirai_gafgyt.extract(blob)
        assert result is not None
        assert result['xor_key'] == hex(0x54)

    def test_known_tokens_are_corroboration_not_gate(self):
        """A table using words NOT in the known-vocabulary list must still be detected
        by the structural mechanism alone."""
        strings = [b'FOOBARBAZ', b'QUXQUUXCORGE', b'GRAULTGARPLY', b'WALDOFRED',
                   b'PLUGHXYZZY', b'THUDBLARG', b'ZORPFRIZZLE', b'SNARFBLATT',
                   b'WIBBLEWOBBLE', b'FLIBBERGIBBET', b'CRANKYPANTS', b'MUMBLEJUMBLE',
                   b'SPUTTERGRIND', b'WHIZBANGBOOM', b'CLATTERTRAP', b'GIZMODOODAD',
                   b'THINGAMAJIG', b'WHATCHAMACALL', b'DOOHICKEYBOB', b'GADGETRONIC',
                   b'BLIBBERSNOOT', b'FROBULATOR', b'ZIGZAGBOOMBASTIC', b'KERPLUNKERINO',
                   b'SPLONKAMAJIGGER', b'WHATSITCALLED', b'THINGYMABOBBER']
        blob = b'\x00'.join(strings) + b'\x00'
        xored = bytes(b ^ 0x91 for b in blob)
        result = mirai_gafgyt.extract(xored)
        assert result is not None
        assert result['known_token_hits'] == []
        assert result['decoded_token_count'] >= mirai_gafgyt._XOR_MIN_TOKENS


def _build_elf64_with_dynsym(defined_names, undefined_names):
    """Minimal, genuinely parseable ELF64 object with a real SHT_DYNSYM/SHT_STRTAB
    section pair -- ground truth for the ELF parser, not a byte-soup approximation."""
    dynstr = b'\x00'
    name_offsets = {}
    for n in defined_names + undefined_names:
        name_offsets[n] = len(dynstr)
        dynstr += n.encode() + b'\x00'

    def sym_entry(name_off, shndx):
        return struct.pack('<IBBHQQ', name_off, 0x10, 0, shndx, 0, 0)
    dynsym = sym_entry(0, 0)
    for n in defined_names:
        dynsym += sym_entry(name_offsets[n], 1)
    for n in undefined_names:
        dynsym += sym_entry(name_offsets[n], 0)

    dynsym_off = 64
    dynstr_off = dynsym_off + len(dynsym)
    shoff = dynstr_off + len(dynstr)

    def sh_entry(sh_type, link, offset, size, entsize):
        return struct.pack('<IIQQQQIIQQ', 0, sh_type, 0, 0, offset, size, link, 0, 0, entsize)
    shdrs = (sh_entry(0, 0, 0, 0, 0) +
            sh_entry(11, 2, dynsym_off, len(dynsym), 24) +
            sh_entry(3, 0, dynstr_off, len(dynstr), 0))

    e_ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8
    header = e_ident + struct.pack('<HHIQQQIHHHHHH',
        3, 0x3e, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 0)
    return header + dynsym + dynstr + shdrs


class TestEburyELFVerification:
    def test_clean_keyutils_shape_not_flagged(self):
        elf = _build_elf64_with_dynsym(
            defined_names=['keyctl', 'add_key', 'request_key', 'find_key_by_type_and_desc'],
            undefined_names=['malloc', 'free', 'memcmp', 'syscall'])
        assert ebury.identify(elf) is False

    def test_trojanized_keyutils_shape_flagged_and_verified(self):
        elf = _build_elf64_with_dynsym(
            defined_names=['keyctl', 'add_key', 'request_key'],
            undefined_names=['connect', 'getaddrinfo', 'socket', 'malloc'])
        assert ebury.identify(elf) is True
        result = ebury.extract(elf)
        assert result['verified'] is True
        assert set(result['keyutils_api_present']) == {'keyctl', 'add_key', 'request_key'}

    def test_network_imports_alone_without_keyutils_exports_not_flagged(self):
        elf = _build_elf64_with_dynsym(
            defined_names=['main_helper'],
            undefined_names=['connect', 'getaddrinfo', 'socket', 'malloc'])
        assert ebury.identify(elf) is False

    def test_keyutils_exports_alone_without_network_imports_not_flagged(self):
        elf = _build_elf64_with_dynsym(
            defined_names=['keyctl', 'add_key', 'request_key'],
            undefined_names=['malloc', 'free', 'strlen'])
        assert ebury.identify(elf) is False


class TestElfDynamicSymbolsParser:
    def test_returns_none_on_non_elf(self):
        assert elf_dynamic_symbols(os.urandom(5000)) is None
        assert elf_dynamic_symbols(b'') is None

    def test_section_header_path_matches_expected_sets(self):
        elf = _build_elf64_with_dynsym(
            defined_names=['foo', 'bar'], undefined_names=['baz', 'qux'])
        result = elf_dynamic_symbols(elf)
        defined, undefined = result
        assert defined == {'foo', 'bar'}
        assert undefined == {'baz', 'qux'}


class TestEburyCapabilityMismatchFallback:
    def test_detects_capability_mismatch(self):
        blob = b'keyctl\x00add_key\x00request_key\x00connect\x00getaddrinfo\x00socket\x00'
        assert ebury.identify(blob) is True
        result = ebury.extract(blob)
        assert result['verified'] is False

    def test_does_not_check_family_name_string(self):
        assert ebury.identify(b'ebury\x00libkeyutils.so.1.9\x00') is False


class TestBPFDoorMagicSequence:
    def test_detects_magic_sequence(self):
        assert bpfdoor.identify(_tp("bpfdoor.bin")) is True

    def test_no_false_positive_on_random_noise(self):
        assert bpfdoor.identify(os.urandom(5000)) is False

    def test_no_false_positive_on_generic_packet_capture_strings(self):
        blob = b'setsockopt\x00iptable_filter\x00BPF_SOCKET_FILTER\x00' + os.urandom(500)
        assert bpfdoor.identify(blob) is False


def test_xmrig_identifies_tp():
    assert xmrig_miner.identify(_tp("xmrig.bin")) is True


def test_smtp_exfil_requires_full_context_cluster():
    hits = smtp_exfil.extract(_tp("smtp_exfil.bin"))
    assert len(hits) == 1
    assert hits[0]['password']


def test_smtp_exfil_host_alone_is_not_enough():
    assert smtp_exfil.extract(b'smtp.test.com\x00') == []


# ---------------------------------------------------------------------------
# ransomware
# ---------------------------------------------------------------------------
def test_esxi_encryptor_identifies_tp():
    assert esxi_encryptor.identify(_tp("esxi_encryptor.bin")) is True


def test_esxi_encryptor_single_signal_alone_not_enough():
    # extension cluster alone (no kill-sequence, no snapshot removal)
    assert esxi_encryptor.identify(b'.vmdk\x00.vmx\x00.vmsn\x00.vswp\x00') is False


def test_recovery_inhibition_identifies_tp():
    assert recovery_inhibition.identify(_tp("recovery_inhibition.bin")) is True


def test_recovery_inhibition_bare_forced_delete_not_enough():
    """The bug caught during FP validation: a single -f flag is routine cron/backup
    housekeeping and must not be sufficient alone."""
    assert recovery_inhibition.identify(b'lvremove -f /dev/vg0/old_snap') is False


def test_generic_ransomware_indicators_identifies_tp():
    assert generic_indicators.identify(_tp("ransomware_generic.bin")) is True


def test_generic_ransomware_indicators_single_signal_not_enough():
    assert generic_indicators.identify(b'-----BEGIN PUBLIC KEY-----\x00') is False


def test_conti_linux_requires_mode_and_sibling_flag():
    assert conti_linux.identify(_tp("conti_linux.bin")) is True
    assert conti_linux.identify(b'-m all') is False           # mode flag alone


def test_blackcat_linux_requires_4_of_10_fields():
    assert blackcat_linux.identify(_tp("blackcat_linux.bin")) is True
    assert blackcat_linux.identify(b'{"config_id": "x", "public_key": "y"}' + b' ' * 130) is False


# ---------------------------------------------------------------------------
# cloud_saas
# ---------------------------------------------------------------------------
def test_telegram_identifies_tp():
    assert telegram.identify(_tp("telegram.bin")) is True


def test_telegram_requires_valid_token_length():
    # 34-char token (one short of the required 35) must NOT match
    short = b'https://api.telegram.org/bot123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/sendMessage'
    assert telegram.identify(short) is False


def test_discord_identifies_tp():
    assert discord.identify(_tp("discord.bin")) is True


def test_discord_url_alone_without_payload_field_not_enough():
    wid = '3' * 18
    token = 'C' * 68
    url = f'https://discord.com/api/webhooks/{wid}/{token}'.encode()
    assert discord.identify(url) is False


def test_slack_identifies_tp():
    assert slack.identify(_tp("slack.bin")) is True


def test_dropbox_identifies_tp():
    assert dropbox.identify(_tp("dropbox.bin")) is True


def test_dropbox_endpoint_alone_without_header_not_enough():
    assert dropbox.identify(b'content.dropboxapi.com/2/files/upload') is False


def test_github_identifies_tp():
    assert github.identify(_tp("github.bin")) is True


def test_pastebin_identifies_tp():
    assert pastebin.identify(_tp("pastebin.bin")) is True


def test_ngrok_identifies_tp():
    assert ngrok.identify(_tp("ngrok.bin")) is True


def test_ngrok_domain_alone_without_agent_config_not_enough():
    assert ngrok.identify(b'a1b2c3d4.ngrok-free.app') is False


# ---------------------------------------------------------------------------
# delivery
# ---------------------------------------------------------------------------
def test_shell_pipeline_stager_identifies_tp():
    assert shell_pipeline_stager.identify(_tp("shell_pipeline_stager.bin")) is True


def test_shell_pipeline_stager_requires_actual_pipe_relationship():
    """curl with a URL, and bash somewhere else in the file, but NOT piped together --
    must not fire on mere co-occurrence."""
    blob = b'curl -s https://example.com/status > /tmp/s.txt\x00bash /opt/app/run.sh\x00'
    assert shell_pipeline_stager.identify(blob) is False


def test_base64_elf_dropper_identifies_tp():
    assert base64_elf_dropper.identify(_tp("base64_elf_dropper.bin")) is True


def test_base64_elf_dropper_decode_alone_not_enough():
    assert base64_elf_dropper.identify(b'base64 -d config.b64 > /etc/app/config.json') is False


# ---------------------------------------------------------------------------
# specialized
# ---------------------------------------------------------------------------
def test_anti_analysis_identifies_tp():
    assert anti_analysis.identify(_tp("anti_analysis.bin")) is True


def test_anti_analysis_field_name_alone_not_enough():
    assert anti_analysis.identify(b'TracerPid:\x00') is False


def test_dns_tunnel_identifies_tp():
    assert dns_tunnel.identify(_tp("dns_tunnel.bin")) is True


def test_dns_tunnel_label_alone_without_resolver_api_not_enough():
    label = 'B' * 40
    assert dns_tunnel.identify(f'{label}.exfil.test'.encode()) is False


# ---------------------------------------------------------------------------
# driver end-to-end
# ---------------------------------------------------------------------------
def test_extract_all_never_raises_on_garbage():
    assert driver.extract_all(b'') == []
    assert driver.extract_all(os.urandom(10000)) == []


def test_to_findings_produces_common_schema():
    hits = [{'family': 'Sliver', 'c2_urls': ['mtls://1.2.3.4:443'], 'implant_name': 'x'}]
    findings = driver.to_findings(hits, 'PID 1234 (implant)')
    assert len(findings) == 1
    f = findings[0]
    for key in ('Timestamp', 'Severity', 'Type', 'Target', 'Details', 'MITRE'):
        assert key in f
    assert f['Type'] == 'C2 Config Recovered (Sliver, memory)'


def test_bpfdoor_finding_is_critical_severity():
    hits = [{'family': 'BPFDoor', 'magic_sequence': 'deadbeef', 'note': 'x'}]
    findings = driver.to_findings(hits, 'PID 1 (x)')
    assert findings[0]['Severity'] == 'Critical'


def test_ransomware_finding_is_critical_severity():
    hits = driver.extract_all(_tp("esxi_encryptor.bin"))
    findings = driver.to_findings(hits, 'PID 1 (encryptor)')
    assert findings and findings[0]['Severity'] == 'Critical'
    assert 'Ransomware Indicators Recovered' in findings[0]['Type']


def test_cloud_saas_finding_is_high_severity():
    hits = driver.extract_all(_tp("telegram.bin"))
    findings = driver.to_findings(hits, 'PID 1 (implant)')
    assert findings and findings[0]['Severity'] == 'High'
    assert 'Cloud SaaS C2 Channel Recovered' in findings[0]['Type']


def test_multiple_families_can_coexist():
    blob = (_make_mirai_table() + os.urandom(200) +
           b'keyctl\x00add_key\x00request_key\x00connect\x00socket\x00getaddrinfo\x00')
    hits = driver.extract_all(blob)
    families = {h['family'] for h in hits}
    assert 'Mirai/Gafgyt-class' in families
    assert any('Ebury-class' in f for f in families)


def test_all_tp_samples_produce_at_least_one_hit():
    """Every generated TP sample must produce at least one finding through the full
    driver pipeline -- catches a parser that's wired into MODULES but silently never
    fires end-to-end (as opposed to the per-family identify() tests above, which call
    the module directly)."""
    for fp in sorted(glob.glob(os.path.join(TP, "*"))):
        data = open(fp, "rb").read()
        hits = driver.extract_all(data)
        assert hits, f"no hit at all for TP sample {os.path.basename(fp)}"
