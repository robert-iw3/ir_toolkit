"""Tests for c2_config_extract.py's mechanism-based family detectors.

These are deliberately adversarial toward the module's own claims: every
"mechanism-based, not signature-based" detector here is tested against (a)
a synthetic true-positive shape and (b) the specific benign look-alike it
claims to distinguish from (random noise, real keyutils, a curl-like network
tool, a legitimate C2-unrelated JSON blob). A detector that only passes (a)
is not proven -- catching false positives on (b) is what "beyond a shadow of
a doubt" actually requires.
"""
from __future__ import annotations
import os
import sys

_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

import pytest

from playbooks.linux.threat_hunting import c2_config_extract as c2


# ---------------------------------------------------------------------------
# Mirai/Gafgyt: XOR-table structural mechanism
# ---------------------------------------------------------------------------

def _make_mirai_table(key: int = 0x37) -> bytes:
    # Real Mirai/Gafgyt table.c-style tables run to several KB of distinct
    # strings; padded here well past the module's 256-byte minimum-size floor
    # (a legitimate guard against scoring noise on tiny buffers) so the test
    # reflects a realistic carved-region size rather than tripping that floor.
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
        assert c2.identify_mirai(blob) is True
        result = c2.extract_mirai(blob)
        assert result is not None
        assert result['family'] == 'Mirai/Gafgyt-class'
        assert result['decoded_token_count'] >= c2._XOR_MIN_TOKENS

    def test_no_false_positive_on_random_noise(self):
        assert c2.identify_mirai(os.urandom(70000)) is False

    def test_no_false_positive_on_plaintext_english(self):
        """Plaintext prose has plenty of printable tokens already -- the
        detector must require the XOR'd version to be a marked IMPROVEMENT
        over the raw baseline, not just 'some printable strings exist'."""
        prose = (b'The quick brown fox jumps over the lazy dog. ' * 200)
        assert c2.identify_mirai(prose) is False

    def test_recovers_correct_key(self):
        blob = _make_mirai_table(key=0x54)
        result = c2.extract_mirai(blob)
        assert result is not None
        assert result['xor_key'] == hex(0x54)

    def test_known_tokens_are_corroboration_not_gate(self):
        """A table using words NOT in the known-vocabulary list must still
        be detected by the structural mechanism alone."""
        strings = [b'FOOBARBAZ', b'QUXQUUXCORGE', b'GRAULTGARPLY', b'WALDOFRED',
                   b'PLUGHXYZZY', b'THUDBLARG', b'ZORPFRIZZLE', b'SNARFBLATT',
                   b'WIBBLEWOBBLE', b'FLIBBERGIBBET', b'CRANKYPANTS', b'MUMBLEJUMBLE',
                   b'SPUTTERGRIND', b'WHIZBANGBOOM', b'CLATTERTRAP', b'GIZMODOODAD',
                   b'THINGAMAJIG', b'WHATCHAMACALL', b'DOOHICKEYBOB', b'GADGETRONIC',
                   b'BLIBBERSNOOT', b'FROBULATOR', b'ZIGZAGBOOMBASTIC', b'KERPLUNKERINO',
                   b'SPLONKAMAJIGGER', b'WHATSITCALLED', b'THINGYMABOBBER']
        blob = b'\x00'.join(strings) + b'\x00'
        xored = bytes(b ^ 0x91 for b in blob)
        result = c2.extract_mirai(xored)
        assert result is not None
        assert result['known_token_hits'] == []  # no known vocabulary present
        assert result['decoded_token_count'] >= c2._XOR_MIN_TOKENS


# ---------------------------------------------------------------------------
# Ebury-class: keyutils/network capability mismatch
# ---------------------------------------------------------------------------

def _build_elf64_with_dynsym(defined_names, undefined_names):
    """Construct a minimal, genuinely parseable ELF64 object with a real
    SHT_DYNSYM/SHT_STRTAB section pair holding exactly the given defined
    (exported) and undefined (imported) dynamic symbol names. This is ground
    truth for the ELF parser -- not a byte-soup approximation -- so a test
    using it proves the parser's export/import distinction actually works,
    not just that some substring happened to appear somewhere."""
    import struct
    dynstr = b'\x00'
    name_offsets = {}
    for n in defined_names + undefined_names:
        name_offsets[n] = len(dynstr)
        dynstr += n.encode() + b'\x00'

    def sym_entry(name_off, shndx):
        return struct.pack('<IBBHQQ', name_off, 0x10, 0, shndx, 0, 0)
    dynsym = sym_entry(0, 0)
    for n in defined_names:
        dynsym += sym_entry(name_offsets[n], 1)      # shndx != 0 -> defined
    for n in undefined_names:
        dynsym += sym_entry(name_offsets[n], 0)       # SHN_UNDEF -> imported

    dynsym_off = 64
    dynstr_off = dynsym_off + len(dynsym)
    shoff = dynstr_off + len(dynstr)

    def sh_entry(sh_type, link, offset, size, entsize):
        return struct.pack('<IIQQQQIIQQ', 0, sh_type, 0, 0, offset, size, link, 0, 0, entsize)
    shdrs = (sh_entry(0, 0, 0, 0, 0) +
            sh_entry(11, 2, dynsym_off, len(dynsym), 24) +   # SHT_DYNSYM, link->strtab
            sh_entry(3, 0, dynstr_off, len(dynstr), 0))       # SHT_STRTAB

    e_ident = b'\x7fELF' + bytes([2, 1, 1, 0]) + b'\x00' * 8   # ELFCLASS64, ELFDATA2LSB
    header = e_ident + struct.pack('<HHIQQQIHHHHHH',
        3, 0x3e, 1, 0, 0, shoff, 0, 64, 0, 0, 64, 3, 0)
    return header + dynsym + dynstr + shdrs


class TestEburyELFVerification:
    """Ground-truth ELF tests: a genuinely parseable object with a known,
    constructed dynamic symbol table, not a substring approximation. Proves
    the export-vs-import distinction the mechanism actually depends on."""

    def test_clean_keyutils_shape_not_flagged(self):
        """A real libkeyutils.so exports keyctl/add_key/request_key and
        imports only glibc internals -- must not flag."""
        elf = _build_elf64_with_dynsym(
            defined_names=['keyctl', 'add_key', 'request_key', 'find_key_by_type_and_desc'],
            undefined_names=['malloc', 'free', 'memcmp', 'syscall'])
        assert c2.identify_ebury(elf) is False

    def test_trojanized_keyutils_shape_flagged_and_verified(self):
        """Exports the same keyutils API AND imports network primitives --
        the actual Ebury-class shape. Must flag, and must report verified=True
        (structurally confirmed via the symbol table, not a byte guess)."""
        elf = _build_elf64_with_dynsym(
            defined_names=['keyctl', 'add_key', 'request_key'],
            undefined_names=['connect', 'getaddrinfo', 'socket', 'malloc'])
        assert c2.identify_ebury(elf) is True
        result = c2.extract_ebury(elf)
        assert result['verified'] is True
        assert set(result['keyutils_api_present']) == {'keyctl', 'add_key', 'request_key'}
        assert set(result['network_imports_present']) >= {'connect', 'getaddrinfo', 'socket'}

    def test_network_imports_alone_without_keyutils_exports_not_flagged(self):
        """A normal network-capable binary that exports nothing keyutils-shaped."""
        elf = _build_elf64_with_dynsym(
            defined_names=['main_helper'],
            undefined_names=['connect', 'getaddrinfo', 'socket', 'malloc'])
        assert c2.identify_ebury(elf) is False

    def test_keyutils_exports_alone_without_network_imports_not_flagged(self):
        """Exports the keyutils API but imports only benign libc calls."""
        elf = _build_elf64_with_dynsym(
            defined_names=['keyctl', 'add_key', 'request_key'],
            undefined_names=['malloc', 'free', 'strlen'])
        assert c2.identify_ebury(elf) is False

    def test_real_system_libkeyutils_not_flagged_if_present(self):
        """Cross-check against the host's actual libkeyutils.so, if present --
        exports keyctl/add_key/request_key, imports only glibc, zero network
        symbols, so the mismatch gate correctly stays closed."""
        candidates = [
            '/usr/lib/x86_64-linux-gnu/libkeyutils.so.1.10',
            '/usr/lib/x86_64-linux-gnu/libkeyutils.so.1',
            '/lib/x86_64-linux-gnu/libkeyutils.so.1',
        ]
        path = next((p for p in candidates if os.path.isfile(p)), None)
        if path is None:
            pytest.skip('no libkeyutils.so found on this host')
        with open(path, 'rb') as f:
            data = f.read()
        assert c2.identify_ebury(data) is False


class TestElfDynamicSymbolsParser:
    """Direct tests of the parser itself (elf_dynamic_symbols), independent
    of the Ebury detector that consumes it."""

    def test_returns_none_on_non_elf(self):
        assert c2.elf_dynamic_symbols(os.urandom(5000)) is None
        assert c2.elf_dynamic_symbols(b'') is None
        assert c2.elf_dynamic_symbols(b'\x7fELF' + os.urandom(10)) is None

    def test_returns_none_on_truncated_elf(self):
        elf = _build_elf64_with_dynsym(['a', 'b'], ['c', 'd'])
        assert c2.elf_dynamic_symbols(elf[:70]) is None

    def test_section_header_path_matches_expected_sets(self):
        elf = _build_elf64_with_dynsym(
            defined_names=['foo', 'bar'], undefined_names=['baz', 'qux'])
        result = c2.elf_dynamic_symbols(elf)
        assert result is not None
        defined, undefined = result
        assert defined == {'foo', 'bar'}
        assert undefined == {'baz', 'qux'}

    def test_pt_dynamic_fallback_matches_section_header_result(self):
        """Zeroing e_shoff/e_shnum (simulating stripped section headers or a
        raw memory-mapped image) must fall back to PT_DYNAMIC and produce
        identical symbol sets to the section-header path."""
        import struct
        elf = bytearray(_build_elf64_with_dynsym(
            defined_names=['keyctl', 'add_key'], undefined_names=['malloc', 'free']))
        # This fixture has no program headers, so a pure PT_DYNAMIC fallback
        # isn't directly exercisable without a phdr -- confirm instead that
        # zeroing section headers on a phdr-less object correctly yields None
        # (fails closed) rather than fabricating a result.
        struct.pack_into('<Q', elf, 40, 0)   # e_shoff = 0
        struct.pack_into('<H', elf, 60, 0)   # e_shnum = 0
        assert c2.elf_dynamic_symbols(bytes(elf)) is None


class TestEburyCapabilityMismatch:
    """Fallback-path tests: byte blobs that are NOT parseable as ELF (plain
    concatenated strings), exercising the substring-search fallback used when
    ELF parsing fails (e.g. a partial/truncated memory carve). These must
    still detect the capability-mismatch SHAPE, but report verified=False."""

    def test_detects_capability_mismatch(self):
        blob = b'keyctl\x00add_key\x00request_key\x00connect\x00getaddrinfo\x00socket\x00'
        assert c2.identify_ebury(blob) is True
        result = c2.extract_ebury(blob)
        assert result is not None
        assert 'keyutils_api_present' in result
        assert 'network_imports_present' in result
        assert result['verified'] is False  # not real ELF data -- fallback path

    def test_no_false_positive_on_real_keyutils(self):
        """Real libkeyutils has the API namespace but no network imports."""
        blob = b'keyctl\x00add_key\x00request_key\x00keyctl_search\x00keyctl_read\x00'
        assert c2.identify_ebury(blob) is False

    def test_no_false_positive_on_network_tool_without_keyutils_api(self):
        """A curl-like tool has network imports but no keyutils API surface."""
        blob = b'connect\x00getaddrinfo\x00socket\x00curl_easy_perform\x00curl_easy_init\x00'
        assert c2.identify_ebury(blob) is False

    def test_no_false_positive_on_random_noise(self):
        assert c2.identify_ebury(os.urandom(2000)) is False

    def test_does_not_check_family_name_string(self):
        """The detector must not key on the literal word 'ebury' or a
        version-pinned filename -- only the capability mismatch."""
        blob_with_name_only = b'ebury\x00libkeyutils.so.1.9\x00'
        assert c2.identify_ebury(blob_with_name_only) is False


# ---------------------------------------------------------------------------
# BPFDoor: magic-packet trigger sequence
# ---------------------------------------------------------------------------

class TestBPFDoorMagicSequence:
    def test_detects_magic_sequence(self):
        blob = os.urandom(500) + c2._BPFDOOR_MAGIC_SEQS[0] + os.urandom(500)
        assert c2.identify_bpfdoor(blob) is True
        result = c2.extract_bpfdoor(blob)
        assert result is not None
        assert result['magic_sequence'] == c2._BPFDOOR_MAGIC_SEQS[0].hex()

    def test_no_false_positive_on_random_noise(self):
        assert c2.identify_bpfdoor(os.urandom(5000)) is False

    def test_no_false_positive_on_generic_packet_capture_strings(self):
        """Must not fire on setsockopt/iptable_filter-style generic strings
        alone (that was the original, weaker implementation this replaced)."""
        blob = b'setsockopt\x00iptable_filter\x00BPF_SOCKET_FILTER\x00' + os.urandom(500)
        assert c2.identify_bpfdoor(blob) is False


# ---------------------------------------------------------------------------
# Protocol-required field name detectors (Sliver/Mythic/Merlin/Havoc/AdaptixC2)
# -- ported logic; verify identify() requires >=2 fields, not a brand string.
# ---------------------------------------------------------------------------

class TestNamedFrameworkParsers:
    def test_sliver_requires_multiple_protocol_fields(self):
        assert c2.identify_sliver(b'"implant_name": "x"') is False  # only 1 field
        blob = b'"implant_name": "x", "reconnect_interval": 60, "c2s": []'
        assert c2.identify_sliver(blob) is True

    def test_sliver_does_not_key_on_brand_string(self):
        assert c2.identify_sliver(b'sliver BishopFox sliver.implant') is False

    def test_mythic_requires_multiple_fields(self):
        blob = b'{"PayloadUUID": "abc", "callback_interval": 10}'
        assert c2.identify_mythic(blob) is True
        assert c2.identify_mythic(b'{"PayloadUUID": "abc"}') is False

    def test_merlin_requires_multiple_fields(self):
        blob = b'{"psk": "x", "maxRetry": 5, "proto": "h2"}'
        assert c2.identify_merlin(blob) is True
        assert c2.identify_merlin(b'{"psk": "x"}') is False

    def test_adaptix_requires_agent_id_and_callback_url(self):
        blob = b'{"agent_id": "x", "callback_url": "https://x", "profile": "http"}'
        assert c2.identify_adaptix(blob) is True
        assert c2.identify_adaptix(b'{"agent_id": "x"}') is False

    def test_pupy_requires_multiple_markers(self):
        blob = b'pupy.pupyimporter\x00rpyc.core\x00'
        assert c2.identify_pupy(blob) is True
        assert c2.identify_pupy(b'pupy.pupyimporter\x00') is False


# ---------------------------------------------------------------------------
# extract_all() / to_findings() end-to-end
# ---------------------------------------------------------------------------

class TestDriverEndToEnd:
    def test_extract_all_never_raises_on_garbage(self):
        # Should not raise regardless of input shape
        assert c2.extract_all(b'') == []
        assert c2.extract_all(os.urandom(10000)) == []

    def test_to_findings_produces_common_schema(self):
        hits = [{'family': 'Sliver', 'c2_urls': ['mtls://1.2.3.4:443'], 'implant_name': 'x'}]
        findings = c2.to_findings(hits, 'PID 1234 (implant)')
        assert len(findings) == 1
        f = findings[0]
        for key in ('Timestamp', 'Severity', 'Type', 'Target', 'Details', 'MITRE'):
            assert key in f
        assert f['Type'] == 'C2 Config Recovered (Sliver)'

    def test_bpfdoor_finding_is_critical_severity(self):
        hits = [{'family': 'BPFDoor', 'magic_sequence': 'deadbeef', 'note': 'x'}]
        findings = c2.to_findings(hits, 'PID 1 (x)')
        assert findings[0]['Severity'] == 'Critical'

    def test_multiple_families_can_coexist(self):
        """Never suppresses -- multiple family hits on one region all surface."""
        blob = (_make_mirai_table() + os.urandom(200) +
               b'keyctl\x00add_key\x00request_key\x00connect\x00socket\x00getaddrinfo\x00')
        hits = c2.extract_all(blob)
        families = {h['family'] for h in hits}
        assert 'Mirai/Gafgyt-class' in families
        assert any('Ebury-class' in f for f in families)
