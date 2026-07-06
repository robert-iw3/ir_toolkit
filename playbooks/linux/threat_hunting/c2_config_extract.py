#!/usr/bin/env python3
"""
c2_config_extract.py - Family-specific C2 config extraction for Linux carved regions.

Linux's memory_enrich.py already does a stdlib-only GENERIC IOC sweep (IPs,
domains, URLs, Tor .onion, Monero wallets, Telegram/Discord exfil, AWS keys,
private-key blocks) over carved regions -- see extract_threat_iocs() there.
What it does NOT do is recognise a specific C2 FRAMEWORK's wire-protocol
field names and pull out its structured config (sleep/jitter, PSK, agent
UUID, profile) the way playbooks/windows/threat_hunting/mwcp_parsers/ does
for Windows-targeting families via the DC3-MWCP framework.

This module is that Linux counterpart. It is deliberately NOT an mwcp parser:
mwcp is only staged by Build-OfflineToolkit.ps1 (Windows) -- the Linux build
(Build-OfflineToolkit-Linux.sh) never installs it, and memory_enrich.py's own
docstring commits to "stdlib-only" so the Linux offline toolkit has no extra
runtime dependency to carry to an air-gapped host. Every parser here is a
plain function over `bytes -> dict`, mirroring mwcp_parsers' detection logic
(protocol-required field names an operator cannot rename without breaking
server compatibility) without requiring the mwcp package.

Families covered -- selected because they run on Linux in practice (ELF
agents, cross-compiled Go, or Linux-native tooling), NOT because they exist
in the Windows mwcp_parsers set:

  Cross-platform red-team / post-ex frameworks (Linux agent builds exist):
  - Sliver       (Go, cross-platform; Linux/BSD implants are common)
  - Mythic       (Poseidon/Merlin-type agents are Go/Python and target Linux)
  - Merlin       (Go, explicitly cross-platform, ships Linux builds)
  - Havoc        (Demon agent has Linux/macOS builds since v2)
  - AdaptixC2    (cross-platform JSON-configured agent)
  - Pupy RAT     (Python, explicitly cross-platform -- Linux is a first-class
    target, not a cross-compile afterthought; dnslib/RSA-exchange C2)

  Linux/Unix-native malware families (the actual dominant threats -- these have
  no Windows equivalent in mwcp_parsers because they don't target Windows):
  - BPFDoor      (magic-packet activated backdoor; correlates with the eBPF +
    netfilter hook detection already in analyze_memory_linux.py's
    correlate_ebpf_c2() -- this module recovers the STATIC config artifacts
    a live/carved region can hold: magic sequence, RC4 key, fake PID path)
  - Mirai/Gafgyt-class IoT/server botnet (table-based single-byte-XOR string
    obfuscation is the family's structural signature; hardcoded C2 IP:port
    and attack-command vocabulary survive every rebrand/variant)
  - Ebury        (OpenSSH backdoor delivered via libkeyutils.so hijack --
    ties directly into the Library Preload Hijack / SSH sections already in
    DETAILED-FOLLOW-ON-LINUX.md §9/§11; internal RC4 key + domain-list markers
    are documented from public CERT-Bund/ESET analysis)
  - Generic Go C2 beacon heuristic (unnamed/custom Go backdoors: Go runtime
    build marker + a JSON heartbeat shape near an HTTP(S) endpoint -- the same
    "detect the shape, not the family name" philosophy as GenericC2.py, but
    tuned to Go's serialization conventions since that's the dominant
    language for custom Linux implants)

  Linux-specific addition beyond the Windows set entirely:
  - XMRig-class miner config (the dominant real-world Linux compromise per
    WORKFLOW-INVESTIGATION-LINUX.md is a Kinsing/kdevtmpfsi-class miner+
    rootkit; memory_enrich.py catches the stratum:// URL as a bare IOC but
    not the structured pool/wallet/algo/donate-level config JSON)
  - SMTP exfil credentials (protocol-generic, but commodity Linux backdoors/
    stealers reuse this exfil channel same as Windows RATs; not yet covered
    by memory_enrich.py's Telegram/Discord-only exfil detection)

Usage:
    from c2_config_extract import extract_all, to_findings
    hits = extract_all(data)             # [{'family': 'Sliver', 'fields': {...}}, ...]
    findings = to_findings(hits, where)   # common-schema findings list
"""
from __future__ import annotations

import json
import re
import struct
from typing import Any, Dict, List, Optional, Set, Tuple


def _decode(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'ignore').strip()
    except Exception:
        return ''


def _find_json_objects(data: bytes, anchor_re: 're.Pattern', max_len: int = 4000) -> List[dict]:
    """Extract JSON objects near an anchor pattern (config blobs embedded in a Go
    binary are not always at a clean object boundary, so search a window)."""
    out = []
    for m in anchor_re.finditer(data):
        start = max(0, m.start() - max_len)
        end = min(len(data), m.end() + max_len)
        window = data[start:end]
        brace_start = window.rfind(b'{', 0, m.start() - start + 1)
        if brace_start == -1:
            continue
        depth = 0
        for i in range(brace_start, len(window)):
            if window[i:i + 1] == b'{':
                depth += 1
            elif window[i:i + 1] == b'}':
                depth -= 1
                if depth == 0:
                    try:
                        obj = json.loads(window[brace_start:i + 1].decode('utf-8', 'ignore'))
                        if isinstance(obj, dict):
                            out.append(obj)
                    except (ValueError, UnicodeDecodeError):
                        pass
                    break
    return out


# ---------------------------------------------------------------------------
# Sliver (Go, cross-platform -- ELF implants are common)
# ---------------------------------------------------------------------------
# Wire-protocol field names required by the Sliver server's JSON serialization;
# an operator can strip debug symbols but not rename these without forking the
# server. Do NOT check for "sliver"/"BishopFox" -- those strings are stripped.
_SLIVER_PROTO_FIELDS = (
    b'"implant_name"', b'"reconnect_interval"', b'"c2s"', b'"dns_c2s"',
    b'"ActiveC2"', b'"PollTimeout"', b'"MaxConnectionErrors"',
    b'mtls://', b'wg://',
)
_SLIVER_JSON_ANCHOR = re.compile(rb'"(?:implant_name|ActiveC2|reconnect_interval)"')
_SLIVER_C2_URL_RE = re.compile(rb'(?:mtls|https|wg|dns|http)://[^\s\x00\'"<>{}\[\]]{4,200}', re.IGNORECASE)
_SLIVER_NAME_RE = re.compile(rb'(?:SliverName|implant_name)\x00{0,8}([A-Za-z0-9_\-]{3,32})', re.IGNORECASE)
_SLIVER_RECONNECT_RE = re.compile(rb'(?:ReconnectInterval|reconnect_interval)\x00{0,8}(\d{1,8})', re.IGNORECASE)


def identify_sliver(data: bytes) -> bool:
    return sum(1 for f in _SLIVER_PROTO_FIELDS if f in data) >= 2


def extract_sliver(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_sliver(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in _find_json_objects(data, _SLIVER_JSON_ANCHOR):
        fields.update(obj)

    urls = set()
    c2_list = fields.get('c2s') or fields.get('C2s') or []
    if isinstance(c2_list, list):
        for entry in c2_list:
            url = entry.get('url', '') if isinstance(entry, dict) else str(entry)
            if url:
                urls.add(url)
    if fields.get('server_url'):
        urls.add(fields['server_url'])
    for m in _SLIVER_C2_URL_RE.finditer(data):
        url = _decode(m.group(0)).rstrip('\x00 /').strip()
        if url and len(url) > 8:
            urls.add(url)

    name = fields.get('implant_name', '')
    if not name:
        m = _SLIVER_NAME_RE.search(data)
        if m:
            name = _decode(m.group(1)).strip('\x00')

    interval = fields.get('reconnect_interval', 0)
    if not interval:
        m = _SLIVER_RECONNECT_RE.search(data)
        if m:
            interval = int(m.group(1))

    if not (urls or name):
        return None
    return {
        'family': 'Sliver', 'c2_urls': sorted(urls)[:10],
        'implant_name': name, 'reconnect_interval_s': interval or None,
    }


# ---------------------------------------------------------------------------
# Mythic (Poseidon/Merlin-agent-type/Medusa are Go/Python -- run on Linux)
# ---------------------------------------------------------------------------
_MYTHIC_REQUIRED_FIELDS = (
    b'PayloadUUID', b'callback_interval', b'c2_profiles',
    b'encrypted_exchange_check', b'AES_PSK', b'tasking_type',
)
_MYTHIC_JSON_ANCHOR = re.compile(rb'"?PayloadUUID"?\s*:')


def identify_mythic(data: bytes) -> bool:
    return sum(1 for f in _MYTHIC_REQUIRED_FIELDS if f in data) >= 2


def extract_mythic(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_mythic(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in _find_json_objects(data, _MYTHIC_JSON_ANCHOR):
        fields.update(obj)

    uuid = fields.get('PayloadUUID') or fields.get('uuid') or fields.get('agent_uuid', '')
    interval = fields.get('callback_interval') or fields.get('sleep_interval')
    servers = set()
    profiles = fields.get('c2_profiles') or []
    if isinstance(profiles, list):
        for p in profiles:
            if isinstance(p, dict):
                for k in ('callback_host', 'server', 'endpoint'):
                    if p.get(k):
                        servers.add(str(p[k]))
    if not (uuid or servers):
        return None
    return {
        'family': 'Mythic', 'payload_uuid': uuid,
        'callback_interval_s': interval, 'c2_servers': sorted(servers)[:10],
    }


# ---------------------------------------------------------------------------
# Merlin (Go, explicitly cross-platform -- ships Linux builds)
# ---------------------------------------------------------------------------
# Protocol-required serialization keys used by the Merlin server's REST/gRPC
# interface; operators strip "merlin"/"ne0nd0g" but cannot rename these.
_MERLIN_PROTO_FIELDS = (b'"psk"', b'"PSK"', b'"skew"', b'"maxRetry"', b'"proto"')
_MERLIN_JSON_ANCHOR = re.compile(rb'"(?:psk|PSK|maxRetry)"\s*:')
_MERLIN_URL_RE = re.compile(rb'https?://[^\s\x00\'"<>]{4,200}', re.IGNORECASE)


def identify_merlin(data: bytes) -> bool:
    return sum(1 for f in _MERLIN_PROTO_FIELDS if f in data) >= 2


def extract_merlin(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_merlin(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in _find_json_objects(data, _MERLIN_JSON_ANCHOR):
        fields.update(obj)

    url = fields.get('url') or fields.get('URL', '')
    if not url:
        m = _MERLIN_URL_RE.search(data)
        if m:
            url = _decode(m.group(0))
    sleep = fields.get('sleep') or fields.get('Sleep')
    proto = fields.get('proto') or fields.get('Proto')
    if not url:
        return None
    return {
        'family': 'Merlin', 'c2_url': url,
        'sleep_s': sleep, 'protocol': proto,
    }


# ---------------------------------------------------------------------------
# Havoc (Demon agent -- Linux/macOS builds since Havoc v2)
# ---------------------------------------------------------------------------
_HAVOC_MAGIC = b'\xde\xad\xbe\xef'
_HAVOC_PROTO_FIELDS = (b'DemonID', b'SleepTime', b'Injection', b'encrypted_exchange_check')
_HAVOC_SLEEP_RE = re.compile(rb'(?:SleepTime|Sleep)\s*[=:]\s*(\d{1,6})', re.IGNORECASE)
_HAVOC_HOST_RE = re.compile(rb'(?:Teamserver|Host)\s*[=:]\s*[\x22\x27]?([a-zA-Z0-9\.\-]{4,100}:\d{2,5})', re.IGNORECASE)


def identify_havoc(data: bytes) -> bool:
    if _HAVOC_MAGIC in data:
        pos = data.find(_HAVOC_MAGIC)
        if pos + 8 <= len(data):
            try:
                size = struct.unpack_from('<I', data, pos + 4)[0]
                if 0 < size < 8192:
                    return True
            except struct.error:
                pass
    return sum(1 for f in _HAVOC_PROTO_FIELDS if f in data) >= 2


def extract_havoc(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_havoc(data):
        return None
    sleep, jitter = None, None
    pos = data.find(_HAVOC_MAGIC)
    if pos != -1 and pos + 24 <= len(data):
        try:
            sleep = struct.unpack_from('<I', data, pos + 12)[0]
            jitter = struct.unpack_from('<I', data, pos + 16)[0]
        except struct.error:
            pass
    if sleep is None:
        m = _HAVOC_SLEEP_RE.search(data)
        if m:
            sleep = int(m.group(1))
    host_m = _HAVOC_HOST_RE.search(data)
    host = _decode(host_m.group(1)) if host_m else ''
    if sleep is None and not host:
        return None
    return {'family': 'Havoc', 'teamserver': host, 'sleep_s': sleep, 'jitter': jitter}


# ---------------------------------------------------------------------------
# AdaptixC2 (cross-platform JSON-configured agent)
# ---------------------------------------------------------------------------
_ADAPTIX_FIELDS = (b'agent_id', b'callback_url', b'profile')
_ADAPTIX_JSON_ANCHOR = re.compile(rb'"agent_id"\s*:')


def identify_adaptix(data: bytes) -> bool:
    return sum(1 for f in _ADAPTIX_FIELDS if f in data) >= 2


def extract_adaptix(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_adaptix(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in _find_json_objects(data, _ADAPTIX_JSON_ANCHOR):
        fields.update(obj)
    agent_id = fields.get('agent_id', '')
    url = fields.get('callback_url', '')
    profile = fields.get('profile', '')
    if not (agent_id and url):
        return None
    return {'family': 'AdaptixC2', 'agent_id': agent_id, 'callback_url': url, 'profile': profile}


# ---------------------------------------------------------------------------
# Pupy RAT (Python, explicitly cross-platform -- Linux is a first-class target)
# ---------------------------------------------------------------------------
# Pupy's transport/config layer uses these module and RPC names verbatim in
# its pickled/marshalled config and reflective-loader banner; an operator can
# rebuild the payload but these package/RPC names are load-bearing (the
# client can't dispatch without them).
_PUPY_MARKERS = (
    b'pupy.pupyimporter', b'PupyCredentials', b'rpyc.core', b'ReverseSlave',
    b'launcher_module', b'pupy_srv.py', b'dnscnc',
)
_PUPY_CONF_ANCHOR = re.compile(rb'"?(?:launcher_args|transport|server)"?\s*:')
_PUPY_HOST_RE = re.compile(rb'(?:server|host)["\')\s:=]{1,4}["\']?([a-zA-Z0-9\.\-]{4,100}:\d{2,5})', re.IGNORECASE)


def identify_pupy(data: bytes) -> bool:
    return sum(1 for f in _PUPY_MARKERS if f in data) >= 2


def extract_pupy(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_pupy(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in _find_json_objects(data, _PUPY_CONF_ANCHOR):
        fields.update(obj)
    server = fields.get('server', '')
    if not server:
        m = _PUPY_HOST_RE.search(data)
        if m:
            server = _decode(m.group(1))
    transport = fields.get('transport', '')
    dns_cnc = b'dnscnc' in data
    if not (server or dns_cnc):
        return None
    return {'family': 'Pupy', 'server': server, 'transport': transport,
            'dns_cnc': dns_cnc or None}


# ---------------------------------------------------------------------------
# BPFDoor (magic-packet activated backdoor -- correlates with the eBPF +
# netfilter hook behavior already detected by analyze_memory_linux.py's
# correlate_ebpf_c2(); this recovers the STATIC config an on-disk/carved
# copy of the backdoor holds, which the live kernel-hook check cannot see).
# ---------------------------------------------------------------------------
# The magic sequence is the wire-protocol shared secret BPFDoor's own kernel-
# side classic-BPF filter compares incoming packets against before it acts --
# not an artifact string, the trigger value itself (mechanism-required: the
# kernel-side filter program and the operator's trigger packet must agree on
# these exact bytes, or activation never fires). Publicly documented across
# PwC/CrowdStrike/Deep Instinct write-ups of separate captured samples.
# Disguised on-disk paths / generic setsockopt-style strings are deliberately
# NOT used as identification criteria here -- those are artifact strings that
# any packet-capture tool (tcpdump, Suricata, Zeek) or renamed dropper could
# also contain, and checking for them is exactly the brand-name-substring
# anti-pattern the mwcp parsers this module is modeled on explicitly reject.
# Live-host/kernel confirmation (the actual mechanism: a network-hook eBPF
# program co-occurring with a hooked netfilter hook) already lives in
# analyze_memory_linux.py's correlate_ebpf_c2() -- this is a corroborating,
# not a replacement, check for a static/carved copy of the dropper.
_BPFDOOR_MAGIC_SEQS = (
    b'\x89\x94\xdd\xed', b'\x93\x88\xdd\xdd', b'\x66\x38\x63\x39',
)


def identify_bpfdoor(data: bytes) -> bool:
    return any(seq in data for seq in _BPFDOOR_MAGIC_SEQS)


def extract_bpfdoor(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_bpfdoor(data):
        return None
    magic = next((seq.hex() for seq in _BPFDOOR_MAGIC_SEQS if seq in data), None)
    return {
        'family': 'BPFDoor', 'magic_sequence': magic,
        'note': ('Magic-packet trigger sequence recovered from a static/carved copy of the '
                 'dropper. This does NOT by itself confirm live activation -- correlate with '
                 'the live-host mechanism check: eBPF Network C2 Correlated (memory) / '
                 'Netfilter Hook (memory) findings from analyze_memory_linux.py, which observe '
                 'the actual kernel-side filter+hook co-occurrence.'),
    }


# ---------------------------------------------------------------------------
# Mirai/Gafgyt-class IoT/server botnet.
#
# The mechanism, not a wordlist: Mirai's table.c XORs its ENTIRE string table
# (every C2 domain, attack command, and status string the bot needs) with a
# single global byte key at compile time, then deobfuscates each entry at
# first use via table_retrieve(). This survives every rebrand because it is
# structural to how the source builds -- a fork can rename every string but
# the "one key hides a dense block of otherwise-plaintext-shaped strings"
# shape stays, whereas legitimate binaries have no reason for a contiguous
# byte run to be simultaneously (a) meaningless under key=0x00 and (b) mostly
# printable, NUL-delimited, word-length tokens under exactly one other key.
# Detection here tries every byte key and scores how much MORE printable-
# string structure appears after XOR than is present in the raw bytes -- a
# generic obfuscation-mechanism test, not a match against any fixed vocabulary.
_XOR_SCAN_WINDOW = 65536      # table sits early in .rodata; bounds the cost
_XOR_MIN_TOKENS = 20          # printable NUL-delimited tokens of len>=4 after XOR
_XOR_MIN_IMPROVEMENT = 3.0    # decoded token count must be >=3x the raw-byte baseline


def _printable_token_count(blob: bytes) -> int:
    """Count of UNIQUE printable NUL-delimited tokens, not total occurrences.

    A real string table has largely DISTINCT entries. Counting raw
    occurrences is exploitable by periodic/repetitive plaintext: XORing a
    repeated phrase with a key equal to one of its own recurring byte values
    can turn that byte into NUL at the same relative offset every cycle,
    producing many copies of the SAME couple of substrings -- high count,
    zero diversity, not a string table. Requiring uniqueness closes that gap.
    """
    tokens = {tok for tok in blob.split(b'\x00')
             if len(tok) >= 4 and all(0x20 <= b < 0x7f for b in tok)}
    return len(tokens)


def _mirai_xor_table_key(data: bytes) -> Optional[int]:
    """Return the single byte key that best reveals a dense printable string
    table in `data`, or None if no key does meaningfully better than raw."""
    sample = data[:_XOR_SCAN_WINDOW]
    if len(sample) < 256:
        return None
    baseline = max(_printable_token_count(sample), 1)
    best_key, best_count = None, 0
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in sample)
        count = _printable_token_count(decoded)
        if count > best_count:
            best_key, best_count = key, count
    if best_key is not None and best_count >= _XOR_MIN_TOKENS and best_count >= _XOR_MIN_IMPROVEMENT * baseline:
        return best_key
    return None


_IP_PORT_BIN_RE = re.compile(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})')
# Corroborating labels only (never the identification gate): if the recovered
# key happens to decode any of these, they make the finding easier for an
# analyst to read -- absence changes nothing about the verdict.
_MIRAI_KNOWN_TOKENS = (b'GETLOCALIP', b'watchdog', b'/bin/busybox', b'/dev/watchdog')


def identify_mirai(data: bytes) -> bool:
    return _mirai_xor_table_key(data) is not None


def extract_mirai(data: bytes) -> Optional[Dict[str, Any]]:
    key = _mirai_xor_table_key(data)
    if key is None:
        return None
    sample = data[:_XOR_SCAN_WINDOW]
    decoded = bytes(b ^ key for b in sample)
    token_count = _printable_token_count(decoded)
    known_hits = sorted({t.decode() for t in _MIRAI_KNOWN_TOKENS if t in decoded})
    c2 = set()
    for m in _IP_PORT_BIN_RE.finditer(data):
        ip, port = _decode(m.group(1)), _decode(m.group(2))
        if ip.startswith(('10.', '127.', '192.168.')) or ip.startswith('172.'):
            continue
        c2.add(f'{ip}:{port}')
    return {
        'family': 'Mirai/Gafgyt-class', 'xor_key': hex(key), 'decoded_token_count': token_count,
        'known_token_hits': known_hits, 'c2_candidates': sorted(c2)[:10],
        'note': ('Detected via the obfuscation MECHANISM (single-byte-XOR string table), not '
                 'a vocabulary match -- known_token_hits is corroborating context only.'),
    }


# ---------------------------------------------------------------------------
# Minimal ELF dynamic-symbol parser (stdlib-only -- no pyelftools dependency
# for the offline Linux toolkit). Distinguishes DEFINED (exported) symbols
# from UNDEFINED (imported) ones, which raw substring search over file bytes
# cannot: a byte string search can't tell "this object EXPORTS keyctl" from
# "this object's string table merely CONTAINS the word keyctl somewhere" (a
# keyutils test suite, a security scanner auditing keyutils, a comment).
#
# Tries section headers first (SHT_DYNSYM -- correct for on-disk ELF files,
# which is the realistic input here: an analyst-copied /lib*/libkeyutils.so*
# or an adjudicate.py evidence-bundle "subject_" copy). Falls back to walking
# the PT_DYNAMIC segment's .dynamic entries (DT_SYMTAB/DT_STRTAB by virtual
# address, resolved through PT_LOAD segments) for stripped binaries or a raw
# memory-mapped image where section headers aren't resident. Both paths
# produce identical symbol sets for the same file.
# ---------------------------------------------------------------------------
_PT_DYNAMIC = 2
_PT_LOAD = 1
_DT_NULL = 0
_DT_STRTAB = 5
_DT_SYMTAB = 6
_DT_STRSZ = 10
_DT_SYMENT = 11


def _read_cstr(data: bytes, offset: int) -> str:
    end = data.find(b'\x00', offset)
    if end == -1:
        return ''
    try:
        return data[offset:end].decode('utf-8', 'ignore')
    except UnicodeDecodeError:
        return ''


def _elf_header(data: bytes) -> Optional[dict]:
    if len(data) < 64 or data[:4] != b'\x7fELF':
        return None
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        return None
    endian = '<' if ei_data == 1 else '>'
    is64 = ei_class == 2
    try:
        if is64:
            e_phoff, = struct.unpack_from(endian + 'Q', data, 32)
            e_shoff, = struct.unpack_from(endian + 'Q', data, 40)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(endian + 'HHHHH', data, 54)
        else:
            e_phoff, = struct.unpack_from(endian + 'I', data, 28)
            e_shoff, = struct.unpack_from(endian + 'I', data, 32)
            e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = \
                struct.unpack_from(endian + 'HHHHH', data, 40)
    except struct.error:
        return None
    return {'endian': endian, 'is64': is64, 'e_phoff': e_phoff,
           'e_phentsize': e_phentsize, 'e_phnum': e_phnum, 'e_shoff': e_shoff,
           'e_shentsize': e_shentsize, 'e_shnum': e_shnum}


def _symbols_via_sections(data: bytes, h: dict) -> Optional[Tuple[Set[str], Set[str]]]:
    endian, is64 = h['endian'], h['is64']
    e_shoff, e_shentsize, e_shnum = h['e_shoff'], h['e_shentsize'], h['e_shnum']
    if not e_shoff or not e_shnum or e_shoff + e_shentsize * e_shnum > len(data):
        return None
    sections = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        try:
            sh_type, = struct.unpack_from(endian + 'I', data, off + 4)
            if is64:
                sh_link, = struct.unpack_from(endian + 'I', data, off + 40)
                sh_offset, sh_size = struct.unpack_from(endian + 'QQ', data, off + 24)
                sh_entsize, = struct.unpack_from(endian + 'Q', data, off + 56)
            else:
                sh_link, = struct.unpack_from(endian + 'I', data, off + 24)
                sh_offset, sh_size = struct.unpack_from(endian + 'II', data, off + 16)
                sh_entsize, = struct.unpack_from(endian + 'I', data, off + 36)
        except struct.error:
            return None
        sections.append({'type': sh_type, 'link': sh_link, 'offset': sh_offset,
                         'size': sh_size, 'entsize': sh_entsize})
    dynsym = next((s for s in sections if s['type'] == 11), None)  # SHT_DYNSYM
    if dynsym is None or dynsym['link'] >= len(sections):
        return None
    strtab = sections[dynsym['link']]
    entsize = dynsym['entsize'] or (24 if is64 else 16)
    count = dynsym['size'] // entsize if entsize else 0
    return _walk_symtab(data, endian, is64, dynsym['offset'], entsize, count,
                        strtab['offset'], strtab['size'])


def _program_headers(data: bytes, h: dict) -> List[dict]:
    endian, is64 = h['endian'], h['is64']
    e_phoff, e_phentsize, e_phnum = h['e_phoff'], h['e_phentsize'], h['e_phnum']
    if not e_phoff or not e_phnum or e_phoff + e_phentsize * e_phnum > len(data):
        return []
    phdrs = []
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        try:
            if is64:
                p_type, = struct.unpack_from(endian + 'I', data, off)
                p_offset, p_vaddr = struct.unpack_from(endian + 'QQ', data, off + 8)
                p_filesz, p_memsz = struct.unpack_from(endian + 'QQ', data, off + 32)
            else:
                p_type, = struct.unpack_from(endian + 'I', data, off)
                p_offset, p_vaddr = struct.unpack_from(endian + 'II', data, off + 4)
                p_filesz, p_memsz = struct.unpack_from(endian + 'II', data, off + 16)
        except struct.error:
            continue
        phdrs.append({'type': p_type, 'offset': p_offset, 'vaddr': p_vaddr,
                      'filesz': p_filesz, 'memsz': p_memsz})
    return phdrs


def _vaddr_to_offset(phdrs: List[dict], vaddr: int) -> Optional[int]:
    for p in phdrs:
        if p['type'] == _PT_LOAD and p['vaddr'] <= vaddr < p['vaddr'] + p['memsz']:
            return p['offset'] + (vaddr - p['vaddr'])
    return None


def _walk_symtab(data: bytes, endian: str, is64: bool, sym_off: int, entsize: int,
                 count: int, str_off: int, str_size: int) -> Tuple[Set[str], Set[str]]:
    defined: Set[str] = set()
    undefined: Set[str] = set()
    for i in range(max(count, 0)):
        off = sym_off + i * entsize
        if off + entsize > len(data):
            break
        try:
            st_name, = struct.unpack_from(endian + 'I', data, off)
            st_shndx, = struct.unpack_from(endian + 'H', data, off + (6 if is64 else 14))
        except struct.error:
            continue
        if not st_name or st_name >= str_size:
            continue
        name = _read_cstr(data, str_off + st_name)
        if name:
            (undefined if st_shndx == 0 else defined).add(name)
    return defined, undefined


def _symbols_via_dynamic_segment(data: bytes, h: dict) -> Optional[Tuple[Set[str], Set[str]]]:
    """Fallback for stripped section headers or a raw memory-mapped image:
    walk PT_DYNAMIC's .dynamic entries to locate DT_SYMTAB/DT_STRTAB by
    virtual address, resolved to a buffer offset via PT_LOAD segments."""
    endian, is64 = h['endian'], h['is64']
    phdrs = _program_headers(data, h)
    dyn_seg = next((p for p in phdrs if p['type'] == _PT_DYNAMIC), None)
    if dyn_seg is None:
        return None

    entsize = 16 if is64 else 8
    tags: Dict[int, int] = {}
    off, end = dyn_seg['offset'], dyn_seg['offset'] + dyn_seg['filesz']
    while off + entsize <= end and off + entsize <= len(data):
        try:
            fmt = 'qQ' if is64 else 'iI'
            d_tag, d_val = struct.unpack_from(endian + fmt, data, off)
        except struct.error:
            break
        if d_tag == _DT_NULL:
            break
        tags[d_tag] = d_val
        off += entsize

    if _DT_SYMTAB not in tags or _DT_STRTAB not in tags:
        return None
    symtab_off = _vaddr_to_offset(phdrs, tags[_DT_SYMTAB])
    strtab_off = _vaddr_to_offset(phdrs, tags[_DT_STRTAB])
    if symtab_off is None or strtab_off is None:
        return None
    strsz = tags.get(_DT_STRSZ, 0)
    syment = tags.get(_DT_SYMENT) or (24 if is64 else 16)
    # .dynamic has no explicit symbol count; bound the walk by the string
    # table's start (symtab always precedes strtab in practice) + a sane cap.
    approx_count = (strtab_off - symtab_off) // syment if strtab_off > symtab_off else 0
    defined, undefined = _walk_symtab(data, endian, is64, symtab_off, syment,
                                      min(approx_count, 100000), strtab_off, strsz)
    return (defined, undefined) if (defined or undefined) else None


def elf_dynamic_symbols(data: bytes) -> Optional[Tuple[Set[str], Set[str]]]:
    """Return (defined_names, undefined/imported_names) for an ELF object's
    dynamic symbol table, or None if data isn't parseable as ELF (absent,
    truncated, corrupted -- callers must fall back to a weaker heuristic
    rather than treating None as "verified clean")."""
    h = _elf_header(data)
    if h is None:
        return None
    return _symbols_via_sections(data, h) or _symbols_via_dynamic_segment(data, h)


# ---------------------------------------------------------------------------
# Ebury-class OpenSSH/libkeyutils backdoor -- ties into the Library Preload
# Hijack / SSH sections in DETAILED-FOLLOW-ON-LINUX.md.
#
# The mechanism, not a brand name: a real libkeyutils.so EXPORTS the
# keyctl(2)-family API (keyctl/add_key/request_key as DEFINED dynamic
# symbols) and has no legitimate reason to IMPORT network syscalls
# (connect/getaddrinfo/gethostbyname/socket as UNDEFINED symbols) -- it
# never needs to resolve a host or open a socket to manage an in-kernel
# keyring. A shared object that EXPORTS the keyutils API namespace but ALSO
# IMPORTS network primitives has a capability mismatch no genuine keyutils
# build can produce -- the structural tell public Ebury analyses describe (a
# trojanised libkeyutils.so that phones home), independent of C2 domains or
# version.
#
# The export/import distinction matters because some legitimate system
# binaries (e.g. coreutils built with a runtime that links networking
# symbols unconditionally) import connect/getaddrinfo/socket as unused
# linked references despite doing no networking -- checking network imports
# alone would false-positive on them. They export none of the keyutils
# names, so the combined gate (exports keyutils AND imports network)
# excludes them; either check alone would not.
#
# When ELF parsing fails (not a valid/complete ELF -- e.g. a partial memory
# carve), falls back to the original raw-byte substring heuristic rather
# than losing detection coverage, but tags the result "unverified" so the
# investigation engine's tiering can weight it appropriately lower than a
# structurally-confirmed capability mismatch.
# ---------------------------------------------------------------------------
_KEYUTILS_API_NAMESPACE = (b'keyctl', b'add_key', b'request_key')
_NETWORK_IMPORT_SYMS = (b'connect', b'getaddrinfo', b'gethostbyname', b'socket')
_MIN_NAMESPACE_HITS = 2
_MIN_NETWORK_HITS = 2


def _ebury_verdict(data: bytes) -> Optional[Dict[str, Any]]:
    """Returns a dict with 'verified': True/False, or None if no match at all."""
    parsed = elf_dynamic_symbols(data)
    if parsed is not None:
        defined, undefined = parsed
        namespace_hits = sorted(n for n in _KEYUTILS_API_NAMESPACE if n.decode() in defined)
        network_hits = sorted(n for n in _NETWORK_IMPORT_SYMS if n.decode() in undefined)
        if len(namespace_hits) >= _MIN_NAMESPACE_HITS and len(network_hits) >= _MIN_NETWORK_HITS:
            return {
                'verified': True,
                'keyutils_api_present': [n.decode() for n in namespace_hits],
                'network_imports_present': [n.decode() for n in network_hits],
            }
        return None  # ELF parsed successfully and did NOT match -- confirmed clean, not "unknown"

    # Not parseable as ELF (partial carve, truncated, corrupted) -- fall back
    # to substring search so detection coverage is never lost, but mark it
    # explicitly unverified (can't distinguish export/import or confirm these
    # are real symbol-table entries vs. incidental string content).
    namespace_hits = sorted({m.decode() for m in _KEYUTILS_API_NAMESPACE if m in data})
    network_hits = sorted({m.decode() for m in _NETWORK_IMPORT_SYMS if m in data})
    if len(namespace_hits) >= _MIN_NAMESPACE_HITS and len(network_hits) >= _MIN_NETWORK_HITS:
        return {'verified': False, 'keyutils_api_present': namespace_hits,
               'network_imports_present': network_hits}
    return None


def identify_ebury(data: bytes) -> bool:
    return _ebury_verdict(data) is not None


def extract_ebury(data: bytes) -> Optional[Dict[str, Any]]:
    v = _ebury_verdict(data)
    if v is None:
        return None
    if v['verified']:
        note = ('ELF-VERIFIED: object EXPORTS the keyutils keyring API as defined dynamic '
                'symbols AND IMPORTS network primitives as undefined symbols -- confirmed via '
                'dynamic symbol table parsing, not a substring match. A genuine libkeyutils.so '
                'never imports networking. Cross-check against Library Preload Hijack findings '
                'and verify /lib*/libkeyutils.so* package ownership/hash (dpkg -V / rpm -V) '
                'before closing.')
    else:
        note = ('UNVERIFIED (raw byte match, not ELF-parseable -- likely a partial/truncated '
                'carve): object bytes contain both the keyutils API namespace and network '
                'primitive names, but this could not be confirmed as an actual export/import '
                'relationship via the dynamic symbol table. Weight accordingly; re-run against '
                'the full on-disk /lib*/libkeyutils.so* file if available for a definitive '
                'verdict.')
    return {
        'family': 'Ebury-class (keyutils/network capability mismatch)',
        'keyutils_api_present': v['keyutils_api_present'],
        'network_imports_present': v['network_imports_present'],
        'verified': v['verified'],
        'note': note,
    }


# ---------------------------------------------------------------------------
# Generic Go C2 beacon heuristic (unnamed/custom Go backdoors -- detect the
# SHAPE, not a family name, the same philosophy as GenericC2.py but tuned to
# Go's build/serialization conventions since Go is the dominant language for
# custom Linux implants that don't match a named framework above).
# ---------------------------------------------------------------------------
_GO_BUILD_MARKER_RE = re.compile(rb'Go build ID: "|golang\.org/x/|runtime\.goexit')
_GO_HEARTBEAT_JSON_ANCHOR = re.compile(rb'"(?:hostname|beacon|interval|agent_id|task_id)"\s*:')
_GO_HEARTBEAT_FIELDS = (b'"hostname"', b'"interval"', b'"beacon"', b'"task_id"', b'"agent_id"')
_GENERIC_URL_RE = re.compile(rb'https?://[^\s\x00\'"<>]{4,200}', re.IGNORECASE)


def identify_generic_go_c2(data: bytes) -> bool:
    if not _GO_BUILD_MARKER_RE.search(data):
        return False
    return sum(1 for f in _GO_HEARTBEAT_FIELDS if f in data) >= 2


def extract_generic_go_c2(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_generic_go_c2(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in _find_json_objects(data, _GO_HEARTBEAT_JSON_ANCHOR):
        fields.update(obj)
    urls = sorted({_decode(m.group(0)) for m in _GENERIC_URL_RE.finditer(data)})[:10]
    if not (fields or urls):
        return None
    return {
        'family': 'Unnamed Go C2 (structural)', 'heartbeat_fields': sorted(fields.keys()),
        'candidate_urls': urls,
        'note': ('Go runtime marker + heartbeat-shaped JSON (hostname/interval/task_id) near '
                 'HTTP endpoint(s) -- structural match only, no named family. Same rationale as '
                 'the Windows engine\'s YARA-by-location approach: the mechanism is the evidence.'),
    }


# ---------------------------------------------------------------------------
# Cryptominer config (XMRig-class -- Kinsing/kdevtmpfsi-style Linux compromise)
# ---------------------------------------------------------------------------
# XMRig's config.json / CLI args share these field names verbatim; a JSON
# blob with a "pools" array + "user"/"url" keys, or a stratum+tcp CLI
# invocation, is the structural signature regardless of the wrapper script
# hiding it under a masqueraded process name.
_MINER_JSON_ANCHOR = re.compile(rb'"(?:donate-level|pools|algo)"\s*:')
_MINER_STRATUM_RE = re.compile(
    rb'stratum\+(?:tcp|ssl)://[A-Za-z0-9\.\-]+:\d{2,5}', re.IGNORECASE)
_MINER_WALLET_CLI_RE = re.compile(rb'-[ou]\s+([A-Za-z0-9]{20,106})')
_MINER_ALGO_RE = re.compile(rb'"algo"\s*:\s*"([a-z0-9/_\-]{3,40})"', re.IGNORECASE)


def identify_miner(data: bytes) -> bool:
    return bool(_MINER_JSON_ANCHOR.search(data) or _MINER_STRATUM_RE.search(data))


def extract_miner(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify_miner(data):
        return None
    fields: Dict[str, Any] = {}
    for obj in _find_json_objects(data, _MINER_JSON_ANCHOR):
        fields.update(obj)

    pools = set()
    pools_list = fields.get('pools') or []
    if isinstance(pools_list, list):
        for p in pools_list:
            if isinstance(p, dict) and p.get('url'):
                pools.add(str(p['url']))
                if p.get('user'):
                    pools.add(f"user={p['user']}")
    for m in _MINER_STRATUM_RE.finditer(data):
        pools.add(_decode(m.group(0)))

    algo = fields.get('algo', '')
    if not algo:
        m = _MINER_ALGO_RE.search(data)
        if m:
            algo = _decode(m.group(1))

    wallets = {_decode(m.group(1)) for m in _MINER_WALLET_CLI_RE.finditer(data)}

    if not pools:
        return None
    return {
        'family': 'Miner (XMRig-class)', 'pools': sorted(pools)[:10],
        'algo': algo, 'wallets_cli': sorted(wallets)[:5],
        'donate_level': fields.get('donate-level'),
    }


# ---------------------------------------------------------------------------
# SMTP exfil credentials (protocol-generic; commodity Linux stealers reuse
# this channel the same way Windows RATs do -- not yet in memory_enrich.py)
# ---------------------------------------------------------------------------
_SMTP_HOST_RE = re.compile(rb'(?<![a-zA-Z0-9@])(?:smtp|mail)\.[a-zA-Z0-9\.\-]{3,100}', re.IGNORECASE)
_SMTP_PORTS = {25, 465, 587, 2525, 26, 2526}
_SMTP_PORT_RE = re.compile(
    rb'(?:\b|[\x00:;,\s])(' + b'|'.join(str(p).encode() for p in sorted(_SMTP_PORTS)) + rb')(?:\b|[\x00:;,\s])')
_SMTP_EMAIL_RE = re.compile(rb'[a-zA-Z0-9][a-zA-Z0-9\.\+\-_]{0,63}@[a-zA-Z0-9\.\-]{3,100}\.[a-zA-Z]{2,10}', re.IGNORECASE)
_SMTP_PASS_LABEL_RE = re.compile(
    rb'(?:password|pass|pwd|secret|key|cred)["\s:=\x00]{0,8}([^\x00\r\n"\'<>\s]{4,64})', re.IGNORECASE)
_SMTP_CONTEXT_WINDOW = 512


def extract_smtp_exfil(data: bytes) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for m in _SMTP_HOST_RE.finditer(data):
        host = _decode(m.group(0))
        if not host:
            continue
        lo, hi = max(0, m.start() - _SMTP_CONTEXT_WINDOW), min(len(data), m.end() + _SMTP_CONTEXT_WINDOW)
        ctx = data[lo:hi]

        port = '587'
        pm = _SMTP_PORT_RE.search(ctx)
        if pm:
            try:
                p = int(_decode(pm.group(1)))
                if p in _SMTP_PORTS:
                    port = str(p)
            except ValueError:
                pass

        em = _SMTP_EMAIL_RE.search(ctx)
        email = _decode(em.group(0)) if em else None

        password = None
        passm = _SMTP_PASS_LABEL_RE.search(ctx)
        if passm:
            val = _decode(passm.group(1))
            if val and val.lower() not in ('smtp', 'mail', 'email', 'password', 'pass'):
                password = val

        if not password:
            continue
        key = (host, port, email, password)
        if key in seen:
            continue
        seen.add(key)
        out.append({'family': 'SMTP-Exfil', 'host': host, 'port': port,
                    'user': email, 'password': password})
    return out


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
_FAMILY_EXTRACTORS = (
    extract_sliver, extract_mythic, extract_merlin, extract_havoc, extract_adaptix,
    extract_pupy, extract_bpfdoor, extract_mirai, extract_ebury, extract_generic_go_c2,
    extract_miner,
)


def extract_all(data: bytes) -> List[Dict[str, Any]]:
    """Run every family parser over one region's bytes. Returns a list of
    per-family config dicts (never suppresses -- multiple families can
    'hit' the same region if a rule grazes shared library bytes; each hit
    is surfaced and left for the analyst/adjudicator to weigh)."""
    if not data:
        return []
    hits = []
    for fn in _FAMILY_EXTRACTORS:
        try:
            r = fn(data)
        except Exception:
            r = None
        if r:
            hits.append(r)
    for smtp_hit in extract_smtp_exfil(data):
        hits.append(smtp_hit)
    return hits


def to_findings(hits: List[Dict[str, Any]], where: str, mitre_default: str = 'T1071') -> List[dict]:
    """Convert extract_all() output into common-schema findings
    ({Timestamp, Severity, Type, Target, Details, MITRE}) consistent with
    memory_enrich.py's _finding() schema, for merging into the same
    Memory_Findings_enrich_*.json flow."""
    import datetime

    def _now():
        return datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')

    out = []
    for h in hits:
        fam = h.get('family', 'Unknown')
        if fam == 'SMTP-Exfil':
            out.append({
                'Timestamp': _now(), 'Severity': 'High',
                'Type': 'Exfiltration Channel (memory)',
                'Target': f"{h['host']}:{h['port']}",
                'Details': (f"SMTP exfil credentials recovered from {where}: "
                            f"host={h['host']}:{h['port']} user={h.get('user') or '?'} "
                            f"pass={h['password']}"),
                'MITRE': 'T1567 (Exfiltration Over Web Service)',
            })
            continue
        if fam == 'Miner (XMRig-class)':
            out.append({
                'Timestamp': _now(), 'Severity': 'High',
                'Type': 'Cryptominer Config Recovered (memory)',
                'Target': (h['pools'][0] if h['pools'] else where),
                'Details': (f"XMRig-class miner config recovered from {where}: "
                            f"pools={h['pools']} algo={h.get('algo') or '?'} "
                            f"wallets={h.get('wallets_cli') or []} "
                            f"donate-level={h.get('donate_level')}"),
                'MITRE': 'T1496 (Resource Hijacking)',
            })
            continue
        if fam == 'BPFDoor':
            out.append({
                'Timestamp': _now(), 'Severity': 'Critical',
                'Type': 'BPFDoor Config Artifact (memory)',
                'Target': where,
                'Details': (f"BPFDoor-class magic-packet trigger sequence recovered from {where}: "
                            f"magic={h.get('magic_sequence')}. {h.get('note', '')}"),
                'MITRE': 'T1205.002 (Socket Filters), T1014 (Rootkit)',
            })
            continue
        if fam == 'Mirai/Gafgyt-class':
            out.append({
                'Timestamp': _now(), 'Severity': 'High',
                'Type': 'Botnet Config Recovered (memory)',
                'Target': (h['c2_candidates'][0] if h.get('c2_candidates') else where),
                'Details': (f"Mirai/Gafgyt-class XOR-obfuscated string table recovered from {where}: "
                            f"xor_key={h['xor_key']} decoded_tokens={h['decoded_token_count']} "
                            f"known_hits={h.get('known_token_hits') or []} "
                            f"c2={h.get('c2_candidates') or []}. {h.get('note', '')}"),
                'MITRE': 'T1498 (Network DoS), T1071',
            })
            continue
        if fam.startswith('Ebury-class'):
            out.append({
                'Timestamp': _now(), 'Severity': 'Critical',
                'Type': 'SSH Backdoor Artifact (memory)',
                'Target': where,
                'Details': (f"Keyutils/network capability-mismatch backdoor recovered from {where}: "
                            f"keyutils_api={h.get('keyutils_api_present') or []} "
                            f"network_imports={h.get('network_imports_present') or []}. "
                            f"{h.get('note', '')}"),
                'MITRE': 'T1556 (Modify Authentication Process), T1554 (Compromise Client Binary)',
            })
            continue
        # C2 framework families (Sliver/Mythic/Merlin/Havoc/AdaptixC2/Pupy/unnamed Go):
        # uniform "config recovered" finding.
        detail_fields = {k: v for k, v in h.items() if k != 'family' and v}
        out.append({
            'Timestamp': _now(), 'Severity': 'High',
            'Type': f'C2 Config Recovered ({fam})',
            'Target': where,
            'Details': f'{fam} implant configuration recovered from {where}: {detail_fields}',
            'MITRE': f'{mitre_default} (Application Layer Protocol), T1027 (Obfuscated Files)',
        })
    return out
