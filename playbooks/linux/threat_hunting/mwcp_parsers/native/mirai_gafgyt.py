"""Mirai/Gafgyt-class IoT/server botnet.

The mechanism, not a wordlist: Mirai's table.c XORs its ENTIRE string table (every C2
domain, attack command, and status string the bot needs) with a single global byte key
at compile time, then deobfuscates each entry at first use via table_retrieve(). This
survives every rebrand because it is structural to how the source builds -- a fork can
rename every string but the "one key hides a dense block of otherwise-plaintext-shaped
strings" shape stays, whereas legitimate binaries have no reason for a contiguous byte
run to be simultaneously (a) meaningless under key=0x00 and (b) mostly printable,
NUL-delimited, word-length tokens under exactly one other key. Detection here tries
every byte key and scores how much MORE printable-string structure appears after XOR
than is present in the raw bytes -- a generic obfuscation-mechanism test, not a match
against any fixed vocabulary."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

from .._common import decode

_XOR_SCAN_WINDOW = 65536      # table sits early in .rodata; bounds the cost
_XOR_MIN_TOKENS = 20          # printable NUL-delimited tokens of len>=4 after XOR
_XOR_MIN_IMPROVEMENT = 3.0    # decoded token count must be >=3x the raw-byte baseline


_MIN_ALPHA_FRACTION = 0.6   # a token must be predominantly letters to count


def _is_wordlike(tok: bytes) -> bool:
    """Real string-table entries (hostnames, paths, attack-command names) are
    predominantly alphabetic. XORing structured binary data (relocation tables,
    symbol tables, other regularly-strided sections real compiled libraries contain)
    against the wrong key can still land in the printable range and produce runs that
    LOOK like distinct tokens by the NUL-delimited/len>=4 test alone, but they're
    dominated by punctuation/symbol characters, not letters -- confirmed against real
    system libraries (libcrypto/liblzma/libzstd/coreutils): false-positive tokens
    there measured under 0.22 alphabetic fraction, genuine Mirai-table tokens measured
    0.8+ (only very short numeric/IP-shaped tokens fall below that, which is why this
    is a token-quality filter, not a per-character gate)."""
    letters = sum(1 for b in tok if 0x41 <= b <= 0x5a or 0x61 <= b <= 0x7a)
    return (letters / len(tok)) >= _MIN_ALPHA_FRACTION


def _printable_token_count(blob: bytes) -> int:
    """Count of UNIQUE printable, wordlike NUL-delimited tokens, not total
    occurrences.

    A real string table has largely DISTINCT, wordlike entries. Counting raw
    occurrences is exploitable by periodic/repetitive plaintext: XORing a repeated
    phrase with a key equal to one of its own recurring byte values can turn that byte
    into NUL at the same relative offset every cycle, producing many copies of the
    SAME couple of substrings -- high count, zero diversity, not a string table.
    Requiring uniqueness closes that gap. Requiring the token to be wordlike
    (predominantly alphabetic) closes a second one: structured binary data (symbol/
    relocation tables) can XOR into many UNIQUE but punctuation-dominated runs that
    are not word-shaped at all."""
    tokens = {tok for tok in blob.split(b'\x00')
             if len(tok) >= 4 and all(0x20 <= b < 0x7f for b in tok) and _is_wordlike(tok)}
    return len(tokens)


def _xor_table_key(data: bytes) -> Optional[int]:
    """Return the single byte key that best reveals a dense printable string table in
    `data`, or None if no key does meaningfully better than raw. Decodes via
    bytes.translate() (one bulk C-level pass per key) rather than a per-byte Python
    generator -- translate() runs the 255-key search in a fraction of the time a
    per-byte expression takes on a 64KB window."""
    sample = data[:_XOR_SCAN_WINDOW]
    if len(sample) < 256:
        return None
    baseline = max(_printable_token_count(sample), 1)
    best_key, best_count = None, 0
    for key in range(1, 256):
        table = bytes(b ^ key for b in range(256))   # 256-byte lookup table, built ONCE per key
        decoded = sample.translate(table)             # single bulk C-level pass over the window
        count = _printable_token_count(decoded)
        if count > best_count:
            best_key, best_count = key, count
    if best_key is not None and best_count >= _XOR_MIN_TOKENS and best_count >= _XOR_MIN_IMPROVEMENT * baseline:
        return best_key
    return None


_IP_PORT_BIN_RE = re.compile(rb'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{2,5})')
# Corroborating labels only (never the identification gate): if the recovered key
# happens to decode any of these, they make the finding easier for an analyst to read
# -- absence changes nothing about the verdict.
_KNOWN_TOKENS = (b'GETLOCALIP', b'watchdog', b'/bin/busybox', b'/dev/watchdog')


def identify(data: bytes) -> bool:
    return _xor_table_key(data) is not None


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    key = _xor_table_key(data)
    if key is None:
        return None
    sample = data[:_XOR_SCAN_WINDOW]
    decoded = bytes(b ^ key for b in sample)
    token_count = _printable_token_count(decoded)
    known_hits = sorted({t.decode() for t in _KNOWN_TOKENS if t in decoded})
    c2 = set()
    for m in _IP_PORT_BIN_RE.finditer(data):
        ip, port = decode(m.group(1)), decode(m.group(2))
        if ip.startswith(('10.', '127.', '192.168.')) or ip.startswith('172.'):
            continue
        c2.add(f'{ip}:{port}')
    return {
        'family': 'Mirai/Gafgyt-class', 'xor_key': hex(key), 'decoded_token_count': token_count,
        'known_token_hits': known_hits, 'c2_candidates': sorted(c2)[:10],
        'note': ('Detected via the obfuscation MECHANISM (single-byte-XOR string table), not '
                 'a vocabulary match -- known_token_hits is corroborating context only.'),
    }
