"""Ebury-class OpenSSH/libkeyutils backdoor -- ties into the Library Preload Hijack /
SSH sections in DETAILED-FOLLOW-ON-LINUX.md.

The mechanism, not a brand name: a real libkeyutils.so EXPORTS the keyctl(2)-family
API (keyctl/add_key/request_key as DEFINED dynamic symbols) and has no legitimate
reason to IMPORT network syscalls (connect/getaddrinfo/gethostbyname/socket as
UNDEFINED symbols) -- it never needs to resolve a host or open a socket to manage an
in-kernel keyring. A shared object that EXPORTS the keyutils API namespace but ALSO
IMPORTS network primitives has a capability mismatch no genuine keyutils build can
produce -- the structural tell public Ebury analyses describe (a trojanised
libkeyutils.so that phones home), independent of C2 domains or version.

The export/import distinction matters because some legitimate system binaries (e.g.
coreutils built with a runtime that links networking symbols unconditionally) import
connect/getaddrinfo/socket as unused linked references despite doing no networking --
checking network imports alone would false-positive on them. They export none of the
keyutils names, so the combined gate (exports keyutils AND imports network) excludes
them; either check alone would not.

When ELF parsing fails (not a valid/complete ELF -- e.g. a partial memory carve), falls
back to the original raw-byte substring heuristic rather than losing detection
coverage, but tags the result "unverified" so the investigation engine's tiering can
weight it appropriately lower than a structurally-confirmed capability mismatch."""
from __future__ import annotations

from typing import Any, Dict, Optional

from .._elf_utils import elf_dynamic_symbols

_KEYUTILS_API_NAMESPACE = (b'keyctl', b'add_key', b'request_key')
_NETWORK_IMPORT_SYMS = (b'connect', b'getaddrinfo', b'gethostbyname', b'socket')
_MIN_NAMESPACE_HITS = 2
_MIN_NETWORK_HITS = 2


def _verdict(data: bytes) -> Optional[Dict[str, Any]]:
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

    # Not parseable as ELF (partial carve, truncated, corrupted) -- fall back to
    # substring search so detection coverage is never lost, but mark it explicitly
    # unverified (can't distinguish export/import or confirm these are real
    # symbol-table entries vs. incidental string content).
    namespace_hits = sorted({m.decode() for m in _KEYUTILS_API_NAMESPACE if m in data})
    network_hits = sorted({m.decode() for m in _NETWORK_IMPORT_SYMS if m in data})
    if len(namespace_hits) >= _MIN_NAMESPACE_HITS and len(network_hits) >= _MIN_NETWORK_HITS:
        return {'verified': False, 'keyutils_api_present': namespace_hits,
               'network_imports_present': network_hits}
    return None


def identify(data: bytes) -> bool:
    return _verdict(data) is not None


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    v = _verdict(data)
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
