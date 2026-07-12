"""Generic ransomware indicator cluster -- the Linux analog of the Windows engine's
generic RansomwareIndicators detector. Not tied to ESXi or any named family: any
Linux/Unix ransomware needs (a) a way to encrypt without needing a live C2 round-trip
for every file, which means an embedded asymmetric public key baked into the binary,
and (b) a way to tell the victim how to pay, which means a ransom-note payload
containing both payment-contact infrastructure (a Tor .onion address is the
overwhelmingly dominant choice, since it survives takedown attempts a clearnet domain
would not) and a mass file-extension target list (the binary needs to know which files
are "worth" encrypting, compiled in as a dense array of extensions).

Requires 2+ of these independently-sourced signals -- any one alone is far too common
(a legitimate PKI tool has a public key; a legitimate backup tool enumerates file
extensions) to mean anything on its own."""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

_PUBKEY_RE = re.compile(rb'-----BEGIN (?:RSA )?PUBLIC KEY-----')
# A Tor v2 (16-char) or v3 (56-char) base32 .onion address -- the structural artifact
# a ransom note's payment-contact infrastructure needs, not a string that could be
# renamed without breaking the actual hidden-service address.
_ONION_RE = re.compile(rb'\b[a-z2-7]{16}\.onion\b|\b[a-z2-7]{56}\.onion\b', re.IGNORECASE)
_RANSOM_LANGUAGE_RE = re.compile(
    rb'(?i)(?:your\s+files\s+(?:have\s+been|are)\s+encrypted|decrypt(?:ion)?\s+key|'
    rb'pay(?:ment)?\s+(?:instructions|deadline)|restore\s+your\s+(?:files|data))')
_TARGET_EXTENSIONS = (
    b'.doc', b'.docx', b'.xls', b'.xlsx', b'.pdf', b'.sql', b'.mdb', b'.zip', b'.tar',
    b'.bak', b'.db', b'.csv', b'.ppt', b'.pptx', b'.conf', b'.ini',
)


def _signals(data: bytes) -> Dict[str, Any]:
    pubkey = bool(_PUBKEY_RE.search(data))
    onion_m = _ONION_RE.search(data)
    ransom_lang = bool(_RANSOM_LANGUAGE_RE.search(data))
    ext_hits = [e for e in _TARGET_EXTENSIONS if e in data]
    ext_cluster = len(ext_hits) >= 8
    return {'pubkey': pubkey, 'onion': onion_m.group(0).decode() if onion_m else None,
            'ransom_language': ransom_lang, 'ext_cluster': ext_cluster, 'ext_hits': ext_hits}


def identify(data: bytes) -> bool:
    s = _signals(data)
    return sum([s['pubkey'], bool(s['onion']), s['ransom_language'], s['ext_cluster']]) >= 2


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    if not identify(data):
        return None
    s = _signals(data)
    return {
        'family': 'Ransomware: Generic Indicators',
        'embedded_pubkey': s['pubkey'],
        'onion_contact': s['onion'],
        'ransom_note_language': s['ransom_language'],
        'target_extensions': sorted(e.decode() for e in s['ext_hits']),
        'note': ('2+ of: embedded asymmetric public key, Tor .onion payment-contact address, '
                 'ransom-note-shaped language, and a dense mass-target file-extension list -- '
                 'no named family, structural indicators only.'),
    }
