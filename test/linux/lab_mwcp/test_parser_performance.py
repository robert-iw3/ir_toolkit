"""Every parser's identify() must stay fast against a large adversarial buffer.
Dynamically discovers every module in every category's MODULES tuple -- a new parser
is automatically covered the moment it's added to a MODULES tuple, nothing to wire up.
"""
from __future__ import annotations

import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_HERE, "..", "..", ".."))
_WIN_HUNT = os.path.join(_ROOT, "playbooks", "linux", "threat_hunting")
sys.path.insert(0, _WIN_HUNT)

from mwcp_parsers import c2_frameworks, cloud_saas, delivery, native, ransomware, specialized  # noqa: E402

_ALL_MODULES = [
    m for pkg in (c2_frameworks, native, ransomware, cloud_saas, delivery, specialized)
    for m in pkg.MODULES
]

_TIME_BUDGET_S = 3.0


def _adversarial_buffer():
    # Dense mixed content: base64-shaped runs, JSON-field-shaped tokens, repeated short
    # strings, extension-shaped tokens -- the kind of buffer a real 64MB carved region
    # could resemble, at a size still fast to generate for a per-test budget check.
    import random
    random.seed(1234)
    chunks = []
    alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    for _ in range(2000):
        chunks.append(bytes(random.choice(alphabet) for _ in range(64)))
        chunks.append(b'"field_name_' + str(random.randint(0, 9999)).encode() + b'":')
        chunks.append(b'.ext' + str(random.randint(0, 99)).encode())
    return b'\x00'.join(chunks)


_BUFFER = _adversarial_buffer()


def test_every_parser_identify_completes_within_budget():
    slow = []
    for mod in _ALL_MODULES:
        t0 = time.time()
        try:
            mod.identify(_BUFFER)
        except Exception:
            pass
        elapsed = time.time() - t0
        if elapsed > _TIME_BUDGET_S:
            slow.append((mod.__name__, elapsed))
    assert not slow, f"parser(s) exceeded the {_TIME_BUDGET_S}s budget: {slow}"


def test_smtp_exfil_multi_hit_extractor_completes_within_budget():
    from mwcp_parsers.native import smtp_exfil
    t0 = time.time()
    smtp_exfil.extract(_BUFFER)
    assert time.time() - t0 < _TIME_BUDGET_S
