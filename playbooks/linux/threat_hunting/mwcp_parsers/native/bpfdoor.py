"""BPFDoor (magic-packet activated backdoor -- correlates with the eBPF + netfilter
hook detection already in analyze_memory_linux.py's correlate_ebpf_c2(); this recovers
the STATIC config artifacts a live/carved region can hold: magic sequence.

The magic sequence is the wire-protocol shared secret BPFDoor's own kernel-side
classic-BPF filter compares incoming packets against before it acts -- not an artifact
string, the trigger value itself (mechanism-required: the kernel-side filter program
and the operator's trigger packet must agree on these exact bytes, or activation never
fires). Publicly documented across PwC/CrowdStrike/Deep Instinct write-ups of separate
captured samples.

Disguised on-disk paths / generic setsockopt-style strings are deliberately NOT used as
identification criteria here -- those are artifact strings any packet-capture tool
(tcpdump, Suricata, Zeek) or renamed dropper could also contain.

One of the three documented sequences (0x66386339) happens to be printable ASCII
("f8c9"), which showed a real false positive against a large icon-theme library:
`style="fill:#f8c94d"` in embedded SVG markup contains "f8c9" as an ordinary hex-color
substring, with zero networking/BPF context anywhere near it (confirmed by inspecting
the actual match: 160 bytes of pure SVG path/style markup on both sides). A genuine
magic-byte comparison lives inside BPFDoor's own compiled packet-filter logic --
raw binary opcodes/data, not human-readable markup -- so a match embedded in a long
run of printable text is rejected as the shape of coincidental text content, not a
compiled binary constant.

Live-host/kernel confirmation (the actual mechanism: a network-hook eBPF program
co-occurring with a hooked netfilter hook) already lives in analyze_memory_linux.py's
correlate_ebpf_c2() -- this is a corroborating, not a replacement, check for a
static/carved copy of the dropper."""
from __future__ import annotations

from typing import Any, Dict, Optional

_MAGIC_SEQS = (
    b'\x89\x94\xdd\xed', b'\x93\x88\xdd\xdd', b'\x66\x38\x63\x39',
)
_TEXT_CONTEXT_WINDOW = 40         # bytes examined on each side of a candidate match
_TEXT_CONTEXT_THRESHOLD = 0.85    # fraction printable -> treat as markup/text, not binary


def _is_text_embedded(data: bytes, idx: int, seq_len: int) -> bool:
    """True if the match sits inside a long run of printable/text-shaped bytes on both
    sides -- the shape of markup/source/config content, not the compiled binary logic
    a genuine magic-byte comparison would live in."""
    lo = max(0, idx - _TEXT_CONTEXT_WINDOW)
    hi = min(len(data), idx + seq_len + _TEXT_CONTEXT_WINDOW)
    ctx = data[lo:idx] + data[idx + seq_len:hi]
    if not ctx:
        return False
    printable = sum(1 for b in ctx if 0x20 <= b < 0x7f or b in (0x09, 0x0a, 0x0d))
    return (printable / len(ctx)) >= _TEXT_CONTEXT_THRESHOLD


def _find_binary_match(data: bytes, seq: bytes) -> Optional[int]:
    """First occurrence of seq that is NOT embedded in a printable-text run, or None."""
    start = 0
    while True:
        idx = data.find(seq, start)
        if idx == -1:
            return None
        if not _is_text_embedded(data, idx, len(seq)):
            return idx
        start = idx + 1


def identify(data: bytes) -> bool:
    return any(_find_binary_match(data, seq) is not None for seq in _MAGIC_SEQS)


def extract(data: bytes) -> Optional[Dict[str, Any]]:
    for seq in _MAGIC_SEQS:
        if _find_binary_match(data, seq) is not None:
            return {
                'family': 'BPFDoor', 'magic_sequence': seq.hex(),
                'note': ('Magic-packet trigger sequence recovered from a static/carved copy of '
                         'the dropper (context-checked: not embedded in a printable-text run). '
                         'This does NOT by itself confirm live activation -- correlate with the '
                         'live-host mechanism check: eBPF Network C2 Correlated (memory) / '
                         'Netfilter Hook (memory) findings from analyze_memory_linux.py, which '
                         'observe the actual kernel-side filter+hook co-occurrence.'),
            }
    return None
