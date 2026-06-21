#!/usr/bin/env python3
"""merge_findings.py — idempotently merge one findings file into another (in place).

Used by Analyze-Memory-Linux.sh to fold Memory_Findings_*.json into Combined_Findings_*.json
before re-adjudication. De-duplicates by finding CONTENT — (Type, Target, Details, Severity,
MITRE) — because the Timestamp is set at analysis time and so differs between runs. Without this,
re-running the analysis kept appending the same memory findings (the Combined file ballooned).

    merge_findings.py <combined.json> <new.json>   # writes deduped union back to <combined.json>
"""
import json
import sys


def _load(path):
    try:
        with open(path, encoding="utf-8-sig") as fh:
            d = json.load(fh)
        return d if isinstance(d, list) else [d]
    except (OSError, ValueError):
        return []


def _key(f):
    # Identity of a finding independent of when it was produced (Timestamp excluded on purpose).
    return (f.get("Type"), f.get("Target"), f.get("Details"),
            f.get("Severity"), f.get("MITRE"))


def merge(into_items, new_items):
    """Return the de-duplicated union, preserving first-seen order."""
    seen, out = set(), []
    for f in list(into_items) + list(new_items):
        if not isinstance(f, dict):
            continue
        k = _key(f)
        if k in seen:
            continue
        seen.add(k)
        out.append(f)
    return out


def main():
    if len(sys.argv) < 3:
        print("usage: merge_findings.py <combined.json> <new.json>", file=sys.stderr)
        return 2
    combined, new = sys.argv[1], sys.argv[2]
    merged = merge(_load(combined), _load(new))
    with open(combined, "w", encoding="utf-8") as fh:
        json.dump(merged, fh, indent=2)
    print(f"merged {len(merged)} unique finding(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
