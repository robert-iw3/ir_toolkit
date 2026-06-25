#!/usr/bin/env python3
"""
finding_schema.py - the canonical IR finding schema shared by every platform.

Windows (Get-FindingContext), Linux (adjudicate.py), and cloud (adjudicate_cloud.py)
all emit findings that must conform to this schema so reporting, IOC extraction, and
eradication can consume any platform's output uniformly.

Schema (field names are matched case-insensitively):
    Type      required   finding class, e.g. "Remote Access Tool", "Cloud Detection"
    Target    required   what the finding is about (PID/host/CLSID/...)
    Verdict   adjudicated findings only; one of VERDICTS
    MITRE     recommended  ATT&CK technique id(s)

VERDICTS is the single shared verdict ladder. Validate any adjudicator's output with
validate(findings) -> [errors]; an empty list means conformant.
"""
import json
import sys

VERDICTS = ("False Positive", "Likely False Positive", "Indeterminate",
            "Likely True Positive", "True Positive")
VERDICT_RANK = {v: i for i, v in enumerate(VERDICTS)}
REQUIRED = ("Type", "Target")


def _ci(finding, name):
    """Case-insensitive field fetch."""
    for k, v in finding.items():
        if k.lower() == name.lower():
            return v
    return None


def validate(findings, adjudicated=True):
    """Return a list of human-readable schema errors ([] == conformant)."""
    errors = []
    if not isinstance(findings, list):
        return [f"top level must be a list, got {type(findings).__name__}"]
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            errors.append(f"[{i}] not an object")
            continue
        for req in REQUIRED:
            if _ci(f, req) in (None, ""):
                errors.append(f"[{i}] missing required field '{req}'")
        if adjudicated:
            verdict = _ci(f, "Verdict")
            if verdict in (None, ""):
                errors.append(f"[{i}] adjudicated finding missing 'Verdict'")
            elif verdict not in VERDICTS:
                errors.append(f"[{i}] verdict '{verdict}' not in the canonical ladder")
    return errors


def validate_file(path, adjudicated=True):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return validate(json.load(fh), adjudicated=adjudicated)


def main(argv=None):
    paths = argv if argv is not None else sys.argv[1:]
    if not paths:
        print("usage: finding_schema.py FINDINGS.json [...]", file=sys.stderr)
        return 2
    rc = 0
    for p in paths:
        errs = validate_file(p)
        if errs:
            rc = 1
            print(f"FAIL {p}")
            for e in errs[:20]:
                print(f"  - {e}")
        else:
            print(f"OK   {p}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
