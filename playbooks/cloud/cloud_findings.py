#!/usr/bin/env python3
"""
cloud_findings.py - the shared building blocks every cloud normalizer module uses:
the verdict ladder, JSON readers, severity test, the finding constructor, and the
technique-id parser. Kept dependency-free so each analyzer module can import it
without pulling in the others.
"""
import json

VERDICT_RANK = {"False Positive": 0, "Likely False Positive": 1,
                "Indeterminate": 2, "Likely True Positive": 3, "True Positive": 4}
HIGH_SEV = {"HIGH", "CRITICAL", "SEV_HIGH", "8", "9", "10"}


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return fh.read()
    except Exception:
        return ""


def sev_is_high(value):
    return str(value).upper() in HIGH_SEV or (str(value).replace(".", "").isdigit()
                                              and float(value) >= 7.0)


def finding(ftype, target, details, mitre, verdict, confidence, severity="High"):
    return {"Type": ftype, "Target": target, "Details": details, "MITRE": mitre,
            "Severity": severity, "Verdict": verdict, "Confidence": confidence,
            "Source": "cloud"}


def technique_ids(mitre):
    """Pull the bare technique id(s) (e.g. 'T1098.001') out of a MITRE string."""
    ids = []
    for tok in str(mitre or "").replace(",", " ").split():
        t = tok.strip("()")
        if t.startswith("T") and t[1:2].isdigit():
            ids.append(t)
    return ids
