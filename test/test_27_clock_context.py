"""Host clock / timezone capture + UTC normalization (clock_context.py).

Closes the Collection gap: per-host clock skew and timezone were never captured, so
cross-host timeline correlation silently misaligned. Captures tz/offset/NTP/skew and
provides normalize_to_utc() to put local-time artifacts on one comparable basis.
"""
import json
import os
import subprocess
import sys

from conftest import REPORTING

sys.path.insert(0, REPORTING)
import clock_context as cc          # noqa: E402


def test_capture_without_reference():
    rec = cc.capture()
    assert rec["type"] == "clock_context"
    assert "timezone" in rec and "utc_offset_seconds" in rec
    assert rec["skew_seconds"] is None              # no reference -> unmeasured
    assert rec["ntp_synchronized"] in (True, False, None)


def test_capture_skew_ahead_and_behind():
    # host clock 30s ahead of the trusted reference
    rec = cc.capture(reference_epoch=1_700_000_000, host_epoch=1_700_000_030)
    assert rec["skew_seconds"] == 30.0 and "ahead of" in rec["skew_note"]
    # host clock 30s behind
    rec2 = cc.capture(reference_epoch=1_700_000_000, host_epoch=1_699_999_970)
    assert rec2["skew_seconds"] == -30.0 and "behind" in rec2["skew_note"]


def test_capture_skew_within_tolerance():
    rec = cc.capture(reference_epoch=1_700_000_000, host_epoch=1_700_000_001)
    assert abs(rec["skew_seconds"]) <= 2 and "within 2s" in rec["skew_note"]


def test_normalize_local_to_utc():
    # 12:00 in an EST-style -5h zone -> 17:00Z
    assert cc.normalize_to_utc("2026-06-20 12:00:00", -5 * 3600) == "2026-06-20T17:00:00Z"
    # east-of-UTC +9h: 12:00 -> 03:00Z
    assert cc.normalize_to_utc("2026-06-20 12:00:00", 9 * 3600) == "2026-06-20T03:00:00Z"


def test_normalize_applies_skew():
    # offset 0, host 10s ahead -> subtract 10s to land on reference basis
    assert cc.normalize_to_utc("2026-06-20 12:00:10", 0, skew_seconds=10) == "2026-06-20T12:00:00Z"


def test_normalize_bad_timestamp_is_none():
    assert cc.normalize_to_utc("not a timestamp", 0) is None
    assert cc.normalize_to_utc(None, 0) is None


def test_offset_string_format():
    rec = cc.capture()
    assert ":" in rec["utc_offset"] and rec["utc_offset"][0] in "+-"


def test_cli_writes_clock_json(tmp_path):
    r = subprocess.run(
        [sys.executable, os.path.join(REPORTING, "clock_context.py"),
         "--host-folder", str(tmp_path), "--reference-epoch", "1700000000",
         "--incident-id", "C1", "--quiet"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    rec = json.loads((tmp_path / "_clock.json").read_text())
    assert rec["incident_id"] == "C1" and "timezone" in rec
