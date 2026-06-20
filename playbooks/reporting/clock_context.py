#!/usr/bin/env python3
"""
clock_context.py — capture host clock / timezone context and normalize timestamps to UTC.

Closes the Collection gap: timelines mix local and UTC, and per-host clock skew is never
captured — so cross-host correlation silently misaligns. This records, at collection time:
  - the host timezone + UTC offset,
  - whether the clock is NTP-synchronized,
  - the measured skew between the host clock and a trusted reference (the responder's
    NTP-synced UTC, passed by the orchestrator),
into `_clock.json`, and provides `normalize_to_utc()` so local-time artifact timestamps can
be converted to a single comparable UTC basis.

Read-only. Degrades gracefully (timedatectl absent -> NTP status unknown, never fatal).

Usage:
    clock_context.py --host-folder DIR [--reference-epoch <trusted UTC seconds>]
                     [--incident-id ID] [--quiet]
Writes _clock.json and prints its path.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time


def now_utc_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def local_utc_offset_seconds(when=None):
    """Current local UTC offset in seconds (east of UTC positive), DST-aware."""
    when = when or datetime.datetime.now()
    off = when.astimezone().utcoffset()
    return int(off.total_seconds()) if off else 0


def local_tz_name():
    try:
        name = datetime.datetime.now().astimezone().tzname()
        if name:
            return name
    except Exception:
        pass
    return os.environ.get("TZ") or (time.tzname[0] if time.tzname else "UTC")


def ntp_synchronized():
    """Best-effort: parse `timedatectl` for NTP sync. Returns True/False/None(unknown)."""
    try:
        cp = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                            capture_output=True, text=True, timeout=10, check=False)
        out = cp.stdout.strip().lower()
        if out in ("yes", "true", "1"):
            return True
        if out in ("no", "false", "0"):
            return False
    except (OSError, subprocess.SubprocessError):
        pass
    return None


# -- capture (pure-ish: reads host clock) -------------------------------------
def capture(reference_epoch=None, host_epoch=None):
    """Build the clock-context record.

    reference_epoch: trusted UTC seconds (e.g. the responder's NTP-synced clock). When
                     given, skew_seconds = host_clock - reference (positive = host ahead).
    host_epoch:      override host clock (testing); defaults to time.time().
    """
    host_epoch = time.time() if host_epoch is None else host_epoch
    offset = local_utc_offset_seconds()
    rec = {
        "type": "clock_context",
        "captured_utc": now_utc_iso(),
        "timezone": local_tz_name(),
        "utc_offset_seconds": offset,
        "utc_offset": f"{'+' if offset >= 0 else '-'}{abs(offset)//3600:02d}:{(abs(offset)%3600)//60:02d}",
        "host_clock_utc": datetime.datetime.fromtimestamp(
            host_epoch, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "ntp_synchronized": ntp_synchronized(),
        "skew_seconds": None,
        "skew_note": "no trusted reference supplied — skew unmeasured",
    }
    if reference_epoch is not None:
        skew = round(host_epoch - float(reference_epoch), 3)
        rec["skew_seconds"] = skew
        if abs(skew) <= 2:
            rec["skew_note"] = "host clock within 2s of reference"
        else:
            rec["skew_note"] = (f"host clock is {abs(skew):.1f}s "
                                f"{'ahead of' if skew > 0 else 'behind'} the reference — "
                                f"adjust this host's timestamps before cross-host correlation")
    return rec


# -- normalization ------------------------------------------------------------
def normalize_to_utc(local_ts, offset_seconds, fmt="%Y-%m-%d %H:%M:%S", skew_seconds=0):
    """Convert a naive local timestamp string to a UTC ISO string.

    Subtracts the host UTC offset to reach UTC, then subtracts measured clock skew so the
    result is on the trusted reference's basis. Returns None if the timestamp can't parse.
    """
    try:
        dt = datetime.datetime.strptime(local_ts.strip(), fmt)
    except (ValueError, AttributeError):
        return None
    utc = dt - datetime.timedelta(seconds=offset_seconds) \
             - datetime.timedelta(seconds=skew_seconds or 0)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    ap = argparse.ArgumentParser(description="Capture host clock/timezone context")
    ap.add_argument("--host-folder", required=True)
    ap.add_argument("--incident-id")
    ap.add_argument("--reference-epoch", type=float,
                    help="trusted UTC seconds (responder NTP clock) to measure skew against")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    rec = capture(reference_epoch=args.reference_epoch)
    if args.incident_id:
        rec["incident_id"] = args.incident_id
    out_path = os.path.join(args.host_folder, "_clock.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, indent=2)
    if not args.quiet:
        skew = rec["skew_seconds"]
        print(f"[clock] tz={rec['timezone']} offset={rec['utc_offset']} "
              f"ntp={rec['ntp_synchronized']} "
              f"skew={'%.1fs' % skew if skew is not None else 'n/a'} -> {out_path}")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
