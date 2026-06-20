#!/usr/bin/env python3
"""
evidence_custody.py — chain-of-custody record + tamper-evident signing for a collection.

The collectors already write a sha256 `_manifest_<stamp>.json` of every artifact. This
seals that manifest: it records WHO collected, WHEN, from WHERE, and the manifest's own
sha256, then signs it so later tampering is detectable. Writes a per-run
`_custody_<stamp>.json` and appends to an append-only `_custody_log.jsonl` trail.

Signing backend (auto-selected by env; first match wins):
  IR_SIGNING_GPG_KEY   -> GPG detached, armored signature of the manifest (_manifest_*.json.asc)
  IR_SIGNING_KEY       -> OpenSSL detached signature with that PEM private key (_manifest_*.json.sig)
  IR_CUSTODY_HMAC_KEY  -> HMAC-SHA256 over the manifest (shared-secret, in-record)
  (none)               -> unsigned; the manifest sha256 in the record is still tamper-evident

Operator identity: IR_OPERATOR env, else `<user>@<host>`.

Usage:
  evidence_custody.py --host-folder DIR [--incident-id ID] [--platform linux|cloud]
  evidence_custody.py --host-folder DIR --verify
Writes/updates _custody_<stamp>.json (+ signature sidecar) and _custody_log.jsonl.
"""
import argparse
import datetime
import getpass
import glob
import hashlib
import hmac
import json
import os
import platform as _platform
import socket
import subprocess
import sys

TOOLKIT_VERSION = "ir-toolkit/1.x"


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def operator():
    if os.environ.get("IR_OPERATOR"):
        return os.environ["IR_OPERATOR"]
    try:
        user = getpass.getuser()
    except Exception:
        user = os.environ.get("USER") or "unknown"
    return f"{user}@{socket.gethostname()}"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def newest(host_folder, pattern):
    hits = sorted(glob.glob(os.path.join(host_folder, pattern)), key=os.path.getmtime,
                  reverse=True)
    return hits[0] if hits else None


# -- record (pure) ------------------------------------------------------------
def build_record(manifest_path, incident_id=None, op=None, platform_name=None):
    """Build the unsigned custody record from a manifest file. Pure (besides file read)."""
    manifest = {}
    try:
        with open(manifest_path, "r", encoding="utf-8-sig", errors="replace") as fh:
            manifest = json.load(fh)
    except Exception:
        manifest = {}
    return {
        "type": "chain_of_custody",
        "incident_id": incident_id or manifest.get("incident_id"),
        "hostname": manifest.get("hostname"),
        "platform": platform_name or manifest.get("platform"),
        "collected_by": op or operator(),
        "collector_host": socket.gethostname(),
        "collector_os": _platform.platform(),
        "toolkit_version": TOOLKIT_VERSION,
        "sealed_utc": now_utc(),
        "manifest_file": os.path.basename(manifest_path),
        "manifest_sha256": sha256_file(manifest_path),
        "artifact_count": manifest.get("artifact_count"),
    }


# -- signing ------------------------------------------------------------------
def hmac_sign(data_bytes, key):
    return hmac.new(key.encode("utf-8"), data_bytes, hashlib.sha256).hexdigest()


def hmac_verify(data_bytes, key, mac):
    return hmac.compare_digest(hmac_sign(data_bytes, key), mac or "")


def sign_manifest(manifest_path):
    """Sign the manifest with whatever backend the environment selects. Returns a
    signature dict describing the method (and writes any sidecar file)."""
    gpg_key = os.environ.get("IR_SIGNING_GPG_KEY")
    ssl_key = os.environ.get("IR_SIGNING_KEY")
    hmac_key = os.environ.get("IR_CUSTODY_HMAC_KEY")

    if gpg_key:
        sig_path = manifest_path + ".asc"
        try:
            subprocess.run(["gpg", "--batch", "--yes", "--armor", "--detach-sign",
                            "--local-user", gpg_key, "--output", sig_path, manifest_path],
                           check=True, capture_output=True, timeout=60)
            return {"method": "gpg", "key_id": gpg_key,
                    "signature_file": os.path.basename(sig_path)}
        except (OSError, subprocess.SubprocessError) as e:
            return {"method": "gpg", "key_id": gpg_key, "error": str(e)}
    if ssl_key:
        sig_path = manifest_path + ".sig"
        try:
            subprocess.run(["openssl", "dgst", "-sha256", "-sign", ssl_key,
                            "-out", sig_path, manifest_path],
                           check=True, capture_output=True, timeout=60)
            return {"method": "openssl", "key": ssl_key,
                    "signature_file": os.path.basename(sig_path)}
        except (OSError, subprocess.SubprocessError) as e:
            return {"method": "openssl", "key": ssl_key, "error": str(e)}
    if hmac_key:
        with open(manifest_path, "rb") as fh:
            data = fh.read()
        return {"method": "hmac-sha256", "value": hmac_sign(data, hmac_key)}
    return {"method": "unsigned",
            "note": "manifest_sha256 in the record is tamper-evident; "
                    "set IR_SIGNING_GPG_KEY / IR_SIGNING_KEY / IR_CUSTODY_HMAC_KEY to sign"}


def write_custody(host_folder, incident_id=None, platform_name=None):
    manifest_path = newest(host_folder, "_manifest_*.json")
    if not manifest_path:
        raise FileNotFoundError("no _manifest_*.json in host folder")
    record = build_record(manifest_path, incident_id, operator(), platform_name)
    record["signature"] = sign_manifest(manifest_path)

    stamp = os.path.basename(manifest_path).replace("_manifest_", "").replace(".json", "")
    out_path = os.path.join(host_folder, f"_custody_{stamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)
    # append to the running custody trail
    with open(os.path.join(host_folder, "_custody_log.jsonl"), "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"sealed_utc": record["sealed_utc"],
                             "collected_by": record["collected_by"],
                             "manifest_file": record["manifest_file"],
                             "manifest_sha256": record["manifest_sha256"],
                             "signature_method": record["signature"]["method"]}) + "\n")
    return record, out_path


# -- verification -------------------------------------------------------------
def verify_custody(host_folder):
    """Re-derive the manifest hash and check it (and HMAC, when used) against the
    custody record. Returns (ok, issues)."""
    cust_path = newest(host_folder, "_custody_*.json")
    if not cust_path:
        return False, ["no _custody_*.json found"]
    with open(cust_path, "r", encoding="utf-8") as fh:
        record = json.load(fh)
    issues = []
    manifest_path = os.path.join(host_folder, record.get("manifest_file", ""))
    if not os.path.isfile(manifest_path):
        return False, [f"manifest {record.get('manifest_file')} missing"]
    if sha256_file(manifest_path) != record.get("manifest_sha256"):
        issues.append("manifest sha256 mismatch — evidence manifest was modified after sealing")
    sig = record.get("signature", {})
    if sig.get("method") == "hmac-sha256":
        key = os.environ.get("IR_CUSTODY_HMAC_KEY")
        if not key:
            issues.append("HMAC signature present but IR_CUSTODY_HMAC_KEY not set — cannot verify")
        else:
            with open(manifest_path, "rb") as fh:
                if not hmac_verify(fh.read(), key, sig.get("value")):
                    issues.append("HMAC signature mismatch — manifest or signature altered")
    elif sig.get("method") == "gpg" and sig.get("signature_file"):
        asc = os.path.join(host_folder, sig["signature_file"])
        try:
            r = subprocess.run(["gpg", "--verify", asc, manifest_path],
                               capture_output=True, timeout=60)
            if r.returncode != 0:
                issues.append("GPG signature verification failed")
        except (OSError, subprocess.SubprocessError) as e:
            issues.append(f"GPG verify unavailable: {e}")
    return (not issues), issues


def main():
    ap = argparse.ArgumentParser(description="Evidence chain-of-custody + signing")
    ap.add_argument("--host-folder", required=True)
    ap.add_argument("--incident-id")
    ap.add_argument("--platform")
    ap.add_argument("--verify", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    if args.verify:
        ok, issues = verify_custody(args.host_folder)
        if not args.quiet:
            print(f"[custody] {'OK' if ok else 'FAILED'}: "
                  + ("; ".join(issues) if issues else "manifest sealed and intact"))
        return 0 if ok else 2

    try:
        record, out_path = write_custody(args.host_folder, args.incident_id, args.platform)
    except FileNotFoundError as e:
        print(f"[custody] {e}", file=sys.stderr)
        return 1
    if not args.quiet:
        print(f"[custody] sealed by {record['collected_by']} "
              f"({record['signature']['method']}) -> {os.path.basename(out_path)}")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
