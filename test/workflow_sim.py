"""
workflow_sim.py — executable model of the eradication/restoration contract.

The real eradication (Invoke-Eradication.ps1 / playbooks/linux/02_eradicate_process.sh)
and restoration (06_Restore-Host.ps1 / 06_restore.sh) scripts share one reversible
contract that this module reproduces so it can be proven end-to-end on any host:

    quarantine: move the malicious binary aside and append a rollback-journal line
                {"action":"quarantine","original":...,"dest":...,"sha256":...}
    restore:    read the journal, and ONLY move a quarantined file back if its
                sha256 still matches what was recorded (never restore tampered bytes).

These are the exact semantics of 06_Restore-Host.ps1 (sha256 check before Move-Item)
and 06_restore.sh (sha256 verify against the journal).
"""
import hashlib
import json
import os
import shutil


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def quarantine(original, quarantine_dir, journal):
    """Eradicate a file: move to quarantine, record a reversible journal line."""
    os.makedirs(quarantine_dir, exist_ok=True)
    digest = sha256(original)
    dest = os.path.join(quarantine_dir, f"{digest[:12]}_{os.path.basename(original)}.quarantine")
    entry = {"action": "quarantine", "original": original, "dest": dest, "sha256": digest}
    with open(journal, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")
    shutil.move(original, dest)
    return entry


def restore(journal):
    """Restoration: replay the journal, sha256-verified. Returns (restored, skipped)."""
    restored, skipped = [], []
    if not os.path.exists(journal):
        return restored, skipped
    with open(journal, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("action") != "quarantine":
                continue
            if not os.path.exists(e["dest"]):
                skipped.append(e["original"])
                continue
            if sha256(e["dest"]).lower() != e["sha256"].lower():
                skipped.append(e["original"])     # never restore tampered bytes
                continue
            parent = os.path.dirname(e["original"])
            if parent and not os.path.isdir(parent):
                os.makedirs(parent, exist_ok=True)
            shutil.move(e["dest"], e["original"])
            restored.append(e["original"])
    return restored, skipped


# -- Credential-revocation contract (account disable, reversible) --------------
# Models the OS-level "disable account + journal prior state" that the real
# eradication scripts perform (Disable-LocalUser / passwd -l / IAM disable). The
# `store` is an account database {name: {"enabled": bool}}; restore re-enables only
# what the journal recorded, so a false-positive disable is reversible.
PROTECTED_ACCOUNTS = {"system", "administrator", "root", "guest"}


def revoke_account(store, name, journal, force=False):
    """Disable an account, recording its prior state. Refuses protected accounts."""
    if name.lower() in PROTECTED_ACCOUNTS and not force:
        return "protected"
    acct = store.setdefault(name, {"enabled": True})
    prior = acct["enabled"]
    with open(journal, "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"action": "disable_account", "name": name,
                             "prior_enabled": prior}) + "\n")
    acct["enabled"] = False
    return "disabled" if prior else "already-disabled"


def restore_accounts(store, journal):
    """Re-enable accounts to the prior state recorded in the journal."""
    restored = []
    if not os.path.exists(journal):
        return restored
    with open(journal, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("action") != "disable_account":
                continue
            if e.get("prior_enabled") and e["name"] in store:
                store[e["name"]]["enabled"] = True
                restored.append(e["name"])
    return restored
