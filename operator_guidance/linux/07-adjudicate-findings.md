# 07 · Adjudicate Findings (Linux)

*Turn your pile of "suspicious" things into defensible verdicts. Same discipline, same ladder, as
[../windows/07-adjudicate-findings.md](../windows/07-adjudicate-findings.md) — here are the Linux
context checks.*

---

## The verdict ladder (unchanged)

```
False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive
```

Nothing is dropped silently; weak signals stay weak alone; "Likely True Positive" is the
*look-here-first* signal. What changes on Linux is *how you gather the context* that moves a
finding up or down.

## The Linux context checks (instead of Authenticode)

### 1 — Package provenance: does a package own this file?

Linux's equivalent of "is it signed by a trusted publisher" is "does the package manager own it,
and does it still match?"

```bash
# Is the binary owned by an installed package?
dpkg -S /path/to/bin 2>/dev/null || rpm -qf /path/to/bin 2>/dev/null
# Does it still match what the package shipped (tamper check)?
dpkg -V <pkg> 2>/dev/null            # any output = a file changed from the packaged version
rpm -V  <pkg> 2>/dev/null            # '5' in the flags = MD5/hash mismatch (modified binary)
```

- **Package-owned and verifies clean** → strong exculpatory evidence (still check the path/behavior).
- **Not owned by any package**, living outside standard dirs → **weak-to-moderate** suspicion (lots
  of legit local software isn't packaged — a `Likely FP` unless corroborated).
- **Package-owned but fails verification** (modified from shipped hash) → **strong** signal: a
  trojanized system binary.

### 2 — Path & provenance

`/usr/bin`, `/usr/sbin`, `/opt/<vendor>` = expected. `/tmp`, `/var/tmp`, `/dev/shm`, a home dir,
`(deleted)`, `memfd:` = **suspicious location** — where Linux malware runs.

### 3 — Hash & reputation

```bash
sha256sum /path/to/bin
```

Check the SHA256 against known-good and (safely — step 09) against threat intel **by hash, not by
uploading**. Known-bad convicts; a hash matching the real distro binary clears.

### 4 — Corroboration (the multiplier)

A single weak signal stays weak; stacked signals convict. The strongest Linux convergence:
**a network connection or listener owned by a deleted / `memfd` / writable-path binary = C2
regardless of port.** Add impossible parentage (shell under `sshd`/`nginx`), an `authorized_keys`
backdoor, and a cron/systemd persistence entry pointing at the same binary → **True Positive**.

Weak-alone examples (→ **Indeterminate** without more): high entropy; a world-writable file; a
SUID binary that's actually a legit setuid tool; an unpackaged binary that's just local software.

### 5 — Rule out the benign explanation

- Is the "deleted" binary just a **package upgrade** that replaced a running daemon's on-disk file?
  Check the package-transaction log (step 05) for a matching upgrade at that time — if it matches,
  that's the benign explanation.
- Is the anonymous exec memory a **JIT runtime** (JVM/.NET/browser/V8) rather than injected
  shellcode? Those have a legitimate parent process and no C2 socket.
- Is it the **toolkit's own tools** (avml, yara64, your `python3`)? Cleared outright; their
  recovered strings are never host IOCs.

---

## Worked examples

| Finding | Context gathered | Verdict |
|---|---|---|
| `/dev/shm/.x` running, socket to 45.x.x.x:443 | Not packaged, exe deleted, parent is `nginx` | **True Positive** (writable-path + deleted + C2 + RCE parentage converge) |
| `sshd` daemon file shows `(deleted)` | `apt history.log` shows an `openssh-server` upgrade at that minute | **Likely FP** (benign upgrade replaced the running binary) |
| Anonymous exec memory in `java` | Legit app, parent is systemd unit, no odd socket | **Likely FP** (JVM JIT) |
| SUID `bash` in `/home/user` | Owner root, mode 4755, no package owns it | **True Positive** (root-persistence backdoor) |
| Unpackaged binary in `/opt/app` | Vendor app, signed installer, expected, no network anomaly | **Likely FP** (unpackaged ≠ malicious) |

## Extract IOCs as you confirm

For every **True / Likely True**, record: C2 endpoints (IP:port), file **sha256**, implicated
**accounts/keys** (for revocation), persistence locations, and ATT&CK techniques. You'll feed these
to eradication (step 10) and the report (step 12).

---

➡️ Next: [08-memory-forensics.md](08-memory-forensics.md)

*Toolkit parallel: the Linux adjudicator merges every module's findings through the same verdict
ladder, applies the package-upgrade theory-check, and emits `IOCs.json` / `Principals.json` here.*
