# 03 · Capture Volatile Memory

*The single most important, most perishable evidence on the box. Get it now, before anything
else touches the machine.*

---

## The situation

RAM holds the things that **never touch disk** and **vanish at reboot**:

- **Fileless / in-memory-only malware** — reflective-loaded DLLs, decrypted-in-RAM payloads. A
  disk-only investigation *cannot see these at all.*
- **Process injection & live C2** — injected code regions, the established attacker socket, and
  the *decoded* command behind an obfuscated one-liner.
- **Rootkit ground truth** — kernel rootkits hide processes/modules from the *live* OS; a raw
  memory image exposes them by cross-referencing kernel structures.
- **Cleartext secrets** — credentials, keys, and tokens that are encrypted on disk sit
  *decrypted* in RAM.

> **This is a one-shot (RFC 3227).** Reboot or power-off and it is gone forever. For any serious
> investigation, **capture memory first and analyze it** (step 08). Skipping memory means an
> analysis that is incomplete by construction and can be actively deceived by a present attacker.

---

## Step 1 — Pick an acquisition tool (run it from your USB kit, not the disk)

| Tool | Output | Notes |
|---|---|---|
| **WinPmem / go-winpmem** | `.aff4` (sparse) or `.raw` | Free, open, scriptable. AFF4 captures only real RAM pages. The toolkit's default. |
| **Magnet RAM Capture** | `.raw` / `.dmp` | Free GUI, dead simple — good for beginners. |
| **FTK Imager** | `.mem` / `.raw` | Also images disk; widely trusted in legal contexts. |

All produce a raw physical image analyzable by MemProcFS or Volatility 3 later.

## Step 2 — Capture to external media, then hash immediately

```powershell
# From your trusted USB/kit. Write the image to an EXTERNAL drive (E:), never the suspect disk.
E:\tools\winpmem.exe E:\IR-CASE\evidence\memory_HOST.raw

# Hash it the instant it finishes — this is your integrity anchor and custody record
Get-FileHash -Algorithm SHA256 E:\IR-CASE\evidence\memory_HOST.raw |
    Tee-Object E:\IR-CASE\evidence\memory_HOST.sha256

# Record size + time in UTC in your notes
Get-Item E:\IR-CASE\evidence\memory_HOST.raw | Select-Object Length, CreationTimeUtc
```

**Why external media:** writing a multi-GB image to the suspect's own disk overwrites free space
(destroying deleted-file evidence) and trusts a disk you've assumed is compromised.

## Step 3 — Validate the capture before you rely on it

A truncated image is worse than none — you'll draw conclusions from missing data.

- **Size sanity:** the image should be roughly the size of installed RAM (AFF4 sparse will be
  smaller — only committed pages). A 200 MB "image" of a 16 GB host is a failed capture.
- **Tool exit code 0**, no errors in its log.
- If it failed, **rename it so you never mistake it for good evidence** (e.g.
  `INVALID_memory_HOST.raw`) and re-capture.

> **FAT32 media caps files at 4 GiB.** Memory images exceed that. Use an **NTFS or exFAT**
> external drive, or your capture will silently truncate.

## Step 4 — Note the pitfalls (so you don't get fooled in step 08)

- The **acquisition tool's own process** buffers slices of physical RAM, so *its* memory holds
  ambient strings from every other process. Strings recovered from `winpmem.exe` are **not** its
  C2 — they're unattributed RAM. Remember this when you analyze.
- **Don't analyze on the compromised host.** Move the image to your **analyst workstation** for
  step 08. Analyzing on the victim trusts a potentially-lying OS and risks the attacker seeing you.

---

## If you genuinely can't capture memory

Sometimes you can't (no tooling, locked-down host, the box already rebooted). Then:
- Say so explicitly in your notes — every later conclusion is now "disk-and-logs only," and you
  must state that limitation in the report.
- Lean harder on live process/network state (step 04) *before* anything reboots it away.
- Still grab a **process dump** of the specific suspect PID if you can — a targeted slice of the
  volatile evidence:
  ```powershell
  E:\tools\procdump64.exe -accepteula -ma 1234 E:\IR-CASE\evidence\pid1234.dmp
  ```

---

## Where you are, and what's next

The perishable core is safely off the box and hashed. The host is still running, so now grab the
rest of the live state — processes, connections, sessions — while it's still live and truthful.

➡️ Next: [04-snapshot-live-system-state.md](04-snapshot-live-system-state.md)

*Toolkit parallel: **Phase 1 memory capture** — `Invoke-IRCollection.ps1 -CaptureMemory` runs
go-winpmem to `reports\<HOST>\memory_<HOST>.aff4`, auto-redirects FAT32 volumes, and renames
failed captures `INVALID_*`. Analysis is Phase 3 (step 08 here).*
