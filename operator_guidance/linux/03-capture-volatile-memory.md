# 03 · Capture Volatile Memory (Linux)

*Top of the volatility ladder, one-shot, gone at reboot. On Linux it also catches the things
Linux malware loves: `memfd`/fileless payloads, LD_PRELOAD rootkits, and hidden kernel modules.*

Why memory matters is covered in
[../windows/03-capture-volatile-memory.md](../windows/03-capture-volatile-memory.md). Here's the
Linux how.

---

## Step 1 — Acquire the image (to external media)

**AVML** (Microsoft, static binary, no kernel headers needed) is the easiest reliable path:

```bash
# From your kit, write to mounted external evidence media — never the suspect disk
./avml /mnt/evidence/$CASE/evidence/memory.lime
sha256sum /mnt/evidence/$CASE/evidence/memory.lime | tee evidence/memory.lime.sha256
```

Alternatives: **LiME** (kernel module — needs headers matching the running kernel), or on a
crash-kernel-configured host, an existing dump. AVML avoids the module-build problem, which is why
the toolkit stages it.

## Step 2 — The symbol problem (plan for it now)

Linux memory analysis (Volatility 3) needs a **symbol table (ISF)** that matches the target's
**exact kernel version**. This is the single biggest Linux-memory gotcha.

```bash
uname -r                          # RECORD THIS — the exact kernel build you must match
cat /etc/os-release | tee evidence/os-release.txt
```

Capture the kernel version and distro now. You (or the toolkit) will generate the ISF with
`dwarf2json` from matching debug symbols before analysis in step 08. If you can grab the kernel
debug package (`debuginfod`, or the distro's `-dbgsym`/`kernel-debuginfo`) while online, do it now.

## Step 3 — Validate

- Image size roughly tracks committed RAM (LiME format is not fully sparse).
- If acquisition errored, **rename it `INVALID_memory.lime`** so you never trust a truncated image.
- Use **exFAT/ext4** external media, not FAT32 (4 GiB file cap).

## If you can't capture full memory

- Say so in your notes — every later conclusion becomes "disk + `/proc` + logs only."
- Grab a **targeted process image** of the suspect instead — a slice of the volatile evidence:
  ```bash
  # Dump a process's memory + maps for offline analysis (from /proc, while it's frozen)
  cp /proc/<PID>/maps evidence/pid<PID>.maps
  cat /proc/<PID>/mem > evidence/pid<PID>.mem 2>/dev/null   # needs root; ranges per maps
  # Or use gcore for a portable core dump:
  gcore -o evidence/pid<PID> <PID>
  ```
- `/proc/<PID>/exe` still lets you **recover a deleted-but-running binary** directly:
  ```bash
  cp /proc/<PID>/exe evidence/recovered_<PID>.bin    # pulls the on-disk image back even if unlinked
  ```

## Don't analyze on the victim

Move the image (and its hash) to your **analyst box** for step 08. Analyzing on the compromised
host trusts a possibly-lying kernel and risks the attacker seeing you.

---

➡️ Next: [04-snapshot-live-system-state.md](04-snapshot-live-system-state.md)

*Toolkit parallel: `Invoke-IRCollection-Linux.sh --capture-memory` runs AVML; the offline
`Build-OfflineToolkit-Linux.sh --include-memory [--stage-symbols]` vendors Volatility 3 +
`dwarf2json` + kernel ISF so analysis works air-gapped.*
