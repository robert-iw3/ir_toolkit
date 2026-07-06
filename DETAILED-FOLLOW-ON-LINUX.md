# Detailed Follow-On Investigation — Linux

Generic playbook for pivoting from IR Toolkit output into live-host triage.

> **Living document.** This guide is continuously revised as investigations surface new FP patterns, additional attack vectors, and investigative shortcuts. The long-term goal is for every section here to become an automated playbook step — commands, logic branches, and disposition rules encoded into the toolkit itself.

---

## Automation Status (as of 2026-07-06)

What `playbooks/linux/investigation/` (the second-pass QA/correlation engine) currently
automates from this guide, by section:

- **§2 Deleted Binary / memfd** — `modules/deleted_binary.py` reproduces the writable-vs-package-path
  table; `journal_analysis.py`'s package-manager-event collection (dpkg/apt log, pacman log, RPM
  database) plus `correlator.py`'s upgrade-window match confirm or refute the "package upgrade" FP
  theory with an actual transaction, not an assumption.
- **§3 Hidden Process** — `modules/hidden_process.py` scores the memory-vs-`/proc` asymmetry.
- **§4 Injected/Anonymous-Executable Memory** — `modules/injected_memory.py` (malfind, JIT-runtime
  exemption voided only by a genuine disproof finding, never by process name alone) and
  `modules/ptrace.py`'s `Corroborated Injected Thread` (a TID independently flagged by both
  `linux.pscallstack`'s memory-forensic stack walk and `thread_inventory.py`'s live enumeration).
- **§5 Kernel Rootkit Signals** — `modules/kernel_rootkit.py` scores hidden-module/hook/usermodehelper
  findings as Tier 1 (DEFINITIVE) — a single structurally-unforgeable fact settles TRUE_POSITIVE.
- **§6 Credential Override / Privesc** — `modules/credential_privesc.py`.
- **§7 eBPF / io_uring** — `modules/ebpf_io_uring.py` (agent-name match is context only, never a
  tier-crossing downgrade).
- **§8 Namespace Escape / Container Breakout** — `modules/namespace_container.py` (same
  name-is-context-only rule as §7).
- **§9 Persistence** — `modules/persistence.py`; `adjudicate.py`'s package-ownership/integrity
  resolution is consumed directly (`correlator.py`'s `_package_integrity_dimension`) so "verify
  package ownership before closing" is answered, not left as an instruction — a tampered packaged
  binary is DEFINITIVE TRUE_POSITIVE regardless of finding type, an unowned file in a trusted path
  is incriminating (not exonerating).
- **§10 Network Connection Triage** — `modules/network.py`; `engine.py`'s cross-PID
  shared-infrastructure propagation corroborates two independently-suspicious PIDs sharing the same
  external endpoint (never from the shared endpoint alone).
- **§11 SSH Key & Account Hygiene** — `modules/ssh_hygiene.py`.
- **§1 Triage Live Processes** — process-lineage propagation (`engine.py`'s
  `_propagate_process_lineage`) corroborates two independently-suspicious PIDs in a direct
  parent/child relationship; `thread_inventory.py` extends "triage the PID" to every TID under it.
- **§12 Direct YARA / File Scan** — `modules/yara_capa.py`; `c2_config_extract.py` identifies
  Sliver/Mythic/Merlin/Havoc/AdaptixC2/Pupy/BPFDoor/Mirai-class/Ebury-class/XMRig-class by
  protocol-required structure (ELF dynamic symbols, magic-packet sequences, capability mismatches)
  — never brand-name string matching.
- **§15 Eradication Pivot** — `IR_TARGET_TIDS` + `suspend_thread.py` suspend the SPECIFIC compromised
  thread (`PTRACE_SEIZE`/`PTRACE_INTERRUPT`, held by a tracer daemon) instead of killing an entire
  protected/multi-threaded process; `06_restore.sh` reverses it by terminating the tracer.
- **Quick Reference FP patterns** — the deterministic noise filter (`models/noise_filter.py`) covers
  several rows (known-daemon/expected-path background noise); a name match alone never downgrades a
  genuinely strong signal (a name-spoofing vulnerability found and corrected mid-build).

Run it: `python3 -m playbooks.linux.investigation.live_runner reports/<host>/` ->
`Investigation_<host>_<stamp>.{json,md,csv}`. It resolves each finding to
TRUE_POSITIVE/FALSE_POSITIVE/UNDETERMINED/NOISE_CLOSED before a human opens a section below — pivot
into the numbered sections only for what's still UNDETERMINED, or to verify a verdict yourself before
acting on it. Full architecture reference: `playbooks/linux/investigation/README.md`.

Everything else in this guide (live-host queries, YARA/file scan follow-on, eradication mechanics)
runs outside this offline engine by design — it consumes already-collected JSON, it never queries
the live host directly.

---

## How to use this guide

```
Step 1 — Read the toolkit reports
    reports/<host>/EDR_Report_<stamp>.json        <- live-host hunt (edr_hunt.py)
    reports/<host>/Memory_Findings_<stamp>.json   <- per-PID memory + YARA signals
    reports/<host>/Combined_Findings_<stamp>.json <- cross-source adjudication (verdict ladder)
    reports/<host>/Adjudication_<stamp>.json      <- package ownership/integrity, lineage (ParentPid)
    reports/<host>/Thread_Inventory_<stamp>.json  <- per-PID TID enumeration (if a PID was flagged)
    reports/<host>/Incident_Report.md             <- human summary + coverage grid

Step 2 — Run the automated investigation layer
    python3 -m playbooks.linux.investigation.live_runner reports/<host>/
    This already resolves most findings to TRUE_POSITIVE/FALSE_POSITIVE/UNDETERMINED
    (see "Automation Status" above) — it's the disposition logic in every
    section's "Logic breakdown" table, run automatically before a human opens
    a section. Best results when Adjudication_*.json and Thread_Inventory_*.json
    are already present (both are collected automatically during Step 1 of
    WORKFLOW-LINUX.md, but may not exist yet for a report folder gathered
    before those phases existed).

Step 3 — Pivot here for what's left
    For each finding still UNDETERMINED (or to verify a TP/FP yourself before
    acting on it), find the matching section below and run its commands.

Step 4 — Follow the rabbit hole
    Each section ends with a "what to do if suspicious" branch.
    Pursue until you either close the finding as FP or collect enough
    evidence to escalate/remediate.

Step 5 — Document and close
    Append findings to Investigation_Notes_*.md in the report folder.
    Update the disposition for each PID/artifact.
    Open items needing memory carve -> see Section 13.
```

The two engines behind the reports:
- **`edr_hunt.py`** — live-host triage (reads `/proc`, config files, logs). Fast, no image needed. Distro-agnostic.
- **`analyze_memory_linux.py`** — offline analysis of a RAM capture via Volatility 3 + custom `linux_ir.*` plugins. Sees what a live host hides (unlinked modules, kernel hooks, credential overrides).

**Core detection philosophy:** exclusions are made only for an *impossible* attack vector. Where a signal is dual-use, the toolkit **downgrades severity rather than suppressing** — so an `Info`/`verify` finding is a genuine "look at this," not noise to ignore.

---

## Prerequisites

- **Unprivileged shell**: sufficient for your own processes, `ss`, most of `/proc`, reading world-readable configs.
- **root (or `sudo`)**: required to read other users' `/proc/<pid>/{maps,exe,environ,fd}`, `/proc/kcore`, audit config, most logs, and to run the response playbooks.
- Confirm privilege first: `id`; if not 0, prefix triage reads with `sudo` or note the coverage gap.
- Work on a **copy** of volatile evidence where possible; reads of `/proc` are point-in-time — a sleeping implant may not be connected *right now*.

---

## 1 — Triage Live Processes

Confirm whether a PID flagged in the memory report is still running and what it actually is. Memory-report PIDs are from capture time; the live host may have moved on.

```bash
# Liveness + identity for a set of PIDs
for pid in 1234 5678; do
  if [ -d /proc/$pid ]; then
    printf "%s: %s  (exe=%s)\n" "$pid" \
      "$(tr -d '\0' </proc/$pid/comm)" \
      "$(sudo readlink /proc/$pid/exe 2>/dev/null)"
  else
    echo "$pid: not found (exited)"
  fi
done

# Full identity of one PID
pid=1234
sudo cat /proc/$pid/status | grep -E '^(Name|State|PPid|Uid|Gid|Groups|Seccomp)'
sudo readlink /proc/$pid/exe            # backing binary (or "(deleted)")
sudo tr '\0' ' ' </proc/$pid/cmdline; echo
sudo readlink /proc/$pid/cwd
sudo ls -l /proc/$pid/fd | head -40     # open files, sockets, pipes
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| PID not found (exited) | Snapshot postdates the process; a persistence mechanism may have relaunched it under a new PID | Find the relauncher: Section 9 (persistence); search `ps -ef` for the same `comm`/cmdline |
| PID alive, `exe` resolves to a normal signed path | Finding is current; continue with the signal-specific section | Section per finding type |
| `exe` → `(deleted)` | Process is running a binary unlinked from disk — classic implant anti-forensics | Section 2 |
| `exe` unreadable even as root, PID in `/proc` | Possible `/proc` hiding (rootkit) if the PID appears in memory but `comm`/`exe` are blanked | Section 5 (kernel rootkit) |
| `comm` differs from `exe` basename | Process-name masquerade (`comm` set to look benign) | Section 4; compare `cmdline[0]` to `exe` |
| PPid = 1 (reparented to init) but not a known daemon | Parent died after fork (could be normal daemonization or an orphaned dropper) | Check Section 9 for what launched it; not suspicious alone |
| Uid shows `0` but process is a user tool | Unexpected privilege — check for setuid abuse or credential override | Section 6 |

---

## 2 — Process Running a Deleted Binary (memfd / unlinked)

Toolkit signals: `Process Running Deleted Binary (memory)`, `Deleted Running Binary`, `Memory-Only Executable (memfd)`.

```bash
# All live processes whose executable is deleted or memfd-backed
for p in /proc/[0-9]*; do
  exe=$(sudo readlink "$p/exe" 2>/dev/null) || continue
  case "$exe" in
    *"(deleted)"*|*/memfd:*|*memfd:*) echo "$p -> $exe   comm=$(tr -d '\0' <$p/comm)";;
  esac
done

# Recover the running binary straight from the kernel's view (works even when unlinked)
pid=1234
sudo cp /proc/$pid/exe /tmp/recovered_$pid.bin
sha256sum /tmp/recovered_$pid.bin
file /tmp/recovered_$pid.bin
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `exe` → `/path (deleted)` and path was in `/tmp`, `/dev/shm`, `/var/tmp`, `$HOME` | Dropper deleted itself after exec — strong implant indicator | Recover via `cp /proc/$pid/exe`; hash → VT/offline YARA (Section 12); Section 15 eradicate |
| `exe` → `/memfd:...` | Fileless execution — binary only ever existed in an anonymous memory fd | Recover as above; memfd + no file on disk is high-confidence malware; carve/enrich (Section 13) |
| `exe` → `(deleted)` but path was a package binary (e.g. `/usr/bin/…`) | Legitimate if the package was upgraded/removed while the daemon kept running | Cross-check: was there an `apt`/`dnf` upgrade? `journalctl -u <svc>`; if upgrade window matches = FP |
| Deleted binary + external connection (Section 10) | Running fileless implant actively beaconing | Escalate; capture connection, then eradicate |
| Recovered binary hash is a known-good package file | Upgrade artifact, not malware | Close as FP; note the upgrade correlation |

**Note:** `(deleted)` alone is not malicious — long-running daemons across a package upgrade show it routinely. The *path* (temp/writable dir vs package dir) and corroboration (network, YARA, persistence) decide it.

---

## 3 — Hidden Process (memory ↔ /proc cross-view)

Toolkit signal: `Hidden Process (memory)` / `Hidden Process`. The memory engine cross-checks the kernel task list against what `/proc` and `ps` show; a task present in kernel structures but absent from `/proc` is hidden by a rootkit.

```bash
# Live cross-view: kernel task list vs userland ps (run on the live host)
# /proc PIDs:
ls -d /proc/[0-9]* | sed 's#/proc/##' | sort -n > /tmp/proc_pids
# ps view:
ps -eL -o pid= | tr -d ' ' | sort -nu > /tmp/ps_pids
comm -3 /tmp/proc_pids /tmp/ps_pids     # any asymmetry is worth a look

# Compare against a kernel-authoritative source (thread count in scheduler):
sudo cat /proc/sched_debug 2>/dev/null | grep -cE '^\s' # gross sanity only
# Authoritative answer comes from the memory image (psscan vs pslist), Section 13
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| PID in memory `psscan` but not in `pslist`/`/proc` | Task unlinked from the process list — kernel rootkit hiding a process | True Positive; Section 5 to find the hiding module; carve the task (Section 13) |
| `/proc` and `ps` agree, memory image agrees | No hiding | Close |
| `ps` shows fewer PIDs than `/proc` | `ps`/`procps` binary may be trojaned to filter output | Compare with a known-good statically-linked `ps`, or read `/proc` directly; treat trojaned `ps` as TP |
| Hidden PID's `exe`/`comm` blanked | Rootkit both hides and scrubs identity | Recover backing pages from the image; Section 13 enrichment |
| Discrepancy is a race (short-lived process) | Timing artifact between the two listings | Re-run; if it does not reproduce and memory image agrees, close as FP |

---

## 4 — Injected / Anonymous-Executable Memory (malfind)

Toolkit signals: `Injected Memory (malfind)`, `Implant-Backed Mapping (memory)`, `Reverse Shell (memory)`, `Anomalous Call Stack (memory)`.

```bash
# Live approximation: anonymous executable mappings (rwx or x with no file backing)
pid=1234
sudo awk '$2 ~ /x/ && $6=="" {print}' /proc/$pid/maps      # exec regions with no pathname
# Reverse-shell smell: shell with stdio wired to a socket
sudo ls -l /proc/$pid/fd | grep -E 'socket:' && \
  echo "shell fds -> socket? check comm=$(tr -d '\0' <sudo cat /proc/$pid/comm)"
# Dump one anonymous exec region for inspection (start-end from maps):
sudo dd if=/proc/$pid/mem bs=1 skip=$((0xSTART)) count=$((0xEND-0xSTART)) of=/tmp/region.bin 2>/dev/null
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Anonymous `rwx` or `r-x` region, no pathname, in a normal process | Classic code injection / shellcode staged in the process | Dump the region; YARA/enrich (Section 12/13); True Positive if capa shows socket/inject caps |
| `bash`/`sh`/`python` with stdin+stdout+stderr all pointing to the same `socket:` inode | Interactive reverse shell | Trace the socket to its remote peer (Section 10); escalate |
| Anon exec region in a JIT runtime (`node`, `java`, `mono`, browsers, `python` w/ JIT) | Legitimate JIT-compiled code | FP if the owning process is a known JIT runtime and no YARA/family hit in the region |
| malfind hit in a file-backed `r-x` page | Rule grazed a loaded library (not injection) | Verify the library's package hash; downgrade if it matches on-disk |
| Anon exec region + deleted binary + external conn | Full implant footprint | Escalate; run enrichment (Section 13) to pull C2/config before eradicating |

---

## 5 — Kernel Rootkit Signals (memory-only)

These fire **only** from the memory engine — a live host cannot reliably see them because the rootkit is what answers the queries. Signals: `Hidden Kernel Module (memory/carved)`, `Netfilter Hook (memory)`, `IDT Hook (memory)`, `Kernel .text Inline Hook (memory)`, `VFS fops Hook (memory)`, `Kernel Timer Hook (memory)`, `Kernel Thread Hook (memory)`, `modprobe_path/uevent_helper/core_pattern Hijack (memory)`, `Kernel-Thread Name Masquerade (memory)`.

```bash
# Live corroboration only (the image is authoritative). On the live host:
sudo cat /proc/modules | sort > /tmp/mod_proc          # what the kernel admits to
ls /sys/module | sort > /tmp/mod_sys                    # sysfs view
comm -3 /tmp/mod_proc <(sed 's/ .*//' /tmp/mod_sys|sort)  # asymmetry = hidden module hint

# Usermodehelper hijack targets — read the actual values (edr_hunt does this too)
for k in /proc/sys/kernel/modprobe /proc/sys/kernel/core_pattern \
         /sys/kernel/uevent_helper; do
  printf "%s = %s\n" "$k" "$(sudo cat $k 2>/dev/null)"
done
# Kernel taint (unaccounted module leaves a taint bit):
cat /proc/sys/kernel/tainted    # decode with kernel docs; non-zero warrants the image
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `Hidden Kernel Module (memory)` — module in kernel structures, absent from `/proc/modules` | LKM rootkit hiding itself (Diamorphine-class) | True Positive; carve the module (`Hidden Kernel Module (carved)`); identify by strings/symbols; Section 15 |
| `modprobe_path`/`uevent_helper` points to a writable/non-standard path | Root-code-execution primitive armed (kernel runs it as root on an event) | True Positive; capture the target path + its contents; this is a persistence + privesc mechanism |
| `core_pattern` starts with `|` piping to a non-standard handler | Crash-triggered root code execution | Verify handler is not systemd-coredump/apport/ABRT; if unknown → TP |
| `.text Inline Hook` / `IDT Hook` / `Netfilter Hook` with handler resolving to **no module** | Kernel function pointer redirected to unbacked/injected code | True Positive; the hooked function tells you the capability (netfilter = C2 traffic filter, fops = file hiding) |
| `VFS fops Hook (memory)` on `proc_root_operations.iterate_shared` | `/proc` readdir hooked = PID hiding | Correlate with Section 3 (hidden process); TP |
| `Kernel Timer Hook (memory)` — mapped callback, no module | Periodic code running with no owning process | TP; carve the callback region |
| `Kernel Tainted By Unaccounted Module (verify)` (live) | Taint bit set with no matching loaded module — hint, not proof | Pull a memory image and run the engine; do not clear on the live host alone |
| `[bpf]`/`[ftrace]` pseudo-module surfaced at `Info` | Legit kernel subsystem tag *or* a masquerade | Verify against expected eBPF/ftrace usage (Section 7); downgraded, not suppressed, on purpose |

**Why memory, not live:** a rootkit that hooks `iterate_shared`, hides its LKM, and filters `/proc/modules` is invisible to `lsmod`, `ps`, and `cat /proc/modules` — those all traverse the structures it controls. The RAM image is read out-of-band, so the hooks and unlinked modules are visible. Always escalate a memory rootkit signal to image analysis rather than trusting live tools.

---

## 6 — Credential Override / Privilege-Escalation Residue

Toolkit signal: `Credential Override (memory)` — a task whose `cred != real_cred` (credentials overwritten after fork), the residue of a kernel privesc such as a magic-signal "become root" (Diamorphine `kill -64`).

```bash
# Live corroboration: processes running as uid 0 whose parent chain is a user shell
ps -eo pid,ppid,euid,ruid,comm,args | awk '$3==0 && $4!=0'   # euid=0, ruid!=0 mismatch
# Unexpected uid-0 accounts (edr_hunt: "Unauthorized UID0 Account")
awk -F: '$3==0 {print $1}' /etc/passwd        # anything beyond root is suspect
# Empty-password accounts (edr_hunt: "Empty Password Account")
sudo awk -F: '($2=="" ){print $1" has EMPTY password"}' /etc/shadow
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `Credential Override (memory)`: cred≠real_cred, euid=0 on a non-root task | A process was given root credentials after fork by kernel code — magic-signal rootkit privesc | True Positive; correlate with Section 5 (the LKM that granted it); the parent shell is the operator |
| euid=0 / ruid≠0 on a legitimate setuid binary (`sudo`, `passwd`, `su`, `pkexec`) | Normal setuid transition | FP; confirm `exe` is the real signed setuid binary at its package path |
| Second uid-0 line in `/etc/passwd` | Backdoor superuser account | TP; capture the account; Section 15 remove; audit `last`/auth logs for its use |
| Empty-password account | Auth bypass | TP; lock the account; check for use in auth logs |
| euid=0/ruid≠0 with `exe` in `/tmp` or `(deleted)` | Privesc payload, not a real setuid tool | TP; Section 2 + Section 15 |

---

## 7 — eBPF / io_uring Anti-EDR Surface

Toolkit signals: `eBPF Network C2 Correlated (memory)`, `eBPF Object Held By Implant`, `Pinned eBPF Objects (verify)`, `io_uring Anti-EDR I/O (memory)`, `io_uring In Use (memory/verify)`.

```bash
# Loaded eBPF programs and maps (needs root; bpftool from linux-tools)
sudo bpftool prog show 2>/dev/null      # type, name, loaded-by pid, tag
sudo bpftool map show  2>/dev/null
sudo ls -l /sys/fs/bpf 2>/dev/null      # pinned objects

# Processes holding bpf/io_uring fds
for p in /proc/[0-9]*; do
  if sudo ls -l "$p/fd" 2>/dev/null | grep -qE 'anon_inode:(bpf-|\[io_uring\])'; then
    echo "$p ($(tr -d '\0' <$p/comm)) holds bpf/io_uring fd"
  fi
done
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `eBPF Network C2 Correlated` — a network-hook eBPF prog co-occurring with a hooked netfilter hook | bpfdoor-class magic-packet C2 / traffic-signalling backdoor | True Positive; identify the prog (`bpftool prog dump`), the pinning process, and the socket filter |
| eBPF prog `type=kprobe/tracepoint` loaded by a non-observability process | Possible syscall-hiding / EDR-blinding eBPF | Check the loader's legitimacy; observability agents (falco, cilium, datadog) are expected → FP |
| BPF-LSM program present | Can neuter access control / hide activity at the policy layer | High-severity; confirm it is an expected security agent, else TP |
| `io_uring Anti-EDR I/O` — ring held by a process from a writable dir / deleted binary | I/O performed via io_uring to dodge syscall-based EDR | True Positive; correlate with Section 2/4; capture the process |
| `io_uring In Use (verify)` on a normal service (nginx, postgres, systemd) | Legitimate performance use of io_uring | FP after confirming the owning binary is the real service (downgraded to Info by design, not suppressed) |
| Pinned bpffs object with no owning agent | Orphaned or hidden persistence via pinned prog | Inspect the pinned prog; TP if it hooks network/syscalls and no agent claims it |

---

## 8 — Namespace Escape / Container Breakout

Toolkit signals: `Namespace Escape (memory)`, `Bind Mount Over System Path (memory)`. A task containerized in some namespaces but sharing the **host** namespace in others is a breakout/host-reach indicator.

```bash
# Per-process namespace inode ids — compare a suspect against PID 1 (host ns)
pid=1234
for ns in mnt pid net user ipc uts cgroup; do
  printf "%-7s pid=%s host=%s\n" "$ns" \
    "$(sudo readlink /proc/$pid/ns/$ns 2>/dev/null)" \
    "$(sudo readlink /proc/1/ns/$ns 2>/dev/null)"
done
# Bind mounts hiding a system path
sudo cat /proc/$pid/mountinfo | awk '$5 ~ /^\/(etc|bin|sbin|usr|boot)/'
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Task has its own `mnt` ns but shares the **host** `pid` or `net` ns | Container with host reach — breakout or a privileged/`--pid=host` container | TP unless it is a known monitoring sidecar that intentionally shares host ns |
| All namespaces match PID 1 | Host process (not containerized) | Not an escape; evaluate on its own merits |
| All namespaces distinct from host | Fully contained | FP for escape; still evaluate the workload |
| `Bind Mount Over System Path` — a mount shadows `/etc`, `/bin`, `/usr` | Path shadowing to hide files or hijack binaries | Inspect the source; TP if it masks a system dir with attacker content |
| Container process with `user` ns = host + `CAP_SYS_ADMIN` | Effectively root on host | Escalate; Section 6 (capabilities) |

---

## 9 — Persistence Quick-Sweep

Toolkit signals: `Cron Persistence`, `Systemd Persistence`, `udev Rule Persistence`, `rc.local Persistence`, `Autostart Persistence`, `Shell Init Backdoor`, `Recently Modified PAM Module (verify)`, `SSH Forced-Command Backdoor`, `Scheduled at-job Present`.

```bash
# Cron across all sources
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$f" ] && echo "=== $f ===" && sudo cat "$f"
done
ls -la /etc/cron.{hourly,daily,weekly,monthly}/ 2>/dev/null

# systemd units + timers, newest first (catches freshly-dropped persistence)
systemctl list-unit-files --type=service --state=enabled
sudo find /etc/systemd /run/systemd /usr/lib/systemd -name '*.service' -o -name '*.timer' \
  | xargs ls -lt 2>/dev/null | head -20
systemctl list-timers --all

# Shell init files (backdoors in login scripts)
for f in /etc/profile /etc/bash.bashrc /root/.bashrc /root/.profile \
         /home/*/.bashrc /home/*/.profile /home/*/.bash_profile; do
  [ -f "$f" ] && grep -lEi 'curl|wget|/dev/tcp|base64|nc |ncat|python -c|bash -i' "$f"
done

# udev / rc.local / PAM
sudo grep -rEl 'RUN\+=|PROGRAM==' /etc/udev/rules.d/ 2>/dev/null
[ -f /etc/rc.local ] && sudo cat /etc/rc.local
ls -lt /etc/pam.d/ /lib/security/ /lib*/security/ 2>/dev/null | head
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Cron/systemd/udev entry invoking a shell one-liner with `curl`/`wget`/`/dev/tcp`/`base64` | Download-and-execute or reverse-shell persistence | TP; extract the command + target; Section 15 remove; block the URL/IP (Section 10) |
| systemd unit with `ExecStart` in `/tmp`, `/dev/shm`, `/var/tmp`, `$HOME` | No legitimate service runs from a temp dir | TP; capture the unit + binary |
| PAM module in `/lib/security` modified recently, not by a package | PAM backdoor (credential capture / auth bypass) | TP; diff against the package's file; `dpkg -V`/`rpm -V` the owning package |
| `authorized_keys` with a `command=` forced command | SSH backdoor that runs on connect | Inspect the command; TP if it spawns a shell/tunnel |
| Enabled unit / cron entry is a known package (vendor path, signed) | Legitimate persistence | FP; confirm the file belongs to a package (`dpkg -S`/`rpm -qf`) |
| `at` job queued | One-shot scheduled execution | Inspect `at -c <job>`; TP if it drops/executes payload |
| Recently modified init file but content is a benign PATH/alias edit | Admin change | FP after reading the diff |

**Verify ownership fast:** `dpkg -S <file>` (Debian/Ubuntu) or `rpm -qf <file>` (RHEL/SUSE) tells you if a file belongs to a package; `dpkg -V <pkg>` / `rpm -V <pkg>` shows if a package file was modified after install. A persistence file owned by no package, in a writable dir, invoking a network one-liner is the high-confidence pattern.

---

## 10 — Network Connection Triage

Toolkit signals: `External Connection (memory)`, `External Connection From Untrusted Binary`, `Network Listener From Untrusted Binary`.

```bash
# All sockets with owning process (root shows all PIDs)
sudo ss -tanp                        # TCP incl. state + pid/exe
sudo ss -uanp                        # UDP
sudo ss -tlnp                        # listeners only

# For a flagged PID: its sockets and the remote peers
pid=1234
sudo ss -tanp | grep "pid=$pid,"
# Resolve a remote IP offline (no lookup that tips off the attacker) — check against IOCs first
grep -F "203.0.113.10" reports/<host>/*Findings*.json

# What binary owns a listener on a port
sudo ss -tlnp 'sport = :4444'
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Flagged PID has zero connections now | Beacon may be sleeping / one-shot — does **not** clear the finding | Check its socket fds (`ls -l /proc/$pid/fd`), DNS/`/etc/hosts`, and re-observe; do not close on "no conn" alone |
| Established connection to a non-service port (not 80/443/22) from an untrusted binary | Likely C2 or exfil | Capture IP:port; check against threat intel; Section 15 block-C2 |
| Connection to 443 but the owning binary is in `/tmp` or deleted | C2 over TLS from an implant | Escalate; correlate with Section 2/4 |
| Listener on an unexpected high port owned by an untrusted binary | Backdoor / bind shell | Identify the binary; confirm not a legitimate app; TP |
| Connection owned by a normal package daemon to a vendor endpoint | Update/telemetry traffic | FP after confirming the binary is the real package daemon and the endpoint is the vendor |
| Listener owned by `sshd`/`systemd-resolved`/container runtime | Expected service | FP; confirm the owning binary path |

---

## 11 — SSH Key & Account Hygiene

Toolkit signals: `Many SSH Authorized Keys`, `SSH Key Reused Across Accounts`, `authorized_keys is a Symlink`, `SSH Key File World/Group-Writable`, `SSH Key File Owner Mismatch`, `root authorized_keys Recently Modified`.

```bash
# Enumerate every authorized_keys and its perms/owner
sudo find / -name authorized_keys 2>/dev/null -exec ls -l {} \;
# Dump keys with fingerprints (spot foreign/duplicate keys)
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -f "$f" ] && echo "=== $f ===" && sudo ssh-keygen -lf "$f" 2>/dev/null
done
# Recently modified key files (fresh backdoor keys)
sudo find / -name authorized_keys -mtime -7 2>/dev/null -exec ls -l {} \;
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| `authorized_keys` is a **symlink** | Redirect to attacker-controlled file, or a trick to survive rewrites | TP; read the link target; remove |
| A key appears in multiple accounts' `authorized_keys` | Operator planted one key for broad access | Identify the key comment/fingerprint; remove from all accounts; Section 15 revoke-credentials |
| `root/.ssh/authorized_keys` modified inside the compromise window | Backdoor key added for root | TP; capture the key; correlate with auth log for its first use |
| World/group-writable key file | Any local user can add a key = privesc/persistence | Fix perms; check whether a key was already added |
| Key count normal, owners correct, mtimes old | Baseline | FP |

---

## 12 — Direct YARA / File Scan (Follow-On)

When investigation points to a specific file not caught by the automated hunt (recovered binary, artifact from a share, carved region), scan it directly without re-running collection.

```bash
# Scan a recovered file/directory with the staged YARA binary against the staged rules
# (tools/yara + tools/yara_rules are staged by Build-OfflineToolkit-Linux.sh)
tools/yara -r -w tools/yara_rules/ /tmp/recovered_1234.bin
tools/yara -r -w tools/yara_rules/ /var/tmp/staging/           # -r recurses a directory
# (linux_yara.py itself is the image-scan engine, driven via Analyze-Memory-Linux.sh --yara)

# Quick manual triage of a recovered binary
file /tmp/recovered_1234.bin
sha256sum /tmp/recovered_1234.bin           # -> offline reputation / VT if permitted
strings -n 8 /tmp/recovered_1234.bin | grep -Ei 'http|/tmp/|/dev/tcp|nc |bash -i|LD_PRELOAD'
```

**Logic breakdown:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| YARA hit with a named family rule | Known malware family | TP; use the family to guide eradication + IOC extraction (Section 13) |
| Generic rule (packer/LOLBin) hit only | Suspicious but not conclusive | Corroborate with strings/behaviour; do not escalate on a generic rule alone |
| No YARA hit but high-entropy + network strings | Packed/custom implant | Run enrichment (Section 13); capa/FLOSS may reveal capability |
| Hash matches a known-good package file | Legitimate binary | FP |
| Hash known-bad in threat intel | Confirmed malware | Escalate; sweep the fleet for the same hash |

---

## 13 — Memory Capture, Symbols & Deep Analysis

> **Canonical reference:** `WORKFLOW-LINUX.md` is the authoritative memory pipeline. This section is the pivot summary.

```bash
# 1. Capture RAM on the live host (AVML) — the collector wraps this
sudo ./Invoke-IRCollection-Linux.sh --capture-memory --output-root reports/ --incident-id <id>
#    (image lands in reports/<host>/; use --memory-output /path/on/big/disk if space is tight,
#     --compress for a smaller snappy image)

# 2. Build a Volatility symbol table (ISF) matching the target kernel
#    (needs the target's kernel debug symbols / BTF; Build-LinuxSymbols wraps dwarf2json)
playbooks/linux/threat_hunting/Build-LinuxSymbols.sh --kernel "$(uname -r)" --out ~/ir-symbols/
#    cross-host image: pass --build-id <id> --fetch-symbols to pull matching debug symbols

# 3. Run the memory engine (custom linux_ir.* plugins + stock + optional YARA), then adjudicate
playbooks/linux/threat_hunting/Analyze-Memory-Linux.sh \
  --image reports/<host>/memory_<host>.raw \
  --symbols ~/ir-symbols \
  --host-folder reports/<host>/ \
  --yara --carve --adjudicate

# Targeted single-plugin question (e.g. confirm a hidden module or a specific PID)
vol -q -r json -f reports/<host>/memory_<host>.raw -p playbooks/linux/threat_hunting/vol_plugins \
  -s ~/ir-symbols linux.pslist.PsList
```

**Resource note (stability > speed):** the engine runs plugins **sequentially** (one `vol` at a time) under `nice -n 10 ionice -c3` so it does not tax the host — memory analysis is not latency-sensitive. Override with `IR_MEM_NO_NICE=1` / `IR_MEM_NICE=<n>` if needed. A full run is bounded, not fastest.

**Logic breakdown — which plugin answers which question:**

| Signal to confirm | Plugin / analyzer | Clean-host expectation |
|-------------------|-------------------|------------------------|
| Hidden process | `linux.psscan` vs `linux.pslist` | Identical PID sets |
| Injected code | `linux.malfind` | No anon-exec in normal processes |
| Hidden LKM | `linux.hidden_modules` + carve | Every module accounted for |
| Syscall/IDT/netfilter hooks | `linux.malware.check_syscall` / `check_idt` / `netfilter` | Handlers resolve to a module |
| `.text` inline hooks | `linux_ir.text_hooks` | 0 trampolined prologues |
| `/proc` VFS hooks | `linux_ir.fops_hooks` | Handlers → `__kernel__` |
| Unbacked timers | `linux_ir.kernel_timers` | Callbacks → real modules |
| Credential override | `linux_ir.task_creds` | `cred == real_cred` for all |
| Namespace escape | `linux_ir.namespaces` | Contained tasks share no host ns |
| io_uring anti-EDR | `linux_ir.io_uring` | Rings only in expected services |
| Usermodehelper hijack | `linux_ir.kernel_globals` | `modprobe_path=/sbin/modprobe`, etc. |

**Enrichment (eradication scope):** after a TP is confirmed, `memory_enrich.py` recovers the implant footprint (C2 IPs/domains, dropped-file paths, decoded strings, capa capabilities) and populates `IOCs.json`. **Review `IOCs.json` before eradication** — the enricher promotes recovered endpoints without threat scoring, so benign vendor/telemetry endpoints from FP processes must be pruned before Section 15 runs firewall blocks.

---

## 14 — Staged Tools Quick Reference

```bash
# Live hunt (no image) — the primary triage engine
python3 playbooks/linux/threat_hunting/edr_hunt.py --report-dir reports/<host>/

# Container-aware hunt (namespaces, escapes, mounts)
python3 playbooks/linux/threat_hunting/container_hunt.py --report-dir reports/<host>/

# Journal / log analysis (tamper + persistence in logs); --live reads the running journal
python3 playbooks/linux/threat_hunting/journal_analysis.py --report-dir reports/<host>/ --live

# Remote-access triage (SSH, tunnels, RMM tools)
python3 playbooks/linux/threat_hunting/remote_access_triage.py --report-dir reports/<host>/

# Adjudicate: enrich the Combined_Findings JSON with on-host context + verdict ladder
python3 playbooks/linux/threat_hunting/adjudicate.py \
  --host-folder reports/<host>/ --report reports/<host>/Combined_Findings_<stamp>.json
```

---

## 15 — Eradication Pivot

Numbered, analyst-gated playbooks. They are **env-var driven and default to `IR_DRY_RUN=1`** — they print planned actions and change nothing until you set `IR_DRY_RUN=0`. Review the dry-run output first. Common vars: `IR_INCIDENT_ID`, `IR_MGMT_IPS` (mgmt CIDRs kept open during isolation), `IR_MALICIOUS_PROCESSES` (comma-separated PIDs to kill). Every mutating action is journaled for rollback.

```bash
# 0. Preserve volatile evidence BEFORE any change
sudo IR_INCIDENT_ID=<id> ./playbooks/linux/00_collect_forensics.sh

# 1. Contain: isolate host egress, freeze lateral movement (keep your mgmt IP reachable!)
sudo IR_INCIDENT_ID=<id> IR_MGMT_IPS=10.0.0.0/24 ./playbooks/linux/01_contain_host.sh

# 2. Eradicate process: kill confirmed malicious PIDs, quarantine binaries
sudo IR_DRY_RUN=0 IR_INCIDENT_ID=<id> IR_MALICIOUS_PROCESSES=1234,5678 \
  ./playbooks/linux/02_eradicate_process.sh

# 3. Eradicate persistence: remove cron/systemd/udev/rc.local/shell-init/authorized_keys entries
sudo IR_DRY_RUN=0 IR_INCIDENT_ID=<id> ./playbooks/linux/03_eradicate_persistence.sh

# 4. Block C2: firewall + DNS sinkhole recovered IPs/domains from IOCs.json
sudo IR_DRY_RUN=0 IR_INCIDENT_ID=<id> ./playbooks/linux/04_block_c2.sh

# 5. Acquire artifact: image disk/memory for evidence retention
sudo IR_INCIDENT_ID=<id> ./playbooks/linux/05_acquire_artifact.sh

# 6. Restore: reverse containment once clean (uses the rollback journal)
sudo IR_DRY_RUN=0 IR_INCIDENT_ID=<id> ./playbooks/linux/06_restore.sh

# 7. Revoke credentials: rotate SSH keys, expire sessions, lock backdoor accounts
sudo IR_DRY_RUN=0 IR_INCIDENT_ID=<id> ./playbooks/linux/07_revoke_credentials.sh

# Continuous: watch egress during/after remediation
sudo IR_INCIDENT_ID=<id> ./playbooks/linux/monitor_egress.sh
```

**Logic breakdown — eradication:**

| Result | What it means | Where to go next |
|--------|--------------|-----------------|
| Dry-run output lists the expected PIDs/files | Plan is correct | Re-run with `IR_DRY_RUN=0` |
| `02_eradicate_process`: PID already gone | Process exited or a prior kill worked; persistence may still relaunch it | Proceed to `03_eradicate_persistence` regardless |
| Killed PID reappears | Persistence survived the sweep | Re-run Section 9; check kernel-level persistence (Section 5) — an LKM rootkit relaunching a process is not fixed by userland removal |
| `04_block_c2`: 0 IPs blocked | `IOCs.json` has no C2 yet | Run enrichment (Section 13) first, then re-run |
| Kernel rootkit confirmed (Section 5) | Userland eradication cannot be trusted | Plan for **re-image**; a kernel-mode rootkit can defeat every live tool |
| `06_restore` journal mismatch | State changed since containment (reboot / external change) | Review manually before restoring; do not force |

**Prerequisites before eradication:**
- Volatile evidence preserved (`00_collect_forensics.sh` run).
- Memory image captured if any kernel/injection signal fired (Section 13).
- `IOCs.json` reviewed — benign endpoints pruned.
- Every finding closed as FP or escalated to TP.
- Snapshot/backup taken.

---

## Quick Reference: Common FP Patterns

| Signal | Common FP explanation | Confirm or clear |
|--------|----------------------|-----------------|
| `Process Running Deleted Binary` on a system daemon | Package was upgraded/removed while the daemon kept running | FP if `exe` path is a package dir and an upgrade window matches (`journalctl`) |
| `io_uring In Use (verify)` on nginx/postgres/systemd | Legitimate high-performance I/O | FP after confirming the owning binary is the real service (downgraded to Info by design) |
| `Injected Memory (malfind)` in node/java/mono/browser | JIT-compiled code in anon-exec pages | FP if owning process is a known JIT runtime and no family YARA in the region |
| `[bpf]`/`[ftrace]` pseudo-module at Info | Legit kernel subsystem kallsyms tag | Verify against expected eBPF/ftrace agents; surfaced (not suppressed) so a masquerade isn't missed |
| eBPF kprobe/tracepoint prog from falco/cilium/datadog/bpftrace | Observability/security agent | FP after confirming the loader is the known agent |
| `External Connection` from a package daemon to a vendor endpoint | Update/telemetry | FP after confirming binary path + endpoint owner |
| `Credential Override`-looking euid=0/ruid≠0 on `sudo`/`su`/`pkexec` | Normal setuid transition | FP if `exe` is the real signed setuid binary |
| `Many SSH Authorized Keys` on a bastion/CI host | Legitimately many operator keys | FP after fingerprinting each key against the roster |
| `Deleted Running Binary` where recovered hash = package file | Upgrade artifact | FP |
| `Namespace` differences on a monitoring sidecar sharing host ns | Intentional host-ns sharing for observability | FP after confirming the container's purpose |
| Kernel `taint` bit set with proprietary GPU/driver module loaded | Out-of-tree vendor module (NVIDIA, etc.) | FP after matching the taint to a known loaded module; unaccounted taint → image analysis |