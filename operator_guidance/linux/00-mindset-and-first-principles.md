# 00 · Mindset & First Principles (Linux)

The universal principles are platform-independent — read
[../windows/00-mindset-and-first-principles.md](../windows/00-mindset-and-first-principles.md)
once; everything there (order of volatility, collect-before-judge, don't-tip-off, the verdict
ladder, chain of custody, rules of engagement) applies verbatim on Linux. This page adds only what
is *different* about Linux.

---

## What's different on Linux

- **`/proc` is your live forensic goldmine.** Almost everything about a running process — its real
  executable, memory map, open files, environment, network sockets — is a file under
  `/proc/<pid>/`. Much of Linux IR is just reading `/proc` carefully.
- **root vs non-root changes what you can see.** As a normal user you can't read `/etc/shadow`,
  other processes' `fd`/`mem`, or the full SUID picture. **Collect as root** where authorized;
  note in your log when a check ran degraded.
- **Fileless is easy and common.** `memfd_create` + `execve` runs a binary that never touches
  disk; a deleted-but-running binary shows as `/proc/<pid>/exe → '...(deleted)'`. Memory and
  `/proc` catch these; a disk scan does not.
- **The logs an attacker disables *are* evidence.** auditd stopped, journald vacuumed, `HISTFILE`
  set to `/dev/null`, SELinux/AppArmor disabled — each is a finding, not just a gap.
- **Containers add a layer.** A "host" may be a container, and the real risk may be a container
  **escape** to the node or a **cluster-admin** RBAC binding. Know whether you're on a bare host,
  a container, or a k8s node before you start.

## Set up your workspace

```bash
CASE="IR-$(date -u +%Y%m%d)-$(hostname)"
mkdir -p "/mnt/evidence/$CASE"/{evidence,notes}     # external/mounted media, NOT the suspect disk
cd "/mnt/evidence/$CASE"

# Clock context — record offset vs UTC and NTP sync state for later timeline work
date -u '+%Y-%m-%dT%H:%M:%SZ' | tee notes/collect_start_utc.txt
timedatectl status | tee evidence/clock.txt

# Hash anything you collect, immediately
sha256sum evidence/memory.lime | tee evidence/memory.lime.sha256
```

Keep a running `notes/log.md`: every command, timestamped in UTC. It becomes your timeline and
custody trail for free.

---

➡️ Next: [01-triage-the-alert.md](01-triage-the-alert.md)

*Toolkit parallel: `clock_context.py` (`_clock.json`) and `evidence_custody.py` (custody seal)
provide the clock + custody structure automatically.*
