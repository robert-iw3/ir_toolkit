# 01 · Triage the Alert (Linux)

*"An alert fired — from a SIEM, an EDR/falco rule, a cloud detector, or a sysadmin noticing a
weird process/connection — and I can't nail it down yet."*

Same goal as always: decide **real or noise, and how urgent** — not to solve it here. The shared
triage logic is in
[../windows/01-triage-the-alert.md](../windows/01-triage-the-alert.md); below is the Linux-native
first look.

---

## Extract the who/what/where/when

Pull the concrete pivot out of the alert: a **PID**, a **process name**, a **file path**, a
**remote IP**, a **user**, or a **container/pod**. Everything grows from that.

## Take a light, read-only first look

```bash
# The process the alert named — real exe path, cmdline, parent, user
ps -p <PID> -o pid,ppid,user,stat,lstart,cmd
ls -l /proc/<PID>/exe            # real binary — watch for '(deleted)' or /tmp, /dev/shm, memfd
cat  /proc/<PID>/cmdline | tr '\0' ' '; echo
tr '\0' '\n' < /proc/<PID>/environ 2>/dev/null   # env (LD_PRELOAD here is a red flag)

# Who is it talking to, right now, mapped to the PID
ss -tupanp | grep -w <PID>

# Walk its ancestry — a shell/interpreter under a network daemon is the reverse-shell shape
ps -o pid,ppid,user,cmd --ppid <PID>; ps -p <PPID> -o pid,ppid,user,cmd

# Where did the binary come from — is it owned by a package?
dpkg -S "$(readlink -f /proc/<PID>/exe)" 2>/dev/null || rpm -qf "$(readlink -f /proc/<PID>/exe)" 2>/dev/null
```

**Read it in seconds:**
- `/proc/<PID>/exe` pointing at `(deleted)`, `/tmp`, `/var/tmp`, `/dev/shm`, or `memfd:` →
  strong signal (legit software runs from `/usr`, `/opt`, package-owned paths).
- **Impossible parentage:** `bash`/`sh`/`python`/`nc` whose ancestor is `nginx`/`apache2`/`sshd`/a
  DB → service RCE or reverse shell.
- **`LD_PRELOAD`** in the environment, or a connection to a **public IP** from a daemon that
  shouldn't dial out → escalate.
- Binary **not owned by any package** and living outside standard paths → suspicious.

> Don't kill it, delete it, or block the IP yet. You're looking, not acting.

## Make the triage call

Same three outcomes as everywhere: **clear FP** (package-owned, expected path/parent, explains the
alert → close), **can't tell** (the common case → open the investigation, go to step 02), or
**obvious active intrusion** (reverse shell, cryptominer, `/dev/shm` implant beaconing → open +
escalate now).

---

➡️ Next: [02-contain-without-destroying-evidence.md](02-contain-without-destroying-evidence.md)

*Toolkit parallel: `Invoke-IRCollection-Linux.sh` assumes the decision to collect is already made;
the human triage above is what decides whether to run it.*
