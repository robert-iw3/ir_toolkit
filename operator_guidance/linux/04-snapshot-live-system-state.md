# 04 · Snapshot Live System State (Linux)

*Photograph what's alive — processes, sockets, sessions — read-only, saved off-host, before any
of it changes. On Linux, `/proc` gives you ground truth the tools sometimes don't.*

The reasoning mirrors [../windows/04-snapshot-live-system-state.md](../windows/04-snapshot-live-system-state.md).
Here are the Linux commands. Redirect every one to a file under `evidence/`.

---

## Processes — the three facts that matter

For anything interesting: **real executable path, full cmdline, and parent** — from `/proc`, not
just `ps` (which a rootkit can be tricked around).

```bash
ps auxfww | tee evidence/ps_tree.txt                 # full tree with args
# Per suspect: the ground truth from /proc
ls -l /proc/<PID>/exe                                # real binary (watch for '(deleted)', /tmp, memfd:)
tr '\0' ' ' < /proc/<PID>/cmdline; echo
tr '\0' '\n' < /proc/<PID>/environ 2>/dev/null       # LD_PRELOAD / LD_LIBRARY_PATH here = injection
ls -l /proc/<PID>/cwd                                # working dir (implant staging dir?)
cat /proc/<PID>/status | grep -E 'Uid|Gid|PPid|TracerPid'   # TracerPid≠0 = being ptraced
```

**Read it for:** exe pointing at `(deleted)`/`/tmp`/`/dev/shm`/`memfd:`; a shell or interpreter
whose parent is a network daemon (`sshd`,`nginx`,`apache2`,`mysqld`) = RCE/reverse shell; a
`comm` name in brackets (fake kernel thread `[kworker/...]`) that actually has a real exe path =
masquerade; `TracerPid` set on a process nothing should be debugging = injection.

## Network — sockets mapped to processes

```bash
ss -tupanp | tee evidence/sockets.txt                # all TCP/UDP with owning PID/program
# Established outbound to public IPs — the C2-hunting view
ss -tupanp state established | grep -vE '127\.0\.0\.1|::1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.'
ip -o addr; ip route; cat /etc/resolv.conf           # host network context
```

**Read it for:** ESTABLISHED to a public IP on an odd port, especially owned by a process whose
exe is deleted/in `/tmp` (that's C2 **regardless of port** — beats 443-beacon evasion); an
unexpected LISTEN socket (backdoor).

## Sessions & accounts — attackers use valid logins

```bash
who; w                                               # who's on now
last -F -n 50   | tee evidence/last.txt              # successful logins
lastb -F -n 50  2>/dev/null | tee evidence/lastb.txt # FAILED logins (brute force)
# Accounts, and anyone with UID 0 (a second root is a backdoor)
awk -F: '($3==0){print}' /etc/passwd | tee evidence/uid0_accounts.txt
getent group sudo wheel 2>/dev/null
lsof -nP -i 2>/dev/null | tee evidence/lsof_net.txt  # open network files by process (needs root)
```

**Read it for:** a second UID-0 account, an unfamiliar user in `sudo`/`wheel`, a root SSH login
from an odd source, a session from an IP that shouldn't reach this host.

## Open files & deleted-but-held (Linux-specific tell)

```bash
# Files a suspect has open — including binaries deleted from disk but still running
lsof -p <PID> 2>/dev/null
ls -l /proc/<PID>/fd                                 # fd → '(deleted)' means the file was unlinked while open
```

A binary that was **deleted from disk but is still executing** is a classic anti-forensics move —
`/proc/<PID>/exe` and `fd` expose it, and you already recovered it in step 03.

## Hidden-process cross-check (catch a rootkit lying to `ps`)

Ask two ways and compare — a PID in `/proc` that `ps` doesn't list is hidden:

```bash
diff <(ls -1 /proc | grep -E '^[0-9]+$' | sort -n) \
     <(ps -eo pid= | tr -d ' ' | sort -n)
```

Any PID present in `/proc` but missing from `ps` is a strong signal — and a reason you also grabbed
memory (step 08), which sees processes the kernel is hiding.

---

➡️ Next: [05-persistence-and-execution-history.md](05-persistence-and-execution-history.md)

*Toolkit parallel: `00_collect_forensics.sh` + `edr_hunt.py` capture all of this (`/proc`, sockets,
sessions, hidden-proc and deleted-binary checks) read-only, degrading gracefully without root.*
