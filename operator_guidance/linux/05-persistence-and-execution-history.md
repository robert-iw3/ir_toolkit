# 05 · Persistence & Execution History (Linux)

*Two questions: **how does it survive a reboot**, and **what has run here before?** Linux has its
own rich set of autostart locations and log/history artifacts.*

Same intent as [../windows/05-persistence-and-execution-history.md](../windows/05-persistence-and-execution-history.md).
Below is where Linux persistence hides and how to read the journal.

---

## Part A — Persistence: every place a program can auto-start

Sweep these; the attacker's entry almost always lives in `/tmp`, `/var/tmp`, `/dev/shm`, a home
dir, or a world-writable path, and is owned by a non-package binary.

```bash
# systemd units + timers (the modern favorite) — look for ExecStart in odd paths
systemctl list-unit-files --type=service --state=enabled
systemctl list-timers --all
for u in /etc/systemd/system/*.service /run/systemd/system/*.service ~/.config/systemd/user/*.service; do
    grep -H -E 'ExecStart|ExecStartPre' "$u" 2>/dev/null
done | grep -E '/tmp|/var/tmp|/dev/shm|/home|curl|wget|bash -i|nc '

# cron — system, per-user, and the drop-in dirs
cat /etc/crontab; ls -la /etc/cron.*/ /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null
for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/$u: /"; done
atq 2>/dev/null                                     # at-jobs

# Shell init + profile persistence
ls -la /etc/profile.d/; grep -Rn -E 'curl|wget|/dev/tcp|base64 -d' ~/.bashrc ~/.bash_profile /etc/bash.bashrc 2>/dev/null

# Loader / library hijacks — high-signal
cat /etc/ld.so.preload 2>/dev/null                  # ANY content here is suspicious
env | grep -i LD_PRELOAD

# SSH backdoors — the durable-access favorite
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do echo "== $f =="; cat "$f" 2>/dev/null; done
grep -RiE 'AuthorizedKeysFile|PermitRootLogin|ForceCommand' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>/dev/null

# Kernel modules — a malicious/out-of-tree module = rootkit
lsmod | tee evidence/lsmod.txt
# Compare loaded modules against those the kernel considers in-tree/signed (see step 06)

# Other autostarts: rc.local, udev RUN+=, XDG autostart
cat /etc/rc.local 2>/dev/null
grep -RnE 'RUN\+?=' /etc/udev/rules.d/ /lib/udev/rules.d/ 2>/dev/null
ls -la /etc/xdg/autostart/ ~/.config/autostart/ 2>/dev/null
```

**Read it for:** an `ExecStart`/cron/init line pointing into a temp or home dir, a download cradle
(`curl … | bash`), a reverse-shell one-liner, **any** `ld.so.preload` content, an `authorized_keys`
you can't attribute (especially one that's world-writable, has a `command=` forced-command, or
reuses a key across accounts), or a kernel module not owned by the distro.

## Part B — Execution history & credential-access artifacts

```bash
# Shell histories — attackers often forget to clear these (or set HISTFILE=/dev/null, itself a tell)
for f in /root/.bash_history /home/*/.bash_history; do echo "== $f =="; tail -n 50 "$f" 2>/dev/null; done

# Package-manager transactions — confirm/refute "the binary is gone because of an upgrade"
grep -E 'install|remove|upgrade' /var/log/dpkg.log 2>/dev/null | tail -50
tail -50 /var/log/apt/history.log 2>/dev/null; tail -50 /var/log/pacman.log 2>/dev/null
rpm -qa --last 2>/dev/null | head -30

# Credential-access tells
ls -l /etc/shadow                                                # world-readable shadow = credential theft prep
ls -lat /home/*/ 2>/dev/null | grep -iE 'dump|cred|\.gz|\.tar'   # staged loot
ls -la /var/crash /var/lib/systemd/coredump 2>/dev/null          # core dumps (may hold secrets)
```

## Part C — The journal / auth logs (the timeline's backbone)

Export now — an attacker can vacuum the journal.

```bash
# Structured export for offline analysis (bounded)
journalctl -o json --since "-7 days" > evidence/journal.json
# Classic text logs where present
cp -a /var/log/auth.log* /var/log/secure* /var/log/audit/ evidence/ 2>/dev/null
```

The events that tell the story (grep the journal or auth logs):

| Signal | What to grep for | Means |
|---|---|---|
| SSH brute force | `Failed password` bursts from one IP | T1110 — escalates if a `Accepted` root logon follows |
| Remote root logon | `Accepted … for root` | T1078.003 / T1021.004 |
| Sudo abuse | `sudo: … COMMAND`, `NOT in sudoers`, auth failures | T1548.003 |
| New account | `useradd`/`groupadd`, `new user` | T1136.001 |
| Service/cron persistence | unit or cron exec from implant dir | T1543.002 / T1053.003 |
| Reverse shell | `bash -i`, `/dev/tcp`, `nc -e`, `socat` | T1059.004 |
| Log/MAC tamper | `journal … vacuum`, `auditd` stopped, `setenforce 0`, AppArmor disabled | T1070 / T1562.001 |
| Unsigned kmod | `module verification failed`, out-of-tree load | T1547.006 / T1014 |

```bash
# Example: brute force then success, and log tampering, in one pass
grep -E 'Failed password|Accepted .* for root|sudo:|useradd|setenforce|auditd' evidence/auth.log* 2>/dev/null
journalctl --since "-7 days" | grep -iE 'vacuum|module verification failed|apparmor="STATUS"'
```

> Empty results often mean "not logged here," not "didn't happen" — note the visibility gap
> (especially if auditd isn't installed).

---

➡️ Next: [06-hunt-the-host.md](06-hunt-the-host.md)

*Toolkit parallel: `00_collect_forensics.sh` (persistence + histories + journal export),
`journal_analysis.py` (the journal-to-findings table above). Package-transaction context feeds the
investigation module's "deleted binary" theory-check.*
