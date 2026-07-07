# 10 · Eradicate (Linux)

*Evidence secured, story understood. Now remove the threat — completely, reversibly, in an order
that doesn't let it respawn.*

The principles (dry-run first, reanimation-before-body order, rollback journal, re-verify) are in
[../windows/10-eradicate.md](../windows/10-eradicate.md). Here are the Linux mechanics.

---

## The order (or it respawns)

```
1. Cut confirmed C2 egress          5. Kill (or suspend the injected thread)
2. Disable persistence              6. Quarantine the binaries (hash first)
3. Disable accounts / keys          7. Undo tampering (re-enable auditd, remove backdoors)
4. Rotate credentials               8. Re-verify nothing came back
```

## Step 1 — Cut confirmed C2

```bash
# Block each confirmed C2 IP outbound (use the host's firewall manager — ufw/firewalld/nft)
ufw deny out to 45.x.x.x
# firewalld: firewall-cmd --permanent --direct --add-rule ipv4 filter OUTPUT 0 -d 45.x.x.x -j DROP; firewall-cmd --reload
```

## Step 2 — Disable persistence (every location from step 05)

```bash
systemctl disable --now evil.service; rm -f /etc/systemd/system/evil.service; systemctl daemon-reload
crontab -r -u <user> 2>/dev/null; rm -f /etc/cron.d/evil                  # remove attacker cron
sed -i '/attacker-key/d' /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys   # SSH backdoor
: > /etc/ld.so.preload 2>/dev/null                                        # neutralize preload rootkit
rmmod evilmod 2>/dev/null                                                 # unload malicious kmod (if not protected)
# also clear: rc.local lines, udev RUN+=, XDG autostart, at-jobs found in step 05
```

## Step 3 — Disable accounts & keys

```bash
usermod -L -e 1 <attacker_user>      # lock + expire attacker-created account
# Remove a rogue UID-0 account only after confirming it's not a renamed legit one
passwd -l root                       # if root itself was abused, lock pending rotation
```

## Step 4 — Rotate credentials

Everything exposed is burned: passwords for implicated accounts, any **SSH keys** found/used, and
service-account tokens or secrets that sat in memory (step 08) or on disk. Rotate them at the
source (not just on this host), and revoke the compromised keys everywhere they're trusted.

## Step 5 — Kill, or surgically suspend

```bash
kill -9 <PID>                         # stop the malicious process
# If step 06/08 identified ONE injected thread in an otherwise-legit multithreaded process,
# suspend that specific TID instead of killing the whole process:
kill -STOP <PID>                      # (thread-level control via the toolkit's IR_TARGET_TIDS path)
```

## Step 6 — Quarantine (preserve, don't just delete)

```bash
mkdir -p evidence/quarantine
sha256sum /path/to/implant | tee evidence/quarantine/implant.sha256
# You already recovered deleted-but-running binaries via /proc/<pid>/exe in step 03.
mv /path/to/implant evidence/quarantine/implant.quarantined 2>/dev/null || \
    cp /proc/<PID>/exe evidence/quarantine/implant.recovered   # if it's memory-only
```

## Step 7 — Undo tampering

```bash
systemctl enable --now auditd 2>/dev/null                  # re-enable disabled auditing
setenforce 1 2>/dev/null                                   # re-enable SELinux (or AppArmor)
# restore HISTFILE, remove attacker sudoers drop-ins, re-enable journald persistence
rm -f /etc/sudoers.d/attacker 2>/dev/null; visudo -c
```

## Step 8 — Rollback journal + re-verify

Log every change (what, previous value, UTC, why) — reversible and part of your report. Then re-run
the quick checks from steps 04–05: process back? cron/systemd/authorized_keys recreated? new socket
to the (now-blocked) C2? A good implant has **multiple** persistence tails — if anything returns,
you missed one; go back to step 05/06.

## When to re-image instead

Be honest: **kernel rootkit** (hooked syscalls / hidden module from step 08), a compromise you
can't fully scope, or a host you can't prove is clean → **rebuild from known-good media** and
restore data from a backup predating the compromise window (step 09 tells you when). Always fix the
credentials and the entry vector too — re-imaging while the stolen SSH key still works just gets you
re-owned.

---

➡️ Next: [11-restore-and-recover.md](11-restore-and-recover.md)

*Toolkit parallel: **Step 4** — `Invoke-Eradication-Linux.sh --apply` (dry-run by default)
kills/suspends-thread, quarantines with sha256, disables persistence, revokes accounts, blocks C2,
and journals every action for reversible restore.*
