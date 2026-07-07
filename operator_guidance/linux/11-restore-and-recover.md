# 11 · Restore & Recover (Linux)

*Threat gone. Return the host to a known-good, working state — and make sure it stays clean.*

Full reasoning: [../windows/11-restore-and-recover.md](../windows/11-restore-and-recover.md).
Linux specifics below.

---

## Step 1 — Confirm clean before you reconnect

Re-run the fast checks (steps 04–05): no malicious process/socket, no recreated
cron/systemd/`authorized_keys`, no new UID-0 account, no beacon to the blocked C2. Anything back →
you missed a persistence tail; return to step 05/06 before restoring connectivity.

## Step 2 — Restore the firewall (minus the C2 blocks)

Return the pre-incident ruleset you saved in step 02 with the host's own manager, but **keep the
confirmed-C2 blocks and the lateral-movement blocks** in place until the entry vector is closed.

```bash
# ufw:  reset then re-apply your known-good policy, or restore the saved /etc/ufw config
# firewalld:  restore saved zone config, firewall-cmd --reload
# nftables (authoritative on modern hosts):
nft -f evidence/nft_before.rules
nft list ruleset | grep -iE '45\.x\.x\.x|drop'   # verify C2 + lateral blocks survived
```

Remove the temporary IR admin-access rule once you no longer need it.

## Step 3 — Close the entry vector (or it recurs)

Eradication removed the implant; recovery must remove the **way in** (from your step 09 timeline):

| Entry vector | The fix |
|---|---|
| SSH brute force / weak creds | Key-only auth, disable password + root login, `fail2ban`, MFA, the rotation from step 10 |
| Exploited web app / service | Patch it; take it off the internet / behind a WAF until patched |
| Vulnerable/misconfigured service | Patch, least-privilege the service account, disable unused modules |
| Malicious cron/package supply-chain | Verify package sources, pin/verify signatures |
| Container escape | Drop `privileged`, remove `docker.sock` mounts/host namespaces, apply seccomp/AppArmor, fix RBAC |

## Step 4 — Patch & harden

Apply outstanding updates, re-enable and *tighten* auditing you wish you'd had (auditd rules, SSH
logging), confirm SELinux/AppArmor is enforcing, and remove the attacker's footholds' preconditions
(world-writable dirs, excess SUID, permissive sudoers).

## Step 5 — Return to service, or rebuild?

- **Return** if eradication was surgical, no kernel-level compromise, high confidence.
- **Rebuild from known-good image** if there was a kernel rootkit (step 08), root/credential
  compromise you can't fully scope, or you can't *prove* every foothold is gone. Restore data from a
  backup predating the compromise window.

## Step 6 — Watch it

Keep the C2 blocks and heightened monitoring for a defined window; a "low and slow" implant may
sleep for days. Re-check in 24–72h for reconnect attempts, recreated persistence, or the rotated
credentials/keys being used from an odd source.

---

➡️ Next: [12-report-and-retrospective.md](12-report-and-retrospective.md)

*Toolkit parallel: **Step 5** — `06_restore.sh` does the sha256-verified restore of the saved
ruleset while preserving `IOCs.json` C2 blocks; the eradication journal makes every change
reversible.*
