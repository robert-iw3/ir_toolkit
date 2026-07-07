# 12 · Report & Retrospective (Linux)

*Write it down so others can trust it — and close the loop so the vector can't recur.*

The report structure, chain-of-custody sealing, and the **preventive-controls feedback loop** are
identical to [../windows/12-report-and-retrospective.md](../windows/12-report-and-retrospective.md)
— read it for the full model. Below is what's Linux-flavored.

---

## The report (same sections)

Executive summary → severity/scope → timeline (UTC) → attack narrative (ATT&CK) → true-positive
findings *with evidence* → adjudication funnel → remediation actions → IOC appendix →
recommendations. Lead with the executive paragraph; back every TP with proof (package-verify
mismatch, deleted-exe + C2 socket, recovered `linux.bash` command), not assertion.

## Seal the evidence

```bash
# Manifest every artifact with its hash + who/when (UTC)
find evidence -type f -exec sha256sum {} \; > _manifest.txt
echo "$(whoami) sealed $(date -u +%FT%TZ)" > _custody.txt
```

## Close the loop — preventive controls (the point of the exercise)

Same principle as the Windows guide: **detection catches it faster next time; prevention makes sure
there is no next time for this vector.** Drive it from the root cause in your step-09 timeline, make
each control a tracked, owned, fleet-wide, *verified* deliverable, and bake it into the baseline
(golden image / config-management). Linux-specific mappings:

| Root-cause vector | Preventive control (removes the vector) |
|---|---|
| SSH brute force / password auth | Key-only auth, disable root+password login, MFA, `fail2ban`/rate-limit — enforce via config management fleet-wide |
| Exploited internet-facing service | Patch SLA, remove from internet / WAF, minimize exposed surface |
| Weak service isolation | seccomp/AppArmor/SELinux profiles, least-privilege service accounts, systemd hardening (`ProtectSystem`, `NoNewPrivileges`) |
| Excess SUID / sudo | Trim SUID inventory, tighten `sudoers`, remove standing root |
| Container escape | Drop `privileged`, no `docker.sock`/host-namespace mounts, Pod Security Standards, fix cluster-admin RBAC |
| Supply-chain / rogue package | Pin + verify signatures, trusted repos only, SBOM |
| Lateral SSH movement | Network segmentation, host firewall east-west deny, bastion-only access, unique keys per host |

> **The loop:** *incident → root-cause vector → preventive control → fleet-wide rollout → verified
> → baked into the config-management baseline.* Push it into Ansible/Puppet/Chef/cloud-init so
> **every** current and future host inherits the fix — not just the victim. A report that ends at
> "we removed the implant" leaves the door open.

## Feed detection too

Push confirmed hashes, C2 IPs, and SSH-key fingerprints into the SIEM/EDR; sweep the fleet for
them; and turn the *behavior* (implant in `/dev/shm` with a socket, `ld.so.preload` write, journal
vacuum) into behavioral detections that survive after the IOCs go stale.

---

## You've completed the loop

Alert you couldn't explain → triage → contain → collect → adjudicate → memory → timeline →
eradicate → restore → report, every step by hand. Now `WORKFLOW-LINUX.md`'s automation will read
like old friends — and you'll know how to check it when it surprises you.

➡️ Other platforms: [../windows/](../windows/) · [../aws/](../aws/) · [../azure/](../azure/) ·
[../gcp/](../gcp/)

*Toolkit parallel: `generate_reports.py` (report/timeline/attack-graph/IOCs), `evidence_custody.py`
(seal/verify), `correlate_campaign.py` (cross-host). The preventive-controls loop is the human
judgment the automation deliberately leaves to the analyst.*
