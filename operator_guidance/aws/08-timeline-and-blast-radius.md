# 08 · Timeline & Blast Radius (AWS)

*Assemble the ordered story, and map everything the compromised identity could reach — because in
cloud, "scope" is permission-shaped, not machine-shaped.*

Shared method: [../windows/09-build-the-timeline-and-chain.md](../windows/09-build-the-timeline-and-chain.md).

---

## Step 1 — Timeline (UTC is free in cloud)

Cloud logs are already UTC, so no clock-skew normalization — just order the CloudTrail/flow/data
events into one line, labeling **activity time** vs **detection time** (GuardDuty often lags the
actual API call by minutes to hours).

```
2026-06-28T22:14Z  ConsoleLogin user/bob  MFAUsed:No  src 185.x.x.x (VPS, RU)   ← initial access
2026-06-28T22:16Z  CreateAccessKey (2nd key for bob)                            ← persistence
2026-06-28T22:20Z  AttachUserPolicy bob AdministratorAccess                     ← priv-esc
2026-06-28T22:40Z  RunInstances x20 p3.2xlarge us-east-2                        ← crypto-mining impact
2026-06-29T01:10Z  GetObject x8,400 s3://customer-pii by user/bob               ← exfil
2026-06-29T01:55Z  StopLogging on org-trail                                     ← defense evasion (blind after here)
```

## Step 2 — Draw the cloud kill chain

Map to ATT&CK Cloud tactics. Fill the **coverage grid** — blank tactics are gaps. A common gap: you
see everything *after* the login but not *how the credential leaked* (public repo? phishing? SSRF +
metadata theft?). Chase the entry — it dictates the preventive control (step 11).

## Step 3 — Blast radius: what could this identity reach?

This is the cloud-specific step. The incident scope isn't "one instance" — it's **every resource the
principal (and every role it can assume) had permission to touch**, across regions and accounts.

```bash
# Enumerate the reachable surface (from step 06's IAM graph)
# 1) Direct permissions of the principal
# 2) Roles it can AssumeRole into (and THOSE roles' permissions — follow the chain)
# 3) Every region the activity touched (attackers spread to unwatched regions)
# 4) Cross-account trust the principal exploited
```

Produce a concrete list: *these buckets, these instances, these roles, in these accounts/regions*.
That list is:
- Your **eradication scope** (step 09) — every credential in it is burned.
- Your **exfil-exposure estimate** — what data the identity *could* have read (assume it did, absent
  data-event proof otherwise).

## Step 4 — OSINT safely, then scope the campaign

Same rules as everywhere (hashes/passive lookups, don't poke live infra). Then check for a
**campaign**:
- Did the same source IP / access key / user-agent touch **other accounts or regions**?
- Are there sibling GuardDuty findings elsewhere in the org?
- A leaked-key incident is often one of many (the same key list dumped in a repo) — sweep the org.

---

➡️ Next: [09-eradicate.md](09-eradicate.md)

*Toolkit parallel: `generate_reports` emits `Timeline.md` + `Attack_Graph.md` + the coverage grid;
`correlate_campaign.py` sweeps cross-account/region indicators; flow-log C2 confirmation upgrades
asserted IOCs to observed.*
