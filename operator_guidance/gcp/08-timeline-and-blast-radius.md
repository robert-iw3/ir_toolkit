# 08 · Timeline & Blast Radius (GCP)

*Order the story and map everything the identity could reach across the org hierarchy. Shared method:
[../aws/08-timeline-and-blast-radius.md](../aws/08-timeline-and-blast-radius.md).*

---

## Step 1 — Timeline (UTC)

Order the Admin Activity / Data Access / flow events into one UTC line; label activity vs detection
(SCC lags the API call).

```
2026-06-28T22:04Z  Key used: svc-deploy@ SA key from 185.x.x.x (VPS)         ← leaked key, initial access
2026-06-28T22:07Z  SetIamPolicy: user:svc-deploy@ → roles/owner on proj-prod ← priv-esc
2026-06-28T22:10Z  CreateServiceAccountKey on svc-billing@                   ← persistence
2026-06-28T22:35Z  compute.instances.insert x15 n2-highcpu us-central1       ← crypto-mining impact
2026-06-29T01:05Z  storage.objects.get x9,000 gs://customer-data             ← exfil
2026-06-29T01:50Z  DeleteSink _Default                                       ← evasion (blind after)
```

## Step 2 — Cloud kill chain + coverage grid

Map to ATT&CK Cloud; blanks are gaps. Common GCP gap: activity *after* the key was used but not
**how the SA key leaked** (public repo? compromised dev laptop? metadata theft on a VM?) — chase it;
it sets the preventive control (step 11).

## Step 3 — Blast radius across the hierarchy

Scope isn't one project — it's everything the principal could reach given **inherited IAM** and
**impersonation chains**:
- Bindings at **org / folder / project** (inheritance means a folder-level role touches every project
  under it).
- Every SA it can **impersonate** (`TokenCreator`/`serviceAccountUser`) — follow the chain.
- Every **user-managed key** in play — each is independent durable access.

Produce the concrete list of projects, SAs, buckets, and resources in scope — your eradication scope
and "assume-read" exposure.

## Step 4 — Campaign scope

Check the source IP / SA / user-agent across **all projects** (`gcloud projects list`) — a leaked-key
incident is often one of many. Sweep the org.

---

➡️ Next: [09-eradicate.md](09-eradicate.md)
