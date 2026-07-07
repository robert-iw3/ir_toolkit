# 00 · Mindset & First Principles (GCP / Cloud)

Universal principles: [../windows/00-mindset-and-first-principles.md](../windows/00-mindset-and-first-principles.md).
Shared cloud mindset (identity is the perimeter, logs are time-windowed evidence, control vs data
plane, permission-shaped blast radius): [../aws/00-mindset-and-first-principles.md](../aws/00-mindset-and-first-principles.md).
This page adds only what's GCP-specific.

---

## What's different about GCP

- **The resource hierarchy is the blast radius.** Org → Folder → Project → Resource, with IAM
  binding at any level and **inheriting downward**. A role at the org or folder level is vastly more
  powerful than the same role on one project. When you scope an incident, you scope *up* the
  hierarchy, not just the one resource.
- **Service accounts and their keys are the center of gravity.** GCP workloads run *as* service
  accounts. Two attacker moves dominate: **creating a user-managed SA key** (a downloadable, durable
  credential) and **impersonating a service account** (`generateAccessToken` /
  `--impersonate-service-account`) to borrow its permissions without a key. Both are your top
  persistence/priv-esc hunts.
- **Cloud Audit Logs come in streams.** *Admin Activity* (config changes — **always on**), *Data
  Access* (reads/writes to data — **opt-in, usually off**), *System Event*, and *Policy Denied*.
  "Who changed what" is Admin Activity; "who read how much" is Data Access — and you may be blind to
  the latter (a gap to record).
- **Public = `allUsers` / `allAuthenticatedUsers`.** An IAM binding adding those principals exposes a
  resource to the entire internet — GCP's public-bucket equivalent.

## Control plane vs data plane (GCP)

| | Control plane | Data plane |
|---|---|---|
| Question | Who changed what? | Who read/wrote how much? |
| Log | Cloud Audit **Admin Activity** (always on) | Cloud Audit **Data Access** (opt-in) |
| Examples | `serviceAccountKeys.create`, `SetIamPolicy`, firewall open, log-sink delete | bulk `storage.objects.get`/`list` |

## Set up your workspace

```bash
CASE="IR-$(date -u +%Y%m%d)-gcp"; mkdir -p "./$CASE"/{evidence,notes}
gcloud config list --format=json | tee "$CASE/evidence/investigator_context.json"
gcloud projects list --format='value(projectId)' | tee "$CASE/notes/projects.txt"   # sweep them all
gcloud organizations list 2>/dev/null | tee "$CASE/evidence/orgs.txt"
```

Keep a UTC-timestamped notes log. GCP logs are already UTC.

---

➡️ Next: [01-triage-the-alert.md](01-triage-the-alert.md)
