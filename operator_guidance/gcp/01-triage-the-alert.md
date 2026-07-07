# 01 · Triage the Alert (GCP)

*"SCC raised a finding / the SIEM flagged odd API activity / a service-account key showed up in a
public repo / a surprise billing spike — and I can't nail it down yet."*

Decide **real or noise, and how urgent**. Shared method:
[../windows/01-triage-the-alert.md](../windows/01-triage-the-alert.md) and cloud framing in
[../aws/01-triage-the-alert.md](../aws/01-triage-the-alert.md).

---

## Extract who/what/where/when

- **Principal** — a user (`user:...`), a **service account** (`...@...iam.gserviceaccount.com`), or
  an SA key ID.
- **Action** — the method (`google.iam.admin.v1.CreateServiceAccountKey`, `SetIamPolicy`,
  `storage.objects.get` at volume, `compute.instances.insert`).
- **Source** — `callerIp` + geo; corporate/VPN egress or a hosting-provider IP?
- **When** — UTC; widen the window as needed. **Where** — which project (and where in the hierarchy).

## Light, read-only first look

```bash
CASE=IR-...; PROJECT=my-proj; PRINCIPAL="bob@example.com"

# Recent audit-log activity by this principal (Admin Activity is always on)
gcloud logging read \
  "protoPayload.authenticationInfo.principalEmail=\"$PRINCIPAL\"" \
  --project=$PROJECT --freshness=7d --limit=50 --format=json > $CASE/evidence/triage_activity.json

# SCC findings for context (org-level)
gcloud scc findings list <ORG_ID> --filter='state="ACTIVE"' --format=json 2>/dev/null | head > $CASE/evidence/scc.json

# What can this principal do? (blast-radius preview) — IAM bindings mentioning it
gcloud projects get-iam-policy $PROJECT --format=json | \
  jq '.bindings[] | select(.members[]|test("'"$PRINCIPAL"'"))' > $CASE/evidence/triage_iam.json

# Any user-managed keys on the SA (persistence tell)
gcloud iam service-accounts keys list --iam-account=<sa-email> --format=json 2>/dev/null
```

**Read it in seconds:**
- **`callerIp`** from a hosting provider / unexpected country → strong signal.
- **Sensitive methods**: `CreateServiceAccountKey` (durable creds), `SetIamPolicy` adding a role or
  **`allUsers`**, `generateAccessToken` (SA impersonation), `compute.instances.insert` (crypto-mining),
  `DeleteSink`/`_Default` sink change (log evasion) → escalate.
- A **new user-managed SA key**, or activity from a normally-idle SA → suspicious.

> Don't delete keys or bindings yet unless it's actively causing harm (step 02).

## Make the call

Clear FP (known automation/expected) → close. Can't tell (common) → open, go to step 02. Obvious
active intrusion (leaked SA key used from a strange IP, instances spun up, IAM opened to `allUsers`,
logging sink deleted) → open + escalate + identity-first containment now.

---

➡️ Next: [02-contain-identity-first.md](02-contain-identity-first.md)
