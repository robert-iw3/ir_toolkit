# 07 · Adjudicate Findings (GCP)

*Turn findings into defensible verdicts. Same ladder and cloud trust model as
[../aws/07-adjudicate-findings.md](../aws/07-adjudicate-findings.md); GCP-specific cues below.*

---

## The ladder & cloud trust model (unchanged)

```
False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive
```

- **SCC HIGH/CRITICAL**, **log-sink deletion/Data-Access-logging disabled**, **confirmed C2 in flow
  logs** → **True-Positive class**.
- SA-key creation / IAM grants / `allUsers` exposure, **unambiguous** → Likely TP; ambiguous or
  informational SCC → Indeterminate.
- Bulk reads by an **automation** SA → Indeterminate (verify).

## GCP-specific context checks

### 1 — Human vs automation vs service account

Most GCP principals are **service accounts** — a huge share of activity is legitimate automation.
The question is whether the SA's action matches its purpose, and whether it was **recently given a
new key or a new impersonation grant** (step 05/06 = strong signal it's attacker-controlled). A
**human** user doing SA-key creation or bulk reads is more suspicious than the same by a pipeline SA.

### 2 — Source IP & geo

`callerIp` from a hosting provider / country you don't operate in → suspicious. Offline GeoIP; don't
whois the attacker's IP live.

### 3 — Known deploy / Terraform pattern?

Rule out IaC: does a Terraform/Deployment-Manager/Cloud-Build run explain the IAM change or SA-key
creation at that timestamp? A key created by your CI SA differs from one created by a dormant user.

### 4 — Corroboration (the multiplier)

Strong GCP convergence: **leaked SA key used from a VPS IP → `SetIamPolicy` granting Owner →
`compute.instances.insert` (mining) → bulk `storage.objects.get` → `DeleteSink`**. Any one alone may
be Indeterminate; together it's an unambiguous kill chain.

## Worked examples

| Finding | Context | Verdict |
|---|---|---|
| `DeleteSink` on `_Default` | No change ticket, odd IP | **True Positive** (T1562.008) |
| `CreateServiceAccountKey` by `terraform@` SA | Matches a Cloud Build run | **Likely FP** (verify pipeline) |
| Same by `user:bob@` from a VPS IP | Bob on PTO, unusual project | **True Positive** (persistence, T1098.001) |
| `SetIamPolicy` adding `allUsers` to a bucket | No business reason, prod data | **True Positive** (T1530 exposure) |
| Bulk reads by `svc-analytics@` | Nightly, same volume, from GCE | **Likely FP** (automation baseline) |

## Extract IOCs

For every True / Likely True: **principals** (users, **SAs**, **rogue SA keys** → `Principals.json`),
**C2 IPs**, rogue resources (attacker instances/keys/bindings), exposed resources (public buckets),
and ATT&CK techniques.

---

➡️ Next: [08-timeline-and-blast-radius.md](08-timeline-and-blast-radius.md)
