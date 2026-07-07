# 06 · Analyze Data Plane & Identity (GCP)

*"Who read how much" (exfil) and "what could this identity reach" (blast radius across the
hierarchy). Shared framing: [../aws/06-analyze-data-plane-and-identity.md](../aws/06-analyze-data-plane-and-identity.md).*

---

## Part A — Data-plane: the exfiltration hunt

Works over **Data Access** audit logs (`storage.objects.get`/`list`) — off by default, so confirm
they were on (step 03) before concluding "no exfil."

```bash
# Bulk object reads per principal
jq -r 'select(.protoPayload.methodName|test("storage.objects.(get|list)")) | .protoPayload.authenticationInfo.principalEmail' \
    $CASE/evidence/data_access.json | sort | uniq -c | sort -rn | head
# Cross-project / cross-bucket copies = staged exfil
grep -E 'storage.objects.create|rewrite|compose' $CASE/evidence/data_access.json
```

| Signal | ATT&CK | Verdict lean |
|---|---|---|
| Bulk object reads by a **human** principal | T1530 | **Likely True Positive** |
| Bulk reads by an **automation** SA (pipeline/backup) | T1530 | **Indeterminate** — verify |
| Cross-project object copy to a foreign bucket | T1537 | **Likely True Positive** |

> **FP discipline (downgrade, never blind):** volume from an automation SA is routine; the same by a
> human, or a cross-project copy, or reads paired with an `allUsers` grant (step 05) are the strong
> signals. Data Access off → record "exfil visibility: none" as a gap, don't conclude "no exfil."

## Part B — Identity: blast radius across the hierarchy

A compromised member/SA's reach = its bindings **at every level** (org/folder/project inherit down)
plus every SA it can **impersonate**. Map it so eradication is complete.

```bash
# Bindings for the principal at each level (inheritance means check ALL)
for lvl in "projects $PROJECT" "resource-manager folders <folder>" "organizations <org>"; do
    gcloud $lvl get-iam-policy --format=json 2>/dev/null | \
      jq '.bindings[] | select(.members[]|test("'"$PRINCIPAL"'")) | {role, members}'
done

# Impersonation chains: can it mint tokens for a more privileged SA?
# Look for roles/iam.serviceAccountTokenCreator or serviceAccountUser on other SAs.
gcloud iam service-accounts get-iam-policy <target-sa> --format=json 2>/dev/null | \
    jq '.bindings[] | select(.role|test("TokenCreator|serviceAccountUser"))'
```

**What you're building:** the set of projects, buckets, SAs, and resources this identity (and its
impersonation chain) could touch — your eradication scope and "assume-read" exposure.

## Part C — Instance credential theft (metadata-endpoint angle)

A common GCP initial access: an app on a Compute instance is exploited, the attacker reads the
**metadata server** for the instance SA's OAuth token, then uses it. The tell: the instance SA's
token used from an IP that **isn't the instance**. Fix (step 10): restrict metadata access, minimal
instance SA scopes, and disable legacy metadata endpoints.

---

➡️ Next: [07-adjudicate-findings.md](07-adjudicate-findings.md)

*Toolkit parallel: `cloud_dataplane.py`'s `normalize_gcp_data_access` does the bulk-read tiering with
the automation-vs-human FP discipline; the IAM graph feeds blast-radius scoping.*
