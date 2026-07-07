# 05 · Analyze the Control Plane (GCP)

*"Who changed what" in the Admin Activity audit logs — the API-level TTPs SCC's known-pattern
detectors miss. Shared framing: [../aws/05-analyze-control-plane.md](../aws/05-analyze-control-plane.md).*

Each pattern is a **finding to adjudicate** (step 07), tagged with ATT&CK.

---

## The high-value audit-log patterns

### Persistence & privilege escalation (SA keys + IAM)

```bash
AA=$CASE/evidence/admin_activity.json
grep -E 'CreateServiceAccountKey|CreateServiceAccount' $AA          # durable downloadable credential
grep -E 'SetIamPolicy' $AA                                          # role grants (check the delta)
grep -E 'generateAccessToken|signJwt|GenerateAccessToken' $AA       # SA impersonation
```

| Pattern | Meaning | ATT&CK |
|---|---|---|
| `CreateServiceAccountKey` (user-managed) | Durable, exfiltratable credential | T1098.001 |
| `SetIamPolicy` granting **Owner/Editor** to a new member | Priv-esc | T1098 |
| `generateAccessToken` / impersonation of a privileged SA | Borrow permissions without a key | T1078.004 |
| SA created + granted role + key created in sequence | Backdoor identity | T1136 |

### Public exposure — the GCP tell

```bash
grep -E 'SetIamPolicy' $AA | grep -E 'allUsers|allAuthenticatedUsers'   # resource opened to the world
```

- `SetIamPolicy` adding **`allUsers`/`allAuthenticatedUsers`** to a bucket/resource → **T1530**
  (public data exposure), near-conclusive when unexpected.

### Defense evasion (logging)

```bash
grep -E 'DeleteSink|UpdateSink|_Default|storage.buckets.setIamPolicy' $AA   # log sink tampering
```

- **Log-sink deletion/redirection** or disabling Data Access logging → **T1562.008**. Note the UTC —
  a blind spot starts there.

### Execution / impact & network exposure

```bash
grep -E 'compute.instances.insert|SetMetadata|startup-script' $AA   # new instances / startup-script persistence
grep -E 'compute.firewalls.insert|compute.firewalls.patch' $AA      # firewall opened
```

- **`compute.instances.insert`** at volume (esp. large machine types) → crypto-mining impact.
- **Instance metadata / startup-script change** → persistence + code execution (T1059).
- **Firewall opened to `0.0.0.0/0`** on a sensitive port → exposure (T1562.007).

## Read each hit like an analyst

Capture the five facts from the audit record: `authenticationInfo.principalEmail` (who),
`methodName` (what), `timestamp` (UTC), `requestMetadata.callerIp` (from where), and
`request`/`response` (specifics). Map confirmed techniques onto the **ATT&CK Cloud coverage grid**;
blanks are gaps — especially initial access (leaked SA key? OAuth? metadata theft on a VM?).

---

➡️ Next: [06-analyze-data-plane-and-identity.md](06-analyze-data-plane-and-identity.md)

*Toolkit parallel: `adjudicate_cloud.py`'s `normalize_gcp_audit` emits these; every run writes the
coverage grid.*
