# 05 · Analyze the Control Plane (AWS)

*"Who changed what." Read the raw CloudTrail management events for the attacker's actual API-level
TTPs — the things GuardDuty's known-pattern detectors miss.*

Provider detectors (GuardDuty) catch known patterns; the attacker's real moves live in the raw log.
Each pattern below is a **finding to adjudicate** in step 07, tagged with ATT&CK.

---

## The high-value CloudTrail patterns (hunt each)

### Identity persistence & privilege escalation

```bash
CT=$CASE/evidence/cloudtrail_mgmt.json
# New access key created — for ANOTHER user = persistence backdoor
grep -E 'CreateAccessKey|CreateUser|CreateLoginProfile' $CT
# Admin policy attached / inline policy added / role trust widened
grep -E 'AttachUserPolicy|AttachRolePolicy|PutUserPolicy|PutRolePolicy|UpdateAssumeRolePolicy' $CT
```

| Pattern | Why it matters | ATT&CK |
|---|---|---|
| `CreateAccessKey` for another principal | Durable second credential | T1098.001 |
| `AttachUserPolicy`/`PutUserPolicy` with `AdministratorAccess` or `*:*` | Priv-esc | T1098 |
| `UpdateAssumeRolePolicy` adding an external/attacker principal | Cross-account persistence | T1098 |
| `CreateUser` + policy + key in sequence | Backdoor account | T1136.003 |

### Defense evasion — the loudest, most important tell

```bash
# Anyone turning OFF the sensors is doing the attacker's evasion — near-conclusive
grep -E 'StopLogging|DeleteTrail|UpdateTrail|DeleteFlowLogs|DeleteDetector|UpdateDetector|DeleteConfigRule' $CT
```

`StopLogging`/`DeleteTrail`/`DeleteDetector` = **T1562.008**, true-positive class. Note the exact
UTC — everything after it is a blind spot in your timeline.

### Root & MFA anomalies

```bash
grep -E '"userIdentity".*"type":"Root"' $CT                 # root use = should be near-zero
# Console logins without MFA
grep -A3 'ConsoleLogin' $CT | grep -iE 'MFAUsed.*No|"MFAUsed":"No"'
```

- **Root account API/console use** → T1078.004, investigate every one.
- **`ConsoleLogin` with `MFAUsed:No`** from an odd IP → likely compromised credential.

### Public exposure & data-theft prep

```bash
grep -E 'PutBucketPolicy|PutBucketAcl|PutObjectAcl' $CT          # bucket made public
grep -E 'ModifySnapshotAttribute|ModifyImageAttribute|SharedWithAccounts' $CT   # snapshot/AMI shared out
grep -E 'AuthorizeSecurityGroupIngress' $CT | grep '0.0.0.0/0'   # SG opened to the world
```

| Pattern | Meaning | ATT&CK |
|---|---|---|
| `PutBucketPolicy`/`PutObjectAcl` → public | Data exposure / exfil staging | T1530 |
| `ModifySnapshotAttribute` shared to another account | Exfil via snapshot copy | T1537 |
| SG/`0.0.0.0/0` on a sensitive port | Exposure for access/exfil | T1562.007 |

## Read the log like an analyst

For each hit, capture the **five facts** from the CloudTrail record: `userIdentity` (who),
`eventName` (what), `eventTime` (when, UTC), `sourceIPAddress` (from where), and
`requestParameters`/`responseElements` (the specifics). Those become timeline rows and adjudication
inputs.

> **The coverage grid.** As you go, map each confirmed technique onto the ATT&CK Cloud matrix. The
> *blank* tactics are your gaps — "I see persistence and exposure but no initial access" means go
> find the entry (a leaked key? a phished console login? an SSRF hitting the metadata endpoint?).

---

➡️ Next: [06-analyze-data-plane-and-identity.md](06-analyze-data-plane-and-identity.md)

*Toolkit parallel: `adjudicate_cloud.py`'s `normalize_cloudtrail` emits exactly these findings on
the shared ladder, and every run writes `Attack_Coverage_<stamp>.md` (the auto-filled matrix).*
