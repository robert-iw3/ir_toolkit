# 05 · Analyze the Control Plane (Azure)

*"Who changed what" in the Activity log — the resource-level TTPs Defender's known-pattern detectors
miss. Shared framing: [../aws/05-analyze-control-plane.md](../aws/05-analyze-control-plane.md).*

Each pattern is a **finding to adjudicate** (step 07), tagged with ATT&CK.

---

## The high-value Activity-log patterns

### Privilege escalation (RBAC)

```bash
AL=$CASE/evidence/activity_log.json
grep -iE 'roleAssignments/write|Microsoft.Authorization' $AL     # role assignment created
```

| Pattern | Meaning | ATT&CK |
|---|---|---|
| Role assignment → **Owner / Contributor / User Access Administrator** | Priv-esc | T1098.003 |
| Assignment to an unexpected principal or at subscription scope | Persistence/priv-esc | T1098 |

### Defense evasion — the loudest tell

```bash
grep -iE 'diagnosticSettings/delete|microsoft.insights.*delete|networkSecurityGroups/.*delete' $AL
```

- **Diagnostic-settings deletion** → **T1562.008** (blinding the logs), true-positive class. Note
  the UTC — a blind spot begins there.

### Execution on VMs (control-plane → guest)

```bash
grep -iE 'runCommand|Microsoft.Compute/virtualMachines/runCommand|CustomScriptExtension' $AL
```

- **VM Run Command** or **Custom Script Extension** = the control plane executing code *inside* a
  VM — a common way to run attacker commands with just RBAC rights. T1059.

### Public exposure

```bash
grep -iE 'securityRules/write' $AL      # NSG rule change — check for source '*'/Internet on a sensitive port
```

- **NSG rule opened to the internet** (`0.0.0.0/0` / `Internet`) on RDP/SSH/DB → T1562.007 / exposure.

## Read each hit like an analyst

Capture the five facts from the Activity-log record: `caller` (who), `operationName` (what),
`eventTimestamp` (UTC), `claims.ipaddr` (from where), and the resource + properties (specifics).
Map confirmed techniques onto the **ATT&CK Cloud coverage grid**; blank tactics are gaps to chase
(especially initial access — was it a stolen token? a consented app? see step 06).

---

➡️ Next: [06-analyze-identity-and-m365.md](06-analyze-identity-and-m365.md)

*Toolkit parallel: `adjudicate_cloud.py`'s `normalize_azure_activity` emits these; every run writes
the coverage grid.*
