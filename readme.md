# IR Toolkit — Offline Incident Response Workflow

Single-command incident response for **Windows**, **Linux**, and **Cloud** (AWS / Azure / GCP).
One invocation per platform runs the whole chain and writes every artifact into a
per-host folder in the project root:

```
collection  →  deeper analysis  →  report generation  →  eradication  →  restoration
```

Collection is read-only and offline. Eradication is dry-run by default and writes a
rollback journal so every change is reversible.

---

## Workflow stages

| Stage | What it does | Output |
|---|---|---|
| **1. Collection** | Forensic snapshot + fileless/EDR hunt + remote-access triage + persistence/config snapshot. Windows also locks the firewall to Default-Deny inbound **first** (containment). | `<host>/` artifacts, `forensics/`, `_runtime_*.log` |
| **2. Analysis** | Adjudicates every raw finding with on-host context and assigns a verdict (`False Positive` → `True Positive`). A validly-signed binary is **not** cleared on signature alone. Cloud telemetry (GuardDuty/SCC/Entra) is normalized and run through the same ladder. Emits `IOCs.json` here, before reporting. | `Adjudication_*.json`, `IOCs.json`, `Evidence/` |
| **3. Reporting** | Correlates the adjudicated findings into reports with no human authoring. | `Incident_Report.md`, `Attack_Graph.md` (Mermaid), `Retrospective.md` (gap analysis), `Timeline.md` (activity vs detection) |
| **4. Eradication** | Removes true-positive-class findings (kill+quarantine, unregister task, remove COM/BITS, stop RMM). Then restores the firewall to known-good **except** known-bad C2 (from `IOCs.json`), which stays blocked/sinkholed. | `Eradication_*.{json,md}`, rollback journal |
| **5. Restoration** | Reverses containment and restores quarantined files **only after sha256-verifying** them against the rollback journal. | restored host |

`IOCs.json` is the machine-readable handoff, emitted in the **analysis** stage (not reporting) so
eradication's known-bad re-block never depends on reports being generated. Every orchestrator also
writes a uniform `_status.json` (`COMPLETED` / `PARTIAL` / `FAILED` + per-phase results + tp_count)
for SOAR gating. All adjudicators emit the one canonical finding schema
(`playbooks/reporting/finding_schema.py`).

---

## Windows

```powershell
# 1. Collection (locks firewall, hunts, adjudicates, writes reports)
powershell -ExecutionPolicy Bypass -NoProfile -File .\Invoke-IRCollection.ps1

# 4. Eradication — dry-run, then apply (restores firewall, keeps known-bad blocked)
.\Invoke-Eradication.ps1 -HostFolder .\<HOST> -MinVerdict "Likely True Positive"
.\Invoke-Eradication.ps1 -HostFolder .\<HOST> -MinVerdict "Likely True Positive" -Apply

# 5. Restoration (false-positive rollback / un-isolate)
.\playbooks\windows\06_Restore-Host.ps1
```

- Hunt scripts: `playbooks/windows/threat_hunting/` (EDR_Toolkit, Get-RemoteAccessTriage,
  Get-PersistenceSnapshot, Analyze-EDRReport, Get-FindingContext).
- Containment: `playbooks/windows/Enforce-StrictFirewall.ps1 -FullInboundLockdown`. The
  pre-lockdown firewall is exported to a `.wfw` backup, recorded in `<host>/_firewall_state.json`.
- Reports: `playbooks/reporting/generate_reports.ps1` (native, no dependency).
- Flags: `-NoFirewallLockdown`, `-AllowInboundPort 5985`, `-SkipReports`, `-CaptureMemory`, `-DeepFileScan`.

## Linux

```bash
# 1. Collection
./Invoke-IRCollection-Linux.sh

# 4. Eradication (dry-run by default)
./Invoke-Eradication-Linux.sh --host-folder ./<HOST>

# 5. Restoration
./playbooks/linux/06_restore.sh
```

- Hunt tools: `playbooks/linux/threat_hunting/` (edr_hunt.py, remote_access_triage.py, adjudicate.py).
- Reports: `playbooks/reporting/generate_reports.py` (canonical, cross-platform).
- Trust anchor: distro-package ownership + integrity. Run as root for full visibility.

## Cloud (AWS / Azure / GCP)

```bash
# 1. Collection (cloud telemetry + report generation, in the project dir)
./Invoke-IRCollection-Cloud.sh --provider aws --target 10.0.0.5 \
    --c2-ips 45.66.77.88 --c2-domains evil.test [--contain]

# 4/5. Eradication + restoration (dry-run by default)
./Invoke-Eradication-Cloud.sh --provider aws --target 10.0.0.5 \
    --host-folder ./aws-10_0_0_5 --apply --restore
```

- Playbooks: `playbooks/cloud/` (forensics, contain, eradicate process/persistence, block C2, restore).
  Provider auto-detected from `--provider`; uses the `aws` / `az` / `gcloud` CLIs.
- Known-bad C2 supplied via `--c2-ips/--c2-domains` (or read from `IOCs.json`) stays blocked
  by `04_block_c2.sh` across restoration.

---

## Reports

The report generator (`playbooks/reporting/generate_reports.{py,ps1}`) reads the per-host folder
and emits:

- **`Incident_Report.md`** — severity, ATT&CK chain, true-positive findings, adjudication funnel,
  remediation, IOC appendix.
- **`Attack_Graph.md`** — Mermaid graph reconstructing the **full chain of events** from the
  findings: each true-positive finding is a node, ordered along the ATT&CK kill chain (and by
  time where known), coloured by tactic, with C2 endpoints branching off. It is built from
  whatever findings exist, so a cryptominer, webshell, cloud-IAM compromise, and a RAT each
  render a different graph (not a fixed template).
- **`Retrospective.md`** — objective post-incident review with **kill-chain coverage and gap
  analysis** (tactics with no evidence collected, indeterminate findings, missing memory image).
- **`Timeline.md`** — chronological events, labelling **activity** time (process/event start) vs
  **detection** time (when the pipeline observed it).
- **`IOCs.json`** — C2 endpoints, file hashes, tools, ATT&CK techniques (emitted in analysis,
  consumed by eradication).

It tolerates PowerShell's UTF-8 BOM and works on Windows, Linux, and cloud finding shapes.

### Cross-host campaign correlation

`playbooks/reporting/correlate_campaign.py --root <dir-of-host-folders>` scans every host
folder's `IOCs.json`, finds indicators shared by more than one host, and emits
`Campaign_Report.md` (shared-IOC table + a Mermaid graph linking hosts through shared C2/hashes/
tools) and `campaign.json`.

## Offline toolkit (optional depth tools)

Run on an internet-connected machine before deploying to an isolated host:

- **Windows** — `Build-OfflineToolkit.ps1 [-IncludeMemory] [-IncludeSysmon]` stages Sysinternals
  (Autoruns, Sigcheck, Handle, …), WinPmem (memory), and the LOLDrivers list into `tools/`.
- **Linux** — `Build-OfflineToolkit-Linux.sh [--include-memory] [--include-cloud] [--check-only]`
  stages **AVML** (Linux memory acquisition, used by the collector's `--capture-memory`) and the
  LOLDrivers list, and **records** the `aws`/`az`/`gcloud` versions the cloud workflow requires
  (too large to bundle — missing ones are flagged, not silently ignored).

Both write a sha256 `tools/STAGED_MANIFEST.json`. The core workflow runs offline without any of
these; they only enable optional depth (e.g. memory capture).