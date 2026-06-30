# Cloud-IR Lab Environment

A charge-free, scenario-driven mock of AWS / Azure / GCP that exercises the **real** cloud-IR
workflow (`Invoke-IRCollection-Cloud.sh` → `collect/<provider>.sh` → `adjudicate_cloud.py` →
reporting) against realistic per-attack telemetry. No provider is ever contacted, so nothing is
billable. This is the regression + refinement harness for the detection logic before it touches a
real environment.

## How it works

```
test/lab/
├── mock_env/            scenario-driven mock CLIs (shadow real aws/az/gcloud on PATH)
│   ├── _lab.py          the engine: answers each query from the active scenario
│   ├── aws  az  gcloud  thin shims -> _lab.py (pass their name via IR_LAB_CLI)
└── scenarios/           one JSON file per attack (telemetry + expectations)
```

`test/test_40_lab_scenarios.py` is parametrized over `scenarios/*.json`. For each it:

1. puts `mock_env/` on `PATH` and points `IR_LAB_SCENARIO` at the file,
2. runs the actual collection orchestrator for the scenario's provider/target,
3. asserts the attack was **detected** (expected finding `types`), **adjudicated** on the right
   ATT&CK technique (`mitre_any`) and verdict (`min_verdict`), and **mapped** on the coverage grid
   (`tactics`), with the full report pipeline producing `Incident_Report.md`.

Unlike the simple recording mocks in `test/mocks/` (one canned answer per query), `_lab.py` serves
telemetry that differs per attack, so the same code path is validated against many realistic
environments.

## Adding a scenario

Drop a new `scenarios/<name>.json` — it is picked up automatically. Shape:

```jsonc
{
  "name": "aws-iam-privesc",
  "provider": "aws",                       // aws | azure | gcp
  "description": "what the attacker did",
  "collect": {"target": "10.0.0.5", "c2_ips": "", "c2_domains": ""},
  "aws": {                                  // provider block: telemetry the mock serves
    "cloudtrail": [ {raw CloudTrail record}, ... ],
    "guardduty": {"Findings": [...]},
    "credential_report_csv": "user,arn,...\n...",
    "access_analyzer": {"findings": [...]},
    "flow_log_lines": ["... 45.66.77.88 ..."]
  },
  "expect": {
    "types":   ["Cloud Control-Plane Activity"],    // each must be produced
    "mitre_any": ["T1098.001"],                     // at least one must appear
    "min_verdict": "Likely True Positive",          // strongest finding must reach this
    "tactics": ["Privilege Escalation"]             // each must be ✅ on the coverage grid
  }
}
```

Provider blocks the engine understands:

| Provider | Keys |
|---|---|
| `aws` | `cloudtrail`, `guardduty`, `credential_report_csv`, `access_analyzer`, `flow_log_lines`, `regions` |
| `azure` | `activity_log`, `signin_logs`, `oauth_grants`, `directory_audit`, `inbox_rules`, `risky_users`, `diagnostic_settings` |
| `gcp` | `audit_log`, `scc`, `iam_policy`, `service_accounts` + `sa_key_rows`, `flow_log`, `firewall_rules` |

Anything unspecified gets a safe empty default so the happy path still completes.

## Refining detection logic

When a scenario fails, it means the workflow under-detects (or mis-adjudicates) that attack — fix the
analyzer in `playbooks/cloud/cloud_*.py`, not the test. (Example: the `aws-exfil-and-c2` scenario first
surfaced that the ATT&CK coverage grid was missing the *Command and Control* tactic.)

## Run it

```bash
cd test/
pytest test_40_lab_scenarios.py -v
```
