# IR Toolkit — Offline Incident Response Workflow

Single-command incident response for **Windows**, **Linux**, and **Cloud** (AWS / Azure / GCP).

This file is the summary. The detailed, per-platform operating instructions live in:

| Platform | Workflow doc | Runtime |
|---|---|---|
| **Windows** | [WORKFLOW-WINDOWS.md](WORKFLOW-WINDOWS.md) | native PowerShell (no Python on target) |
| **Linux** | [WORKFLOW-LINUX.md](WORKFLOW-LINUX.md) | Python 3 (stdlib) + bash |
| **Cloud** | [WORKFLOW-CLOUD.md](WORKFLOW-CLOUD.md) | Python 3 + bash via `aws`/`az`/`gcloud` |

---

## Executive summary

This toolkit is purpose-built to **steer incident responders and forensic analysts to the right path** — not to make the call for them.

Every collection phase casts the widest possible net. Raw findings from process memory, event logs / journald, file entropy, network connections, registry keys, Amcache/ShimCache execution history, and YARA signatures are gathered without pre-filtering. The subsequent analysis phases then refine that down to the handful of findings that have real investigative value:

1. **Collection** — snapshot everything without judgment. Processes, drivers, network state, logs, memory, execution history, files, persistence. Nothing is excluded at collection time.
2. **Detection** — score-based alerting across all collected data (LOLBin score ≥3, entropy ≥7.2, process hidden from standard API, execution from user-writable paths). Detection logic is never suppressed by publisher or vendor name — a Microsoft-signed binary in `AppData\Roaming` is still flagged.
3. **Adjudication** — on-host context enrichment. Every raw finding is verified against its concrete artifact: signature chain, file existence, install path, binary hash. The verdict ladder is **False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive**. A validly signed binary in a user-writable path earns **Indeterminate**, not clearance.
4. **"Likely True Positive" is the actionable signal.** The adjudicator surfaces findings where the evidence pattern is anomalous but a final call requires analyst context. The toolkit tells you *what to look at* — the analyst confirms whether it is a threat.
5. **Refinement loop** — findings flow detectors → adjudication → reports → eradication. The attack graph clusters TP-class findings into a renderable kill chain (12–15 nodes max). Evidence bundles are written for every TP-class finding.

**Design principle for filtering:** only exclude things that are physically impossible threat vectors. Everything else surfaces with context and confidence; the analyst makes the call. **No network dependency during collection** — tools, YARA rules, and dependencies are staged to USB in advance; the target host is never contacted by the toolkit.

---

## End-to-end lifecycle

One invocation runs the whole chain. Collection is read-only and offline; eradication is
dry-run by default and writes a rollback journal so every change is reversible.

```
collection  →  analysis  →  reporting  →  memory forensics  →  eradication  →  restoration
```

All three platforms follow this shape. Each platform's workflow doc has its own end-to-end
diagram and specifics: [Windows](WORKFLOW-WINDOWS.md) · [Linux](WORKFLOW-LINUX.md) · [Cloud](WORKFLOW-CLOUD.md).

---

## Reports

Every platform writes per-host evidence to `reports/<HOSTNAME>/`. The report generator
(`playbooks/reporting/generate_reports.{py,ps1}`) reads the per-host folder and emits:

- **`Incident_Report.md`** — severity, ATT&CK chain, true-positive findings, adjudication funnel, remediation, IOC appendix.
- **`Attack_Graph.md`** — Mermaid graph reconstructing the chain of events from the findings (each TP finding a node, ordered along the kill chain, coloured by tactic, C2 branching off). Built from whatever findings exist, so different incidents render different graphs.
- **`Retrospective.md`** — objective post-incident review with kill-chain coverage and gap analysis.
- **`Timeline.md`** — chronological events, labelling **activity** time vs **detection** time.
- **`IOCs.json`** — C2 endpoints, file hashes, tools, ATT&CK techniques (emitted in analysis, consumed by eradication).
- **`Principals.json`** — implicated accounts for credential revocation.
- **`_clock.json`** — host timezone / UTC offset / NTP-sync / clock-skew (timeline normalization).
- **`_custody_*.json` + `_custody_log.jsonl`** — chain-of-custody seal of the sha256 manifest (operator identity + GPG/OpenSSL/HMAC signature; `evidence_custody.py --verify` detects tamper).

The optional **AI incident review** (`llm_incident_review.py`) writes `LLM_Incident_Review.{md,json}` — advisory only (`source=LLM`), redaction-first, configurable frontier/local/provider-native model (see [WORKFLOW-CLOUD.md](WORKFLOW-CLOUD.md)).

`IOCs.json` is emitted in the **analysis** stage so eradication's C2 re-block never depends on
reports being generated. Every orchestrator writes a uniform `_status.json`
(`COMPLETED`/`PARTIAL`/`FAILED` + per-phase results + `tp_count`) for SOAR gating.

**Cross-host campaign correlation:** `playbooks/reporting/correlate_campaign.py --root <dir-of-host-folders>`
finds indicators shared by more than one host and emits `Campaign_Report.md` + `campaign.json`.

---

## AI incident review (optional, advisory)

`playbooks/reporting/llm_incident_review.py` runs an LLM over a `reports/<host>/` collection and
writes `LLM_Incident_Review.{md,json}` — a triage summary, likely attack narrative, analyst pivots,
and Indeterminate-resolution suggestions. **Advisory only**: it never changes adjudicated verdicts;
output is flagged `source=LLM`.

Configurable, no SDK dependency (stdlib-only, so it stages to an air-gapped analyst box). Use a
**frontier** API or a **local** OpenAI-compatible server:

```bash
# Frontier (Anthropic Claude)
ANTHROPIC_API_KEY=… python3 playbooks/reporting/llm_incident_review.py \
    --host-folder reports/<host> --provider anthropic --model claude-sonnet-4-6

# Local / offline (Ollama, vLLM, LM Studio, llama.cpp, OpenRouter, …) — any OpenAI-compatible API
python3 playbooks/reporting/llm_incident_review.py --host-folder reports/<host> \
    --provider openai-compatible --base-url http://localhost:11434/v1 --model llama3.1 --no-redact
```

**Guardrails:** internal identifiers (private IPs, usernames, hostnames, emails) are redacted to
placeholders before any frontier call (reversible map kept locally, never sent); evidence is wrapped
in untrusted-data delimiters with an anti-prompt-injection system prompt; output enums are validated.
Redaction is on by default — `--no-redact` only for a local model you trust.

---

## Offline toolkit (optional depth tools)

Run on an internet-connected machine before deploying to an isolated host. Both builders write
a sha256 `tools/STAGED_MANIFEST.json`. The core workflow runs offline without any of these;
they only enable optional depth (memory capture, YARA, extended persistence).

- **Windows** — `Build-OfflineToolkit.ps1 [-IncludeMemory] [-IncludeYaraRules] [-IncludeMemProcFS] [-IncludeVolatility] [-StageSymbols]`
  (memory analysis: **MemProcFS** for the default AFF4 capture; Volatility 3 only for raw/dmp images)
- **Linux** — `Build-OfflineToolkit-Linux.sh [--include-memory] [--include-cloud] [--stage-symbols] [--check-only]`
  (memory analysis: **Volatility 3** wheels + `dwarf2json` + kernel ISF, vendored for offline use)

See each platform's workflow doc and [DEPENDENCIES.md](DEPENDENCIES.md) for the full dependency
inventory and deployment steps.
