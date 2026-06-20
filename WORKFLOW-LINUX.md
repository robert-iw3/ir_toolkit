# Linux Workflow

Driven by Python 3 (stdlib) + bash — both present on Linux targets. Collection is
read-only; eradication is dry-run by default with a reversible rollback journal.
Run as root for full visibility (shadow, all `/proc`, every cron); it degrades
gracefully as a normal user.

See [readme.md](readme.md) for the cross-platform overview and adjudication philosophy.

---

## Pipeline

```mermaid
flowchart TD
    A1["Build-OfflineToolkit-Linux.sh
    [--include-memory]"]:::prep
    A1 --> A2[/"tools/ staged: AVML · LOLDrivers cache"/]:::artifact

    A2 --> B0(["TARGET HOST — root (degrades as user)"]):::phase
    B0 --> B1["Invoke-IRCollection-Linux.sh
    [--deep] [--capture-memory]"]:::tool
    B1 --> B2["① Forensics: /proc · net · modules
    cron · auth · SUID · journal export"]:::step
    B2 --> B3{"--capture-memory?"}:::decision
    B3 -->|yes| B4["② AVML → memory image"]:::step
    B3 -->|no| B5
    B4 --> B5["③ EDR/fileless hunt: hidden procs
    memfd · LD_PRELOAD · kmods · SUID · webshell"]:::step
    B5 --> B6["④ Remote-access triage
    reverse shells · RMM · tunnels"]:::step
    B6 --> B7["⑤ Journal analysis: brute force · sudo
    new acct · service/cron · MAC/log tamper"]:::step
    B7 --> B8["⑥ Merge → Adjudication (verdict ladder)
    + Evidence bundles"]:::step
    B8 --> B9[/"IOCs.json · Principals.json
    Incident_Report · Attack_Graph · Timeline"/]:::artifact

    B9 --> D0(["TARGET HOST — root"]):::phase
    D0 --> D1["Invoke-Eradication-Linux.sh --apply
    dry-run by default"]:::tool
    D1 --> D2["Kill · quarantine (sha256) · disable persistence
    revoke accounts · block C2"]:::step
    D2 --> D3[/"06_restore.sh — sha256-verified restore"/]:::artifact

    classDef prep  fill:#1e3a5f,stroke:#3b82f6,color:#e2e8f0
    classDef phase fill:#1e3a5f,stroke:#60a5fa,color:#e2e8f0,rx:20
    classDef tool  fill:#1e293b,stroke:#64748b,color:#cbd5e1
    classDef step  fill:#0f172a,stroke:#334155,color:#94a3b8
    classDef artifact fill:#14532d,stroke:#22c55e,color:#dcfce7
    classDef decision fill:#451a03,stroke:#f97316,color:#fed7aa
```

Output lands in `reports/<hostname>/` (parity with Windows). Every phase emits findings
in the common schema (`Timestamp / Severity / Type / Target / Details / MITRE`) which are
merged into `Combined_Findings_<stamp>.json` and run through the verdict ladder.

Two cross-cutting artifacts are also written: **`_clock.json`** (host timezone / UTC-offset /
NTP-sync / skew, for timeline normalization — `clock_context.py`) and a **chain-of-custody
seal** of the sha256 manifest (`evidence_custody.py` → `_custody_*.json` + `_custody_log.jsonl`;
set `IR_SIGNING_GPG_KEY` / `IR_CUSTODY_HMAC_KEY` to sign, `--verify` to detect tamper).

### Forensics snapshot (`playbooks/linux/00_collect_forensics.sh`)
Processes, network state, loaded kernel modules, persistence locations, cron, at-jobs,
world-writable executables, hidden files, SUID inventory, auth logs, `last`/`lastb`,
current sessions, and a bounded structured journal export (`journal.json`).

### EDR / fileless hunt (`playbooks/linux/threat_hunting/edr_hunt.py`)
Inspects `/proc`, the loaded-module list, persistence locations and writable paths:
hidden processes (thread-group-leader checks), deleted-but-running binaries, anonymous
executable memory maps (`memfd`/fileless), `LD_PRELOAD`/`ld.so.preload` hijacks,
out-of-tree/hidden kernel modules, writable+executable paths, unexpected SUID binaries,
cron/shell-init persistence, webshell patterns, and added capabilities.

### Remote-access triage (`playbooks/linux/threat_hunting/remote_access_triage.py`)
Reverse-shell indicators, RMM/tunnelling tooling, and suspicious remote-session artifacts.

### Container / Kubernetes hunt (`playbooks/linux/threat_hunting/container_hunt.py`)
Workload forensics for container hosts and clusters (Phase ContainerHunt; best-effort —
skips cleanly with no runtime/kubectl). Flags real escape/privilege techniques:

| Source | Detection | ATT&CK |
|---|---|---|
| docker/podman/nerdctl `inspect` | privileged, host namespaces (net/PID/IPC), `docker.sock` mount, sensitive host mounts, dangerous capabilities (SYS_ADMIN/PTRACE/…) | T1610 / T1611 |
| `kubectl get pods` | hostNetwork/hostPID/hostIPC, hostPath to sensitive paths, privileged containers, allowPrivilegeEscalation, dangerous caps | T1610 / T1611 |
| `kubectl get clusterrolebindings` | cluster-admin granted to a ServiceAccount/non-system subject | T1078 / T1098 |

Run standalone (live or offline from saved JSON):
```bash
python3 playbooks/linux/threat_hunting/container_hunt.py --report-dir reports/<host> --live
python3 playbooks/linux/threat_hunting/container_hunt.py --report-dir reports/<host> \
    --containers-file inspect.json --pods-file pods.json --rbac-file crb.json
```

### Journal analysis (`playbooks/linux/threat_hunting/journal_analysis.py`)
The Linux analog of the Windows EventLogAnalysis. Reads `journalctl -o json` (live, bounded
by `--since`/`-n`, or an exported `forensics/journal.json`) and turns systemd-journal / syslog
into findings — closing the credential-access / privilege-escalation / lateral-movement gaps:

| Signal | Detection | ATT&CK |
|---|---|---|
| SSH brute force | N failed logons from one source within a window (escalates to Critical if a successful root logon follows) | T1110 |
| Remote root logon | `Accepted` SSH logon as root | T1021.004 / T1078.003 |
| Sudo abuse | auth failures, `NOT in sudoers`, sudo→shell/implant-dir command | T1548.003 |
| New account | `useradd`/`groupadd` / "new user" | T1136.001 |
| Service persistence | systemd unit executing from an implant dir; RMM service | T1543.002 / T1219 |
| Cron persistence | cron payload in an implant dir, download cradle (`curl\|bash`), or reverse shell | T1053.003 |
| Reverse shell | `bash -i`, `/dev/tcp`, `nc -e`, `socat` one-liners | T1059.004 |
| Log/MAC tamper | journal vacuum, auditd disabled, SELinux/AppArmor disabled | T1070.002 / T1562.001 |
| Unsigned kernel module | out-of-tree / verification-failed module loads (deduped per module) | T1547.006 / T1014 |

Implant detection targets `/tmp`, `/var/tmp`, `/dev/shm` broadly, and `/run`/`/var/run`
only when a payload (hidden file or script/binary) is implied — so tmpfs staging is covered
without flooding on benign systemd runtime activity. Run standalone for offline re-analysis:

```bash
# Live (bounded), writes Journal_Findings_<stamp>.json
python3 playbooks/linux/threat_hunting/journal_analysis.py --report-dir reports/<host> --live

# From an exported journal (offline)
python3 playbooks/linux/threat_hunting/journal_analysis.py \
    --report-dir reports/<host> --input reports/<host>/forensics/journal.json
```

---

## Step 0 — Build the offline toolkit (once, internet-connected machine)

```bash
chmod +x ./Build-OfflineToolkit-Linux.sh
./Build-OfflineToolkit-Linux.sh                  # core tools + LOLDrivers cache
./Build-OfflineToolkit-Linux.sh --include-memory # + AVML memory acquisition
```

## Step 1 — Collection (run on TARGET as root)

Output is written to `reports/<hostname>/`.

```bash
# Standard full run
sudo ./Invoke-IRCollection-Linux.sh

# With memory capture
sudo ./Invoke-IRCollection-Linux.sh --capture-memory

# Full deep filesystem scan + memory
sudo ./Invoke-IRCollection-Linux.sh --deep --capture-memory

# Custom incident ID and output location
sudo ./Invoke-IRCollection-Linux.sh \
    --incident-id "CASE-$(date +%Y%m%d)" --output-root /mnt/usb/evidence
```

| Flag | Effect |
|---|---|
| `--deep` | Full filesystem scan |
| `--capture-memory` | Live memory image via staged AVML |
| `--skip-forensics` | Hunt-only re-run |
| `--skip-hunt` | Forensics-only |
| `--skip-reports` | Skip automated reports |
| `--incident-id ID` | Override auto-generated ID |
| `--output-root DIR` | Write to a specific directory (default `reports/`) |

## Step 4 — Eradication

```bash
sudo ./Invoke-Eradication-Linux.sh --host-folder ./reports/<HOSTNAME>          # dry-run
sudo ./Invoke-Eradication-Linux.sh --host-folder ./reports/<HOSTNAME> --apply  # apply
sudo ./playbooks/linux/07_revoke_credentials.sh \
    --principals-file ./reports/<HOSTNAME>/Principals.json                      # credential revocation
```

## Step 5 — Restoration

```bash
./playbooks/linux/06_restore.sh
```

## Run the Linux/cloud test suite (pytest)

```bash
cd test/
pip install -r requirements.txt
pytest -v                    # full suite
pytest -v -k "journal"       # the journald analyzer
./run_tests.sh               # full suite with coverage
```

- Hunt tools: `playbooks/linux/threat_hunting/` (`edr_hunt.py`, `remote_access_triage.py`, `journal_analysis.py`, `adjudicate.py`)
- Reports: `playbooks/reporting/generate_reports.py` (canonical, cross-platform)
