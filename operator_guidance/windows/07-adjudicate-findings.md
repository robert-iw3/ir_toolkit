# 07 · Adjudicate Findings

*You have a pile of "suspicious" things. This is where you separate the real threats from the
noise — with evidence, not vibes. It is the most important analytical skill in DFIR.*

---

## The situation

Every collection casts a wide net, so you now have dozens of raw findings. If you act on all of
them you'll break the box and chase ghosts; if you dismiss them you'll miss the implant. The job
is to give **each finding a verdict you can defend**, and to make sure the reports end up
containing only beyond-doubt threats — **without ever silently dropping** something that might
matter.

---

## The verdict ladder

Every finding gets exactly one:

```
False Positive → Likely False Positive → Indeterminate → Likely True Positive → True Positive
```

- **True Positive** — proven malicious, evidence-backed. Goes to eradication.
- **Likely True Positive** — the actionable "**look here first**." Anomalous pattern, final call
  needs analyst context. This is the signal the whole toolkit is built to surface.
- **Indeterminate** — genuinely can't tell yet; needs more evidence (often memory, step 08).
- **Likely FP / FP** — benign, with a recorded reason. Not deleted — *explained*.

> **Nothing is dropped silently.** Anything that doesn't clear the bar goes to a "pivot leads"
> note so the next analyst can still see it. Reducing noise must never blindside the investigation.

---

## The adjudication method: enrich, then judge

For each finding, gather **on-host context** and run it through the tests below in order. The
concrete artifact — not the detector's opinion — decides.

### Step 1 — Signature: valid, absent, or *bad*?

```powershell
Get-AuthenticodeSignature 'C:\path\to\file.exe' | Format-List Status, SignerCertificate, TimeStamperCertificate
```

- **Valid, trusted publisher** → strong *exculpatory* evidence — but see path test next.
- **NotSigned / unsigned** → **weak** signal. Tons of legit software is unsigned. Does *not*
  convict on its own.
- **Bad signature** (revoked, tampered, untrusted root, "HashMismatch") → **strong** signal.
  This is the one that matters.

### Step 2 — Path: where does it live?

```powershell
Get-Item 'C:\path\to\file.exe' | Select-Object FullName, CreationTimeUtc, LastWriteTimeUtc, Length
```

- `C:\Program Files\...`, `C:\Windows\System32\...` → expected.
- `AppData\Roaming`, `AppData\Local\Temp`, `ProgramData\<random>`, `Downloads`, `Public` →
  **suspicious location.** Malware lives in user-writable paths.

> **The combination is the lesson:** a *validly-signed Microsoft binary running from
> `AppData\Roaming`* is **Indeterminate, not cleared.** Valid signature + wrong place = still
> needs answering (could be a legit tool the attacker copied there to LOLBin with).

### Step 3 — Hash it and check reputation

```powershell
Get-FileHash -Algorithm SHA256 'C:\path\to\file.exe'
```

Compare the SHA256 against known-good baselines you trust, and (safely — see step 09) against
threat intel by **hash, not by uploading the file**. A hash known-bad convicts; known-good (from a
trustworthy source, matching the real vendor file) clears.

### Step 4 — Corroboration: does anything else point the same way?

A single weak signal stays weak. **Weak signals only become strong when they stack.** Ask: does
this finding connect to another?

- The odd process (04) is *also* the one with a live connection to a public IP (04) *and* an
  autostart entry (05) *and* an unsigned injected DLL (06) → that convergence is a True Positive.
- A high-entropy file (06) *alone* → **Indeterminate** (entropy is by-design in many legit files).
- A ShimCache entry for a now-missing binary *alone* → **Indeterminate** (normal for installers).

### Step 5 — Rule out the benign explanation

Before you convict, actively try to *clear* it — a good analyst argues both sides:
- Is it a known admin tool used legitimately by this user/role?
- Is the "suspicious" parent actually a known software updater?
- Is the connection to a vendor's real SaaS (verify the domain actually belongs to them)?
- Is it **your own toolkit** (yara64, winpmem, autorunsc, your `python.exe`/`pwsh.exe`)? Those are
  cleared outright — and their recovered strings are never host IOCs.

---

## Worked examples (how the ladder actually lands)

| Finding | Context you gathered | Verdict |
|---|---|---|
| `svchost.exe` in `C:\Users\bob\AppData\Local\Temp` | Unsigned, parent is `winword.exe`, live conn to 45.x.x.x:8443 | **True Positive** (name masquerade + bad parent + C2 all converge) |
| `AnyDesk.exe` in Program Files, signed | Org doesn't use AnyDesk; installed 3 min after the phishing email | **Likely True Positive** (legit tool, illegitimate context — confirm with user/IT) |
| High-entropy `.dat` in a game folder | Signed game, no network, no other signal | **Likely False Positive** (game asset packing) |
| Signed MS binary in `AppData\Roaming` | Valid sig, but no reason to be there; no other signal yet | **Indeterminate** (pull memory / execution history before calling it) |
| `yara64.exe` flagged by a rule | It's your own staged scanner | **False Positive** (own tooling — clear outright) |

---

## Extract IOCs as you confirm (you'll need them twice)

Every time a finding hits **True / Likely True**, record its indicators in a running
`IOCs.json`-style list — you'll feed them to eradication (step 10) and the report (step 12):

- **C2 endpoints** (domains/IPs/ports from step 04)
- **File hashes** (SHA256)
- **Tools/techniques** (ATT&CK IDs — e.g. T1055 injection, T1547 persistence)
- **Implicated accounts** (for credential revocation later)
- **Defender exclusions the attacker added** (tamper IOCs)

---

## Where you are, and what's next

You've turned raw findings into verdicts. But notice how many landed at **Indeterminate** — "need
more evidence." That evidence is almost always in the memory image you captured in step 03. Time
to open it.

➡️ Next: [08-memory-forensics.md](08-memory-forensics.md)

*Toolkit parallel: **Phase 2 — Analyze & adjudicate.** `Get-FindingContext.ps1 -Live` does exactly
this enrichment + verdict ladder, caps weak standalone signals at Indeterminate, clears its own
tooling, and emits `IOCs.json` here (so eradication never waits on reports).*
