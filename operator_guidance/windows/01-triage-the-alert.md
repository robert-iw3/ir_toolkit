# 01 · Triage the Alert

*"I got an alert from a SIEM / EDR / antivirus — or something just feels off — and I can't nail
it down yet."*

This is where every investigation starts. The goal of this step is **not** to solve it. It is to
answer one question: **is this worth opening an investigation, and how urgently?**

---

## The situation

An alert fired. Maybe Defender quarantined something. Maybe the SIEM flagged an odd logon. Maybe
a user said their machine is "slow and popping up windows." Right now you have a *signal*, not a
*story*. Do not spiral, and do not overreact — triage it.

---

## Step 1 — Read the alert like an analyst, not a button

Whatever tool fired, pull out the **who / what / where / when**. Write them in your notes.

| Question | What you're extracting |
|---|---|
| **What** fired? | Rule name, signature, file/hash, technique. A generic "malware detected" is weaker than "Mimikatz credential access." |
| **Which host & user?** | Hostname, the account involved. Is it a workstation, a server, a domain controller? |
| **When** (in UTC)? | The event time. Note the host's clock offset — you'll normalize everything to UTC later. |
| **What process / file / IP?** | The concrete artifact: a path, a PID, a parent process, a remote address. |
| **Severity the tool assigned** | A starting point, not the answer. Tools are noisy in both directions. |

> **Beginner tip:** every alert points at a *thing* — a file path, a process name, an IP, a
> user. That thing is your first pivot. The whole investigation grows outward from it.

---

## Step 2 — Ask the four triage questions

You are deciding **real or noise**, and **how bad**.

1. **Is it plausible?** Does the alert match how this host is actually used? "PsExec on a sysadmin's
   jump box" is routine; "PsExec launched by Word on an accountant's laptop" is not.
2. **Is it isolated or one of many?** One alert vs. the same alert across ten hosts changes the
   severity by an order of magnitude. Check the SIEM for siblings.
3. **What's the blast radius if it's real?** Domain admin account? A server with a database?
   Credentials that unlock the rest of the estate?
4. **Is it still happening?** A quarantined dropper from three weeks ago is different from a
   process beaconing *right now*.

---

## Step 3 — Take a *light* first look (read-only, non-alarming)

You can look without tipping anyone off. These are read-only and normal-looking. If the alert
named a host you can reach, from an admin PowerShell:

```powershell
# The process the alert named — with its parent and full command line (the three facts that matter most)
Get-CimInstance Win32_Process -Filter "Name='suspicious.exe'" |
    Select-Object ProcessId, ParentProcessId, CreationDate, CommandLine

# Or resolve a PID the alert gave you
Get-CimInstance Win32_Process -Filter "ProcessId=1234" |
    Select-Object Name, ParentProcessId, CommandLine, CreationDate

# Is that process talking to the internet right now?
Get-NetTCPConnection -State Established |
    Where-Object { $_.OwningProcess -eq 1234 } |
    Select-Object LocalAddress, RemoteAddress, RemotePort, OwningProcess

# Is the file signed, and where does it live? (path + signature = your first verdict input)
Get-AuthenticodeSignature 'C:\path\suspicious.exe' | Select-Object Status, SignerCertificate
Get-Item 'C:\path\suspicious.exe' | Select-Object FullName, CreationTime, Length
```

**How to read it in ten seconds:**
- **Parent + command line** tell the story. `winword.exe → powershell -enc <base64>` is an
  intrusion. `explorer.exe → chrome.exe` is a Tuesday.
- **Path** matters more than name. `C:\Program Files\...` is expected; `C:\Users\bob\AppData\
  Roaming\...` or `C:\Windows\Temp\...` is where malware lives.
- **A live connection to a public IP on an odd port** raises the priority immediately.

> **Do not** kill the process, delete the file, or block the IP yet. You are still looking, not
> acting. (Why: steps 02–03.)

---

## Step 4 — Make the triage call

Decide, and write the decision + reasoning in your notes:

| Verdict | What it looks like | Next move |
|---|---|---|
| **Clear false positive** | Signed vendor binary, expected path, benign parent, no network — and it explains the alert | Document why, close. Done. |
| **Can't tell yet (most common)** | Something is odd but not proven — unsigned, weird path, odd parent, or you simply can't explain it | **Open the investigation.** Go to step 02. |
| **Obvious active intrusion** | Encoded PowerShell from Office, live C2, ransomware note, creds being dumped | **Open + escalate now.** Notify per your RoE, then step 02 immediately. |

The middle row is the whole reason this guide exists. "I can't nail it down" is not a failure —
it is the correct trigger to move from *triage* to *investigation*. You don't need certainty to
proceed; you need enough doubt.

---

## Where you are, and what's next

You've decided this is worth investigating. Before you go digging — which takes time and touches
the host — you stop the bleeding without wrecking the crime scene.

➡️ Next: [02-contain-without-destroying-evidence.md](02-contain-without-destroying-evidence.md)

*Toolkit parallel: the automation skips manual triage and assumes you've already decided to
collect — it opens straight into Phase 0/1 (`Invoke-IRCollection.ps1`). In real life the human
triage call above is what decides whether you run it at all.*
