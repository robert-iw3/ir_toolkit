# 02 · Contain Without Destroying Evidence

*You've decided this is real enough to investigate. Now buy yourself time — carefully.*

Containment is a scalpel, not a hammer. Done right, it stops the attacker from spreading while
*keeping the evidence trail visible*. Done wrong, it blinds your own investigation or detonates
something.

---

## The situation

The attacker may still have hands on keyboard. You want to cut their ability to move *into* and
*across* your network — without cutting the one thread that shows you *where they call home*.

---

## The key idea: block inbound, and make a *conscious* choice about outbound

This surprises beginners, so here's the logic:

- **Block inbound** → kills the attacker's listeners, their lateral movement *into* this host,
  and inbound remote-access sessions. Pure upside, always do it.
- **Outbound is a judgment call, not a default.** Keeping it open lets the implant keep
  **beaconing out to its C2**, and that traffic is exactly what reveals the C2 domains/IPs and
  what's being exfiltrated. Cut egress now and you go blind to the most valuable IOCs. Keep it
  open and the attacker may keep **stealing data** the whole time you watch.

### This is a risk-based decision — weigh it every time

There is no universally correct answer. You are trading **two competing harms**, and the RoE from
step 00 (data sensitivity, legal hold, business impact) drives the call:

| Keep outbound OPEN (observe) | Cut outbound NOW (isolate) |
|---|---|
| ✅ You learn *where* it beacons and what it exfils — high-value IOCs, attribution, campaign scope | ✅ You stop further data loss immediately |
| ✅ Blocking blindly can tip the attacker off (they see the block and burn access) | ✅ Correct when the data at risk is worth more than the intel |
| ❌ **The adversary may exfiltrate more data while you watch** | ❌ You go blind to C2/exfil destinations — weaker IOCs, harder scoping |
| ❌ Ongoing C2 = ongoing attacker control | ❌ May tip off the attacker that they're detected |

**The deciding question: what is the ongoing exfiltration actually costing versus what the C2
visibility is worth?**

- **Lean toward observing** when: little/no sensitive data is exposed, you have egress *visibility*
  (you can watch without letting bulk data leave — e.g. capture/alert on volume), and knowing the
  C2 materially helps (active campaign, multiple hosts).
- **Lean toward cutting** when: the host holds **regulated / crown-jewel / irreplaceable data**,
  you're seeing **active bulk exfil**, ransomware staging, or you simply can't tolerate one more
  byte leaving. Then **isolate fully (block inbound AND outbound) before you investigate** and
  collect with egress monitoring off. You lose *where* it went; you eliminate further loss.

> **Whatever you choose, choose it deliberately and write down why** (and who approved it). "We
> left egress open from 14:00–15:30 UTC to map C2, accepted exfil risk on a host with no regulated
> data, per <name>" is a defensible decision. Leaving it open by *accident* while data walks out
> the door is not. And if you observe, keep the window **short and bounded** — map the C2, then cut
> it (step 10); don't leave it open indefinitely.

The rest of this guide assumes the **observe** posture (Default-Deny inbound, Allow outbound) for
the analysis window, because that's the default when data risk is low. If you chose to isolate
fully, skip the "keep outbound open" parts below and jump straight to full network isolation.

---

## Step 1 — Back up the current firewall state first (so you can restore it)

Always capture the "before" so restoration (step 11) can return known-good rules while keeping
known-bad C2 blocked.

```powershell
netsh advfirewall export "E:\IR-CASE\evidence\firewall_before.wfw"
```

## Don't forget the third axis: lateral (east-west) movement

Inbound/outbound framing is about the *internet*. But in a real intrusion the more urgent
containment goal is often **east-west**: stopping the attacker from hopping from this host to other
internal hosts (and stopping other already-compromised hosts from reaching this one). C2 lives
north-south; **lateral movement lives east-west**, and blocking internet inbound does nothing to
stop an attacker pivoting over SMB/RDP/WinRM/RPC/SSH to the box next door.

So containment has **three** axes, decided independently:

| Axis | Default action | Why |
|---|---|---|
| **Inbound from internet** | Block | Kills external listeners / inbound RA. Pure upside. |
| **Outbound to internet** | Risk-based (observe vs cut) | The exfil-vs-C2-visibility tradeoff above. |
| **East-west (internal peers)** | **Block the lateral protocols** | Stops the attacker spreading and contains the blast radius. |

**Block the lateral-movement protocols** to/from other internal hosts — this is frequently the
single most valuable containment action in an active intrusion: SMB (445), RDP (3389), WinRM
(5985/5986), RPC/DCOM (135 + ephemeral), NetBIOS (137-139), WMI, and SSH (22). The inbound
default-deny below covers *incoming* lateral; add **outbound blocks to internal ranges** for those
ports to stop this host reaching peers, while still allowing its internet egress if you chose the
observe posture.

## Step 2 — Enforce Default-Deny inbound, block lateral, decide outbound

```powershell
# Turn on the firewall for all profiles; deny inbound by default, allow outbound (observe posture)
Set-NetFirewallProfile -All -Enabled True `
    -DefaultInboundAction Block -DefaultOutboundAction Allow

# STOP LATERAL MOVEMENT: block OUTBOUND to internal ranges on the pivot protocols, so a
# compromised host next door can't be reached from here and this host can't spread.
# (Incoming lateral is already covered by DefaultInboundAction Block.)
$lateralPorts = 445,3389,5985,5986,135,139,137,22
New-NetFirewallRule -DisplayName "IR-Block-Lateral-Out" -Direction Outbound -Action Block `
    -Protocol TCP -RemotePort $lateralPorts `
    -RemoteAddress 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16

# Keep YOUR OWN admin access open — but see the caveat below before you trust this hole.
New-NetFirewallRule -DisplayName "IR-Allow-Admin-WinRM" -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 5985 -RemoteAddress <YOUR.ADMIN.IP>
```

> **The management-IP allowance is itself a risk-based choice — not a freebie.** Every hole you
> punch for your own access is also a potential path *for the attacker*:
> - Only allow a **specific, trusted admin source** (a hardened jump host), never a whole subnet.
> - If the intrusion may have reached your **admin network**, that allowed source is a lateral path
>   — prefer **out-of-band** management (iLO/iDRAC/IPMI, hypervisor console, physical/KVM) that
>   doesn't traverse the production network at all.
> - If you're standing at the console, punch **no** hole — full isolation is cleaner.
> - Document the exception (source, port, why) in your notes; remove it in step 11.

**Read it back to confirm:**
```powershell
Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction
Get-NetFirewallRule -DisplayName "IR-*" | Select-Object DisplayName, Direction, Action, Enabled
```

## Step 3 — Choose your isolation level

| Level | How | Use when |
|---|---|---|
| **Inbound-deny + lateral-block** (above) | `Set-NetFirewallProfile` + lateral rules | Default. Contains spread, keeps you connected, keeps egress visible. |
| **Full network isolation** | EDR "isolate host" button, or block inbound+outbound, or pull from VLAN / private isolation VLAN | Crown-jewel data, active ransomware, or spreading worm. |
| **Physical unplug / disable NIC** | `Disable-NetAdapter -Name "Ethernet"` | Last resort — you lose remote access *and* live C2 visibility. |

> **The EDR "isolate host" button is usually the best lateral-containment tool** if you have one —
> it cuts all traffic except the EDR's own management channel (a purpose-built, trusted out-of-band
> path), giving you both full east-west containment and continued control without punching your own
> firewall hole.

> **Do not power off and do not reboot to "isolate."** That destroys RAM (step 03) — the most
> valuable evidence — and can trigger disk-encrypting payloads on shutdown. Network-isolate; keep
> the box running.

---

## Step 4 — Preserve, don't purge

While containing, resist these evidence-destroying reflexes:
- ❌ Don't delete the malware file (you need it for analysis + hashing).
- ❌ Don't kill the process yet (its memory, handles, and live socket are evidence).
- ❌ Don't clear or "clean up" anything.
- ❌ Don't run antivirus "full remediation" (it quarantines/deletes evidence and alters timestamps).
- ✅ Do note the exact time you contained, in UTC, in your notes — it's a timeline anchor.

---

## Where you are, and what's next

The attacker can't reach *in* anymore, but the box is still running and still holds everything —
including the RAM that dies the moment anyone reboots. That is the most volatile evidence you
have, so it goes next, before you do anything else.

➡️ Next: [03-capture-volatile-memory.md](03-capture-volatile-memory.md)

*Toolkit parallel: **Phase 0 — Contain**. `Invoke-IRCollection.ps1` runs
`Enforce-StrictFirewall.ps1` as its very first act (Default-Deny inbound, outbound Allow) and
exports the pre-lockdown `.wfw`. `-NoFirewallLockdown` skips it; `01_Contain-Host.ps1` /
`-FullInboundLockdown -BlockOutbound` is the crown-jewel full-isolation path.*
