# 02 · Contain Without Destroying Evidence (Linux)

*Stop the bleeding — carefully. Same principle as everywhere: cut the attacker's reach without
blinding your own investigation or detonating anything.*

The full reasoning is in
[../windows/02-contain-without-destroying-evidence.md](../windows/02-contain-without-destroying-evidence.md).
This page is the Linux mechanics.

---

## Block inbound — then make a *conscious* choice about outbound

**Block inbound** always: it kills listeners, lateral movement in, and inbound sessions. Pure
upside.

**Outbound is a risk-based judgment, not a default.** You are trading two harms:

| Keep outbound OPEN (observe) | Cut outbound NOW (isolate) |
|---|---|
| ✅ Learn *where* it beacons / exfils — high-value IOCs, scope | ✅ Stop further data loss immediately |
| ✅ Avoid tipping the attacker off with a sudden block | ✅ Right when the data at risk outweighs the intel |
| ❌ **Attacker may exfiltrate more while you watch** | ❌ Go blind to C2/exfil destinations |
| ❌ Ongoing C2 = ongoing control | ❌ May signal to the attacker they're caught |

**The deciding question: is the ongoing exfiltration cost greater than the C2-visibility value?**
Regulated/crown-jewel data, active bulk exfil, or ransomware staging → **cut now**. Low data risk
and an active campaign you need to map → **observe, briefly and deliberately**. Either way, **write
down the choice, the reason, and who approved it**, and if you observe, keep the window short —
map the C2, then cut it in step 10.

## Don't forget the third axis: lateral (east-west) movement

Inbound/outbound is the *internet* axis. The more urgent goal in an active intrusion is often
**east-west**: stop the attacker hopping from this host to internal peers (and stop already-
compromised peers reaching this one). C2 is north-south; **lateral movement is east-west**, and
blocking internet inbound does nothing to stop a pivot over SSH/SMB/RDP to the box next door. Block
the lateral protocols to/from internal ranges — frequently the highest-value containment action:

```bash
# Block outbound to RFC1918 peers on the pivot protocols (ufw example; adapt to firewalld/nft).
# SSH(22) SMB(445) RDP(3389) WinRM(5985/6) RPC(135) VNC(5900) — plus your env's admin protocols.
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  for port in 22 445 3389 5985 5986 135 5900; do
    ufw deny out to "$net" port "$port" proto tcp
  done
done
# (Incoming lateral is already covered by "default deny incoming".)
```

> **The management-IP allowance is itself a risk choice, not a freebie.** Every hole for your own
> access is also a potential attacker path: allow only a **specific hardened jump host**, never a
> subnet; if the intrusion may have reached your admin network, prefer **out-of-band** management
> (IPMI/iDRAC/iLO, hypervisor/cloud serial console) that never touches the production network; at
> the physical console, punch no hole at all. Document the exception and remove it in step 11.

## First: which firewall does this host actually use?

Raw `iptables` is legacy on modern distros — most now front the firewall with **`ufw`**
(Debian/Ubuntu) or **`firewalld`** (RHEL/Fedora/CentOS/SUSE), both sitting on **nftables**
underneath. Editing `iptables` directly on a `firewalld`/`ufw` host fights the manager and gets
reverted. Check first, then use the matching tool:

```bash
command -v ufw && ufw status verbose                  # Debian/Ubuntu front-end
systemctl is-active firewalld && firewall-cmd --state # RHEL/Fedora front-end
nft list ruleset | head                               # the nftables layer both use
iptables -S 2>/dev/null | head                        # legacy/underlying rules
```

## Back up the current firewall state first

```bash
# Save the "before" for whichever stack is in use, so restoration (step 11) can return known-good
nft list ruleset            > evidence/nft_before.rules           # nftables (authoritative on modern hosts)
iptables-save               > evidence/iptables_before.rules 2>/dev/null
ip6tables-save              > evidence/ip6tables_before.rules 2>/dev/null
ufw status verbose          > evidence/ufw_before.txt 2>/dev/null
firewall-cmd --list-all-zones > evidence/firewalld_before.txt 2>/dev/null
cp -a /etc/ufw evidence/ufw_conf 2>/dev/null
cp -a /etc/firewalld evidence/firewalld_conf 2>/dev/null
```

## Apply containment — use the host's own firewall manager

**Observe posture** (deny inbound, allow outbound) — keep your own admin access open:

```bash
# --- ufw (Debian/Ubuntu) ---
ufw default deny incoming
ufw default allow outgoing
ufw allow from <YOUR.ADMIN.IP> to any port 22 proto tcp   # don't lock yourself out
ufw enable

# --- firewalld (RHEL/Fedora) ---
firewall-cmd --set-default-zone=drop                       # drop = deny inbound by default
firewall-cmd --zone=drop --add-rich-rule='rule family=ipv4 source address=<YOUR.ADMIN.IP> port port=22 protocol=tcp accept'
# firewalld does not filter outbound by default — that's the "allow outbound" posture as-is

# --- legacy iptables (only if no manager is present) ---
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s <YOUR.ADMIN.IP> --dport 22 -j ACCEPT
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
```

**Full isolation** (regulated data / active exfil) — deny both directions:

```bash
# --- ufw ---
ufw default deny incoming
ufw default deny outgoing
ufw allow from <YOUR.ADMIN.IP> to any port 22 proto tcp    # keep a mgmt path if remote
ufw allow out to <YOUR.ADMIN.IP> port 22 proto tcp
ufw enable

# --- firewalld: put the interface in the drop zone and add outbound-blocking direct/policy rules ---
firewall-cmd --set-default-zone=drop
firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -m state --state ESTABLISHED -j ACCEPT
firewall-cmd --direct --add-rule ipv4 filter OUTPUT 1 -d <YOUR.ADMIN.IP> -j ACCEPT
firewall-cmd --direct --add-rule ipv4 filter OUTPUT 2 -o lo -j ACCEPT
firewall-cmd --direct --add-rule ipv4 filter OUTPUT 10 -j DROP

# --- legacy iptables ---
iptables -P INPUT DROP; iptables -P OUTPUT DROP
iptables -A INPUT  -i lo -j ACCEPT;  iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT  -p tcp -s <YOUR.ADMIN.IP> --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp -d <YOUR.ADMIN.IP> --sport 22 -j ACCEPT
```

> Whichever tool you use, **verify the result** (`ufw status` / `firewall-cmd --list-all` /
> `nft list ruleset`) — and remember these front-ends persist rules, so note them in your rollback
> journal (step 10) so restoration is clean.

**Containers:** isolate the workload without killing the node — disconnect the container's network
(`docker network disconnect`), apply a restrictive k8s `NetworkPolicy`, or `cordon`/`drain` a
compromised node. For a running container you can freeze it (below) to preserve state.

## Preserve, don't purge

- ❌ Don't `kill` the process, `rm` the binary, or clear logs yet.
- ❌ **Don't reboot or power off** — it destroys RAM (step 03) and can trigger shutdown payloads.
- ✅ To freeze a suspect *without killing it*, use the freezer cgroup or `SIGSTOP` — it stops
  execution while keeping memory, handles, and sockets intact for collection:
  ```bash
  kill -STOP <PID>        # suspend; kill -CONT to resume. State preserved for steps 03-08.
  ```
- ✅ Record the containment time in UTC in your notes — it's a timeline anchor.

---

➡️ Next: [03-capture-volatile-memory.md](03-capture-volatile-memory.md)

*Toolkit parallel: `Invoke-IRCollection-Linux.sh` handles containment; `06_restore.sh` does the
sha256-verified restore of the saved ruleset.*
