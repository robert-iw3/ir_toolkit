#!/usr/bin/env python3
"""
cloud_posture.py - point-in-time attack-surface (exposure) analysis. Where
cloud_controlplane.py flags the *event* that opened a hole, this reads the *current state*
of the perimeter: security groups / NSGs / firewall rules open to the internet and public
storage buckets. These explain how the breach was reachable and seed eradication targets.

Mostly normalizes telemetry the collectors already gather (security_groups.json,
azure_nsg_rules.json, gcp_firewall_rules.json) plus a public-bucket sweep. Exposure is
Indeterminate by default (it may be intentional); world-open admin ports (SSH/RDP) and
public buckets are likely-true-positive.
"""
from cloud_findings import finding

WORLD = {"0.0.0.0/0", "::/0", "*", "internet"}


def _is_world(cidr):
    return str(cidr).strip().lower() in WORLD


def _spans_admin_port(proto, frm, to):
    """True if a port range covers SSH(22)/RDP(3389) or is all-ports."""
    if str(proto) in ("-1", "all", "*"):
        return True
    if frm is None or to is None:
        return False
    try:
        lo, hi = int(frm), int(to)
    except (TypeError, ValueError):
        return False
    return lo <= 22 <= hi or lo <= 3389 <= hi


def _port_range_is_admin(port):
    """Admin-port test for an Azure destinationPortRange string ('*', '22', '0-65535')."""
    port = str(port or "").strip()
    if port in ("*", ""):
        return True
    if "-" in port:
        lo, hi = (port.split("-") + [port])[:2]
        return _spans_admin_port("tcp", lo, hi)
    return port in ("22", "3389")


def _exposure(target, detail, admin):
    verdict = "Likely True Positive" if admin else "Indeterminate"
    return finding("Cloud Exposure", target, detail,
                   "T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)",
                   verdict, "High" if admin else "Low", severity="High" if admin else "Medium")


def normalize_security_groups(data):
    """AWS describe-security-groups -> exposure findings for 0.0.0.0/0 ingress."""
    out = []
    groups = (data or {}).get("SecurityGroups", []) if isinstance(data, dict) else (data or [])
    for sg in groups if isinstance(groups, list) else []:
        if not isinstance(sg, dict):
            continue
        gid = sg.get("GroupId") or sg.get("GroupName") or "security-group"
        for perm in sg.get("IpPermissions", []) or []:
            if not isinstance(perm, dict):
                continue
            world = any(_is_world(r.get("CidrIp", "")) for r in perm.get("IpRanges", []) or []
                        if isinstance(r, dict)) or \
                any(_is_world(r.get("CidrIpv6", "")) for r in perm.get("Ipv6Ranges", []) or []
                    if isinstance(r, dict))
            if not world:
                continue
            admin = _spans_admin_port(perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
            out.append(_exposure(
                gid, f"Security group {gid} allows ingress from the internet"
                f"{' on an admin port (SSH/RDP)' if admin else ''}", admin))
    return out


def normalize_nsg_rules(data):
    """Azure `network nsg list` -> exposure findings for inbound-allow-from-internet rules."""
    out = []
    nsgs = data if isinstance(data, list) else (data or {}).get("value", []) \
        if isinstance(data, dict) else []
    for nsg in nsgs if isinstance(nsgs, list) else []:
        if not isinstance(nsg, dict):
            continue
        name = nsg.get("name", "nsg")
        for rule in nsg.get("securityRules", []) or []:
            if not isinstance(rule, dict):
                continue
            if str(rule.get("direction", "")).lower() != "inbound" \
                    or str(rule.get("access", "")).lower() != "allow":
                continue
            src = rule.get("sourceAddressPrefix", "")
            srcs = rule.get("sourceAddressPrefixes", []) or [src]
            if not any(_is_world(s) for s in srcs):
                continue
            port = str(rule.get("destinationPortRange", "") or "")
            admin = _port_range_is_admin(port)
            out.append(_exposure(
                f"{name}/{rule.get('name', 'rule')}",
                f"NSG {name} rule allows inbound from the internet (port {port or '*'})", admin))
    return out


def normalize_gcp_firewall(data):
    """GCP `compute firewall-rules list` -> exposure findings for 0.0.0.0/0 ingress allows."""
    out = []
    rules = data if isinstance(data, list) else (data or {}).get("items", []) \
        if isinstance(data, dict) else []
    for rule in rules if isinstance(rules, list) else []:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("direction", "INGRESS")).upper() != "INGRESS":
            continue
        if not rule.get("allowed"):
            continue
        if not any(_is_world(s) for s in rule.get("sourceRanges", []) or []):
            continue
        admin = False
        for a in rule.get("allowed", []):
            proto = str(a.get("IPProtocol", a.get("ipProtocol", "")))
            if proto in ("all", "-1"):
                admin = True
            for p in a.get("ports", []) or []:
                lo_hi = str(p).split("-")
                admin = admin or _spans_admin_port(proto, lo_hi[0], lo_hi[-1])
        out.append(_exposure(
            rule.get("name", "firewall-rule"),
            f"Firewall rule {rule.get('name', '')} allows 0.0.0.0/0 ingress"
            f"{' on an admin port (SSH/RDP)' if admin else ''}", admin))
    return out


def normalize_public_snapshots(data):
    """EBS snapshots shared to all accounts (publicly restorable) -> data-exposure findings."""
    out = []
    snaps = (data or {}).get("Snapshots", []) if isinstance(data, dict) else (data or [])
    for s in snaps if isinstance(snaps, list) else []:
        if not isinstance(s, dict):
            continue
        sid = s.get("SnapshotId", "snapshot")
        out.append(finding(
            "Cloud Exposure", sid,
            f"EBS snapshot {sid} is publicly restorable (shared to all AWS accounts) - "
            f"anyone can copy the disk image.",
            "T1537 (Transfer Data to Cloud Account)", "Likely True Positive", "High"))
    return out


def normalize_public_amis(data):
    """AMIs launchable by all accounts (public) -> image/data-exposure findings."""
    out = []
    imgs = (data or {}).get("Images", []) if isinstance(data, dict) else (data or [])
    for i in imgs if isinstance(imgs, list) else []:
        if not isinstance(i, dict):
            continue
        iid = i.get("ImageId", "ami")
        out.append(finding(
            "Cloud Exposure", iid,
            f"AMI {iid} is public (launchable by all accounts) - image contents exposed.",
            "T1537 (Transfer Data to Cloud Account)", "Likely True Positive", "High"))
    return out


def normalize_imds(data):
    """EC2 instances allowing IMDSv1 (HttpTokens=optional) - an SSRF can then read the
    instance-role credentials from the metadata service without a token."""
    out = []
    insts = (data or {}).get("instances", []) if isinstance(data, dict) else (data or [])
    for i in insts if isinstance(insts, list) else []:
        if not isinstance(i, dict) or str(i.get("HttpTokens", "")).lower() != "optional":
            continue
        iid = i.get("InstanceId", "instance")
        out.append(finding(
            "Cloud Exposure", iid,
            f"Instance {iid} allows IMDSv1 (HttpTokens=optional) - an SSRF can steal the "
            f"instance-role credentials from the metadata service.",
            "T1552.005 (Cloud Instance Metadata API)", "Indeterminate", "Medium",
            severity="Medium"))
    return out


def normalize_public_buckets(data):
    """Public-storage sweep ({"buckets":[{"name","public"}]}) -> exposure findings."""
    out = []
    buckets = (data or {}).get("buckets", []) if isinstance(data, dict) else (data or [])
    for b in buckets if isinstance(buckets, list) else []:
        if not isinstance(b, dict) or not b.get("public"):
            continue
        name = b.get("name", "bucket")
        out.append(finding(
            "Cloud Exposure", name,
            f"Storage bucket {name} is publicly accessible.",
            "T1530 (Data from Cloud Storage)", "Likely True Positive", "High"))
    return out
