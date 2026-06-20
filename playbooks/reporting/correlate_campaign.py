#!/usr/bin/env python3
"""
correlate_campaign.py — cross-host campaign correlation.

Each host folder's IOCs.json is an island. This scans a directory of host folders,
finds indicators (C2 endpoints, file hashes, RAT tools) shared by more than one
host, and emits a campaign view tying the intrusion together across the fleet:

    Campaign_Report.md   shared-IOC table + per-host summary + a Mermaid graph
                         linking hosts through the indicators they share
    campaign.json        machine-readable: {hosts, shared_iocs, links}

Usage: correlate_campaign.py --root DIR [--out DIR]
  --root  a directory whose immediate subdirectories are per-host collection folders
  --out   where to write the campaign artifacts (default: --root)
"""
import argparse
import json
import os
import re
import sys
from collections import OrderedDict, defaultdict


def _load(path):
    try:
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except Exception:
        return None


def collect(root):
    """Return {host: iocs_dict} for every subfolder that has an IOCs.json."""
    hosts = OrderedDict()
    for name in sorted(os.listdir(root)):
        folder = os.path.join(root, name)
        if not os.path.isdir(folder):
            continue
        iocs = _load(os.path.join(folder, "IOCs.json"))
        if isinstance(iocs, dict):
            hosts[name] = iocs
    return hosts


def correlate(hosts):
    """Map each indicator to the set of hosts exhibiting it; keep shared ones."""
    ind_hosts = defaultdict(set)        # (kind, value) -> {hosts}
    for host, iocs in hosts.items():
        for ep in iocs.get("c2_endpoints", []) or []:
            ind_hosts[("c2", ep.get("host"))].add(host)
        for h in iocs.get("file_hashes_sha256", []) or []:
            ind_hosts[("sha256", h)].add(host)
        for tool in iocs.get("remote_access_tools", []) or []:
            ind_hosts[("tool", tool)].add(host)

    shared = OrderedDict()
    for (kind, value), hset in ind_hosts.items():
        if value and len(hset) > 1:
            shared[(kind, value)] = sorted(hset)
    return shared


def build_links(shared):
    """Pairwise host links keyed by the indicators they share."""
    links = defaultdict(list)
    for (kind, value), hset in shared.items():
        for i in range(len(hset)):
            for j in range(i + 1, len(hset)):
                links[(hset[i], hset[j])].append(f"{kind}:{value}")
    return links


def _nid(host):
    return "H_" + re.sub(r"[^A-Za-z0-9_]", "_", host)


def md_campaign(hosts, shared, links):
    L = ["# Campaign Correlation", ""]
    L.append(f"Correlated **{len(hosts)} host(s)**; "
             f"**{len(shared)} shared indicator(s)** link them into a campaign."
             if shared else
             f"Correlated **{len(hosts)} host(s)**; no indicators are shared "
             f"(hosts appear independent).")
    L.append("")
    L.append("## Hosts")
    L.append("")
    L.append("| Host | C2 endpoints | Hashes | Tools |")
    L.append("|---|---:|---:|---:|")
    for host, iocs in hosts.items():
        L.append(f"| {host} | {len(iocs.get('c2_endpoints', []) or [])} | "
                 f"{len(iocs.get('file_hashes_sha256', []) or [])} | "
                 f"{len(iocs.get('remote_access_tools', []) or [])} |")
    L.append("")

    if shared:
        L.append("## Shared indicators (campaign linkage)")
        L.append("")
        L.append("| Indicator | Kind | Hosts |")
        L.append("|---|---|---|")
        for (kind, value), hset in shared.items():
            L.append(f"| `{value}` | {kind} | {', '.join(hset)} |")
        L.append("")
        L.append("## Campaign graph")
        L.append("")
        L.append("```mermaid")
        L.append("flowchart LR")
        L.append("    classDef host fill:#0f766e,stroke:#5eead4,color:#fff;")
        L.append("    classDef ioc  fill:#7f1d1d,stroke:#fca5a5,color:#fff;")
        for host in hosts:
            L.append(f'    {_nid(host)}["{host}"]:::host')
        seen_ioc = {}
        for n, ((kind, value), hset) in enumerate(shared.items()):
            iid = f"I{n}"
            seen_ioc[(kind, value)] = iid
            L.append(f'    {iid}(["{kind}: {value}"]):::ioc')
            for host in hset:
                L.append(f"    {_nid(host)} --- {iid}")
        L.append("```")
        L.append("")
    return "\n".join(L)


def generate(root, out=None):
    out = out or root
    hosts = collect(root)
    shared = correlate(hosts)
    links = build_links(shared)

    report = os.path.join(out, "Campaign_Report.md")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write(md_campaign(hosts, shared, links))
    data = OrderedDict([
        ("host_count", len(hosts)),
        ("hosts", list(hosts.keys())),
        ("shared_iocs", [{"kind": k, "value": v, "hosts": h}
                         for (k, v), h in shared.items()]),
        ("links", [{"hosts": list(pair), "via": via} for pair, via in links.items()]),
    ])
    with open(os.path.join(out, "campaign.json"), "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    return {"report": report, "host_count": len(hosts),
            "shared": len(shared), "links": len(links)}


def main(argv=None):
    p = argparse.ArgumentParser(description="Cross-host campaign correlation.")
    p.add_argument("--root", required=True)
    p.add_argument("--out", default=None)
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)
    res = generate(args.root, args.out)
    if not args.quiet:
        print(f"[+] {res['host_count']} host(s), {res['shared']} shared IOC(s), "
              f"{res['links']} link(s) -> Campaign_Report.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
