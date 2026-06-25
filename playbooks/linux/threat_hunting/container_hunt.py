#!/usr/bin/env python3
"""
container_hunt.py - container runtime + Kubernetes workload forensics -> findings.

Closes the Collection gap: no docker/containerd/pod/EKS-AKS-GKE collection. Inspects
container runtimes (docker / podman / nerdctl `inspect` JSON) and Kubernetes objects
(`kubectl get -o json` for pods + RBAC) and emits findings in the common schema:

    {Timestamp, Severity, Type, Target, Details, MITRE}

so container/K8s risks merge into Combined_Findings for adjudication. Focuses on real
container-escape / privilege techniques (privileged, host namespaces, docker.sock and
sensitive host mounts, dangerous capabilities, cluster-admin bindings) - not noise.

Read-only. Degrades gracefully: missing runtime/kubectl -> that source is skipped.

Usage:
    container_hunt.py [--report-dir DIR] [--stamp STAMP] [--quiet]
                      [--containers-file F] [--pods-file F] [--rbac-file F] [--live]
Writes Container_Findings_<stamp>.json and prints the path.
"""
import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys

# Host paths that, mounted into a container, enable escape or host control.
SENSITIVE_HOST_PATHS = ("/", "/etc", "/root", "/var/run", "/run", "/proc", "/sys",
                        "/var/run/docker.sock", "/var/lib/kubelet", "/home")
DANGEROUS_CAPS = {"SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "NET_ADMIN", "DAC_READ_SEARCH",
                  "DAC_OVERRIDE", "BPF", "SYS_BOOT", "ALL"}


def now():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _finding(severity, ftype, target, details, mitre):
    return {"Timestamp": now(), "Severity": severity, "Type": ftype,
            "Target": target, "Details": details, "MITRE": mitre}


# -- container runtime (docker / podman / nerdctl inspect) ---------------------
def analyze_container_inspect(data):
    """Take `docker inspect`/`podman inspect` output (list of container objects) -> findings."""
    out = []
    containers = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    for c in containers:
        if not isinstance(c, dict):
            continue
        name = (c.get("Name") or c.get("Id") or "unknown").lstrip("/")
        hc = c.get("HostConfig", {}) if isinstance(c.get("HostConfig"), dict) else {}
        cfg = c.get("Config", {}) if isinstance(c.get("Config"), dict) else {}

        if hc.get("Privileged") is True:
            out.append(_finding("High", "Privileged Container", name,
                                "Container runs --privileged (full host device access).",
                                "T1610 (Deploy Container), T1611 (Escape to Host)"))

        for ns, key in (("network", "NetworkMode"), ("PID", "PidMode"), ("IPC", "IpcMode")):
            if str(hc.get(key, "")).lower() == "host":
                out.append(_finding("High", "Container Host Namespace", name,
                                    f"Container shares the host {ns} namespace ({key}=host).",
                                    "T1611 (Escape to Host)"))

        # Mounts: Binds ("/host:/ctr") + Mounts[].Source.
        sources = []
        for b in hc.get("Binds") or []:
            if isinstance(b, str):
                sources.append(b.split(":")[0])
        for m in c.get("Mounts") or []:
            if isinstance(m, dict) and m.get("Source"):
                sources.append(m["Source"])
        for src in sources:
            s = src.rstrip("/") or "/"
            if "docker.sock" in s:
                out.append(_finding("High", "Docker Socket Mount", name,
                                    f"Container mounts the Docker socket ({src}) - full daemon control.",
                                    "T1610 (Deploy Container)"))
            elif s in SENSITIVE_HOST_PATHS:
                out.append(_finding("High", "Sensitive Host Mount", name,
                                    f"Container mounts sensitive host path {src}.",
                                    "T1610 (Deploy Container), T1611 (Escape to Host)"))

        caps = {str(x).replace("CAP_", "").upper() for x in (hc.get("CapAdd") or [])}
        bad = sorted(caps & DANGEROUS_CAPS)
        if bad:
            out.append(_finding("Medium", "Dangerous Container Capabilities", name,
                                f"Container adds capabilities: {', '.join(bad)}.",
                                "T1611 (Escape to Host)"))
    return out


# -- Kubernetes pods ----------------------------------------------------------
def _pod_items(data):
    if isinstance(data, dict) and "items" in data:
        return data["items"]
    if isinstance(data, dict) and data.get("kind") == "Pod":
        return [data]
    return data if isinstance(data, list) else []


def analyze_k8s_pods(data):
    """`kubectl get pods -A -o json` -> findings for risky pod specs."""
    out = []
    for pod in _pod_items(data):
        if not isinstance(pod, dict):
            continue
        meta = pod.get("metadata", {})
        spec = pod.get("spec", {}) if isinstance(pod.get("spec"), dict) else {}
        name = f"{meta.get('namespace', 'default')}/{meta.get('name', 'unknown')}"

        for key, ns in (("hostNetwork", "network"), ("hostPID", "PID"), ("hostIPC", "IPC")):
            if spec.get(key) is True:
                out.append(_finding("High", "Pod Host Namespace", name,
                                    f"Pod uses {key}=true (shares host {ns}).",
                                    "T1611 (Escape to Host)"))

        for v in spec.get("volumes") or []:
            hp = v.get("hostPath", {}) if isinstance(v, dict) else {}
            path = (hp or {}).get("path", "")
            if path and ((path.rstrip("/") or "/") in SENSITIVE_HOST_PATHS or "docker.sock" in path):
                out.append(_finding("High", "Pod hostPath Mount", name,
                                    f"Pod mounts host path {path} via hostPath volume.",
                                    "T1610 (Deploy Container)"))

        containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
        for ctr in containers:
            sc = ctr.get("securityContext", {}) if isinstance(ctr, dict) else {}
            if sc.get("privileged") is True:
                out.append(_finding("High", "Privileged Pod Container", name,
                                    f"Container '{ctr.get('name')}' is privileged.",
                                    "T1610 (Deploy Container), T1611 (Escape to Host)"))
            if sc.get("allowPrivilegeEscalation") is True:
                out.append(_finding("Medium", "Pod Privilege Escalation Allowed", name,
                                    f"Container '{ctr.get('name')}' allowPrivilegeEscalation=true.",
                                    "T1611 (Escape to Host)"))
            caps = (((sc.get("capabilities") or {}).get("add")) or [])
            bad = sorted({str(c).replace("CAP_", "").upper() for c in caps} & DANGEROUS_CAPS)
            if bad:
                out.append(_finding("Medium", "Pod Dangerous Capabilities", name,
                                    f"Container '{ctr.get('name')}' adds: {', '.join(bad)}.",
                                    "T1611 (Escape to Host)"))
    return out


# -- Kubernetes RBAC ----------------------------------------------------------
def analyze_k8s_rbac(data):
    """`kubectl get clusterrolebindings -o json` -> findings for cluster-admin grants."""
    out = []
    items = data.get("items", []) if isinstance(data, dict) else (data or [])
    for crb in items if isinstance(items, list) else []:
        if not isinstance(crb, dict):
            continue
        role = (crb.get("roleRef") or {}).get("name", "")
        if role == "cluster-admin":
            subs = crb.get("subjects") or []
            who = ", ".join(f"{s.get('kind')}:{s.get('name')}" for s in subs
                            if isinstance(s, dict)) or "(no subjects)"
            name = (crb.get("metadata") or {}).get("name", "unknown")
            # System defaults bind cluster-admin to system:masters - flag non-system subjects.
            non_system = [s for s in subs if isinstance(s, dict)
                          and not str(s.get("name", "")).startswith("system:")]
            sev = "High" if non_system else "Low"
            out.append(_finding(sev, "ClusterAdmin Binding", name,
                                f"ClusterRoleBinding '{name}' grants cluster-admin to: {who}.",
                                "T1078 (Valid Accounts), T1098 (Account Manipulation)"))
    return out


# -- live collection ----------------------------------------------------------
def _run_json(cmd):
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
        return json.loads(cp.stdout) if cp.stdout.strip() else None
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def collect_live():
    """Best-effort live collection from whatever runtime/kubectl is present."""
    findings = []
    runtime = next((r for r in ("docker", "podman", "nerdctl") if shutil.which(r)), None)
    if runtime:
        ids = subprocess.run([runtime, "ps", "-aq"], capture_output=True, text=True,
                             timeout=30, check=False).stdout.split()
        if ids:
            data = _run_json([runtime, "inspect", *ids])
            if data:
                findings += analyze_container_inspect(data)
    if shutil.which("kubectl"):
        pods = _run_json(["kubectl", "get", "pods", "-A", "-o", "json"])
        if pods:
            findings += analyze_k8s_pods(pods)
        rbac = _run_json(["kubectl", "get", "clusterrolebindings", "-o", "json"])
        if rbac:
            findings += analyze_k8s_rbac(rbac)
    return findings


def _load(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser(description="Container + Kubernetes workload hunt")
    ap.add_argument("--report-dir", default=".")
    ap.add_argument("--stamp", default=datetime.datetime.now().strftime("%Y%m%d_%H%M%S"))
    ap.add_argument("--containers-file", help="docker/podman inspect JSON (offline)")
    ap.add_argument("--pods-file", help="kubectl get pods -o json (offline)")
    ap.add_argument("--rbac-file", help="kubectl get clusterrolebindings -o json (offline)")
    ap.add_argument("--live", action="store_true", help="collect from local runtime/kubectl")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    findings = []
    any_input = False
    if args.containers_file:
        any_input = True
        findings += analyze_container_inspect(_load(args.containers_file) or [])
    if args.pods_file:
        any_input = True
        findings += analyze_k8s_pods(_load(args.pods_file) or [])
    if args.rbac_file:
        any_input = True
        findings += analyze_k8s_rbac(_load(args.rbac_file) or [])
    if args.live or not any_input:
        findings += collect_live()

    out_path = os.path.join(args.report_dir, f"Container_Findings_{args.stamp}.json")
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2)
    if not args.quiet:
        from collections import Counter
        print(f"[container] {len(findings)} finding(s) "
              f"{dict(Counter(f['Severity'] for f in findings))}")
    print(out_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
