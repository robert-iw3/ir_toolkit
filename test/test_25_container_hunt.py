"""Container runtime + Kubernetes workload hunt (container_hunt.py).

Closes the Collection gap (no docker/containerd/pod/EKS-AKS-GKE collection). Pure
analyzers over `docker inspect` / `kubectl get -o json`; flags real escape/privilege
techniques. Schema-conformant so findings merge into Combined_Findings.
"""
import datetime
import json
import os
import subprocess
import sys

from conftest import LINUX_HUNT

sys.path.insert(0, LINUX_HUNT)
import container_hunt as ch          # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(LINUX_HUNT), "..", "reporting"))
import finding_schema               # noqa: E402


def types(f):
    return {x["Type"] for x in f}


# ── container runtime ────────────────────────────────────────────────────────
def test_privileged_container():
    f = ch.analyze_container_inspect([{"Name": "/evil", "HostConfig": {"Privileged": True}}])
    assert "Privileged Container" in types(f) and f[0]["Severity"] == "High"


def test_host_namespace_container():
    f = ch.analyze_container_inspect([{"Name": "c", "HostConfig": {"NetworkMode": "host"}}])
    assert "Container Host Namespace" in types(f)


def test_docker_socket_mount():
    f = ch.analyze_container_inspect([{"Name": "c", "HostConfig": {
        "Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}}])
    assert "Docker Socket Mount" in types(f)


def test_sensitive_host_mount():
    f = ch.analyze_container_inspect([{"Name": "c", "Mounts": [
        {"Source": "/etc", "Destination": "/host-etc"}]}])
    assert "Sensitive Host Mount" in types(f)


def test_dangerous_capabilities():
    f = ch.analyze_container_inspect([{"Name": "c", "HostConfig": {
        "CapAdd": ["SYS_ADMIN", "NET_RAW"]}}])
    cap = [x for x in f if x["Type"] == "Dangerous Container Capabilities"]
    assert cap and "SYS_ADMIN" in cap[0]["Details"] and "NET_RAW" not in cap[0]["Details"]


def test_benign_container_silent():
    f = ch.analyze_container_inspect([{"Name": "web", "HostConfig": {
        "Privileged": False, "NetworkMode": "bridge", "Binds": ["/data/app:/app:ro"]},
        "Config": {"User": "1000"}}])
    assert f == []


# ── kubernetes pods ──────────────────────────────────────────────────────────
def test_pod_host_pid():
    f = ch.analyze_k8s_pods({"items": [{"metadata": {"name": "p", "namespace": "ns"},
                                        "spec": {"hostPID": True, "containers": []}}]})
    assert "Pod Host Namespace" in types(f)


def test_pod_hostpath_sensitive():
    f = ch.analyze_k8s_pods({"items": [{"metadata": {"name": "p", "namespace": "ns"},
        "spec": {"volumes": [{"name": "v", "hostPath": {"path": "/"}}], "containers": []}}]})
    assert "Pod hostPath Mount" in types(f)


def test_pod_privileged_container():
    f = ch.analyze_k8s_pods({"items": [{"metadata": {"name": "p", "namespace": "ns"},
        "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]}}]})
    assert "Privileged Pod Container" in types(f)


def test_pod_priv_escalation_and_caps():
    f = ch.analyze_k8s_pods({"items": [{"metadata": {"name": "p", "namespace": "ns"},
        "spec": {"containers": [{"name": "c", "securityContext": {
            "allowPrivilegeEscalation": True, "capabilities": {"add": ["SYS_PTRACE"]}}}]}}]})
    assert "Pod Privilege Escalation Allowed" in types(f)
    assert "Pod Dangerous Capabilities" in types(f)


def test_benign_pod_silent():
    f = ch.analyze_k8s_pods({"items": [{"metadata": {"name": "p", "namespace": "ns"},
        "spec": {"containers": [{"name": "c", "securityContext": {
            "privileged": False, "allowPrivilegeEscalation": False}}]}}]})
    assert f == []


# ── kubernetes RBAC ──────────────────────────────────────────────────────────
def test_rbac_cluster_admin_to_serviceaccount_is_high():
    f = ch.analyze_k8s_rbac({"items": [{"metadata": {"name": "evil-binding"},
        "roleRef": {"name": "cluster-admin"},
        "subjects": [{"kind": "ServiceAccount", "name": "default"}]}]})
    cab = [x for x in f if x["Type"] == "ClusterAdmin Binding"]
    assert cab and cab[0]["Severity"] == "High" and "default" in cab[0]["Details"]


def test_rbac_system_masters_is_low():
    f = ch.analyze_k8s_rbac({"items": [{"metadata": {"name": "cluster-admin"},
        "roleRef": {"name": "cluster-admin"},
        "subjects": [{"kind": "Group", "name": "system:masters"}]}]})
    assert f and f[0]["Severity"] == "Low"


def test_rbac_non_admin_binding_silent():
    f = ch.analyze_k8s_rbac({"items": [{"metadata": {"name": "view"},
        "roleRef": {"name": "view"}, "subjects": [{"kind": "User", "name": "alice"}]}]})
    assert f == []


# ── schema + CLI ─────────────────────────────────────────────────────────────
def test_findings_conform_to_schema():
    f = (ch.analyze_container_inspect([{"Name": "c", "HostConfig": {"Privileged": True}}])
         + ch.analyze_k8s_pods({"items": [{"metadata": {"name": "p", "namespace": "n"},
             "spec": {"hostNetwork": True, "containers": []}}]})
         + ch.analyze_k8s_rbac({"items": [{"metadata": {"name": "b"},
             "roleRef": {"name": "cluster-admin"},
             "subjects": [{"kind": "ServiceAccount", "name": "x"}]}]}))
    assert finding_schema.validate(f, adjudicated=False) == []


def test_cli_offline_inputs(tmp_path):
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    cf = tmp_path / "containers.json"
    cf.write_text(json.dumps([{"Name": "/evil", "HostConfig": {"Privileged": True}}]))
    r = subprocess.run(
        [sys.executable, os.path.join(LINUX_HUNT, "container_hunt.py"),
         "--report-dir", str(tmp_path), "--stamp", stamp,
         "--containers-file", str(cf), "--quiet"],
        capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    out = tmp_path / f"Container_Findings_{stamp}.json"
    assert out.exists()
    assert any(x["Type"] == "Privileged Container" for x in json.loads(out.read_text()))
