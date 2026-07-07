# 06 · Hunt the Host (Linux)

*Go looking for the attacker where a casual glance misses them — fileless execution, LD_PRELOAD
and kernel-module rootkits, SUID abuse, webshells, and container escapes.*

Same intent as [../windows/06-hunt-the-host.md](../windows/06-hunt-the-host.md). Each hit here is a
**finding to adjudicate** in step 07, not a conviction. Let the alert and prior findings steer
which hunts you run.

---

## Hunt 1 — Fileless / deleted-binary execution (the Linux signature move)

```bash
# Processes whose executable was deleted or lives in anonymous memory (memfd) = fileless
for p in /proc/[0-9]*; do
    exe=$(readlink "$p/exe" 2>/dev/null)
    case "$exe" in
        *"(deleted)"*|*memfd:*|/tmp/*|/dev/shm/*|/var/tmp/*)
            echo "$p -> $exe";;
    esac
done
```

**Read it for:** any hit is high-signal — recover the binary (`cp /proc/<pid>/exe`) and adjudicate.
Beware legit JIT runtimes (JVM, .NET, browsers, some Python) that also use anonymous exec memory —
those have a *backing* process story; a `memfd:` with a network socket and no parentage does not.

## Hunt 2 — LD_PRELOAD / userland rootkit

```bash
cat /etc/ld.so.preload 2>/dev/null                  # any content = suspicious
# Per-process preload injection
for p in /proc/[0-9]*; do
    tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -q '^LD_PRELOAD=' && echo "LD_PRELOAD in $p"
done
```

## Hunt 3 — Kernel-module rootkit

```bash
lsmod
# A hidden module may be in /proc/modules but missing from `lsmod`, or vice-versa — compare:
diff <(lsmod | awk 'NR>1{print $1}' | sort) <(awk '{print $1}' /proc/modules | sort)
# Recently loaded / out-of-tree modules
dmesg | grep -iE 'module|taint|verification failed'
cat /proc/sys/kernel/tainted    # non-zero often means an out-of-tree/unsigned module loaded
```

## Hunt 4 — SUID / capability abuse (privilege escalation & persistence)

```bash
# Unexpected SUID-root binaries, especially outside standard dirs or shells with SUID
find / -xdev -perm -4000 -type f 2>/dev/null | tee evidence/suid.txt
# File capabilities that grant power without SUID
getcap -r / 2>/dev/null | grep -vE '^/usr/(bin|sbin)/' | tee evidence/caps.txt
```

**Read it for:** a SUID copy of `bash`/`python`/`find` in `/tmp` or a home dir, or `cap_setuid`/
`cap_dac_override` on an unexpected binary — classic root-persistence.

## Hunt 5 — Webshells & world-writable executables (server hosts)

```bash
# Recently-modified scripts in web roots — webshell hunting
find /var/www /srv /usr/share/nginx -type f \( -name '*.php' -o -name '*.jsp' -o -name '*.aspx' \) \
    -newermt '-14 days' 2>/dev/null -exec ls -la {} \;
grep -RilE 'eval\(|base64_decode|system\(|passthru|/dev/tcp|shell_exec' /var/www 2>/dev/null
# World-writable executables anywhere = staging/backdoor risk
find / -xdev -type f -perm -0002 -executable 2>/dev/null | tee evidence/ww_exec.txt
```

## Hunt 6 — Reverse shells & tunnels (network posture)

```bash
# Interpreters/nc/socat with a live outbound socket = live reverse shell
ss -tnp state established | grep -E 'bash|sh|python|perl|nc|socat|ruby'
ps -ef | grep -E 'nc -e|/dev/tcp/|socat .*EXEC|ssh -R|chisel|ngrok' | grep -v grep
```

## Hunt 7 — Container / Kubernetes escape (if this is a container host or node)

The real risk on container hosts isn't the container — it's **escape to the node** or
**cluster-admin**.

```bash
# Container configs: privileged, host namespaces, docker.sock mount, dangerous caps
docker ps -q 2>/dev/null | xargs -r -I{} docker inspect {} \
    --format '{{.Name}} priv={{.HostConfig.Privileged}} pid={{.HostConfig.PidMode}} net={{.HostConfig.NetworkMode}} caps={{.HostConfig.CapAdd}} mounts={{range .Mounts}}{{.Source}};{{end}}'

# Kubernetes: risky pods + cluster-admin bindings to non-system subjects
kubectl get pods -A -o json 2>/dev/null | grep -E 'hostNetwork|hostPID|hostPath|privileged'
kubectl get clusterrolebindings -o wide 2>/dev/null | grep -iE 'cluster-admin'
# Am I inside a container right now?
grep -qaE 'docker|kubepods|containerd' /proc/1/cgroup && echo "running inside a container"
```

**Read it for:** a `privileged` container, `docker.sock` mounted inside a container, host PID/net
namespaces, a `hostPath` mount of `/` or `/etc`, `SYS_ADMIN`/`SYS_PTRACE` caps, or `cluster-admin`
granted to a ServiceAccount — each is an escape/takeover path (T1610/T1611).

## Hunt 8 — YARA & ELF anomalies (targeted)

```bash
# Magic vs extension mismatch, then YARA over a target dir
find /tmp /dev/shm /var/tmp -type f -exec sh -c 'file "$1" | grep -q ELF && echo "$1"' _ {} \;
./yara64 -r rules/linux_index.yar /tmp /dev/shm /home 2>/dev/null
```

---

➡️ Next: [07-adjudicate-findings.md](07-adjudicate-findings.md)

*Toolkit parallel: `edr_hunt.py` (fileless, LD_PRELOAD, kmods, SUID, webshell, behavioral C2
correlation), `remote_access_triage.py` (reverse shells/tunnels/RMM), and `container_hunt.py`
(escape/RBAC) run every hunt here. `thread_inventory.py` then enumerates threads of each flagged
PID so eradication can target the injected thread, not the whole process.*
