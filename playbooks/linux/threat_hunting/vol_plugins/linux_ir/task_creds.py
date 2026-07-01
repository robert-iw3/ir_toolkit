"""Volatility 3 plugin: per-task credential consistency.

A task whose `cred` pointer differs from its `real_cred` has had its credentials overwritten
after fork - the residue of a kernel privesc such as a magic-signal "become root" (Diamorphine).
"""
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist


class TaskCreds(interfaces.plugins.PluginInterface):
    """Per-task cred vs real_cred + uid/euid."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _generator(self, tasks):
        # Anomaly-only (like the stock integrity plugins): emit a task only when its cred
        # pointer differs from real_cred - a credential overwrite. 0 rows on a clean host.
        for task in tasks:
            try:
                if int(task.cred) == int(task.real_cred):
                    continue
            except Exception:
                continue
            uid = euid = -1
            try:
                uid, euid = int(task.cred.uid.val), int(task.cred.euid.val)
            except Exception:
                pass
            try:
                comm = utility.array_to_string(task.comm)
            except Exception:
                comm = "?"
            yield (0, (int(task.pid), comm, uid, euid, False))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Comm", str), ("UID", int), ("EUID", int), ("CredMatchesReal", bool)],
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"])))
