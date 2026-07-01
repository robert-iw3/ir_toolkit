"""Volatility 3 plugin: per-task namespace inode ids.

Comparing each task's namespaces against init (PID 1, the host baseline) reveals container
escapes - a task containerized on its mount namespace yet sharing the host pid or net namespace.
"""
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist


class Namespaces(interfaces.plugins.PluginInterface):
    """Per-task mount / pid / net namespace inode numbers."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    @staticmethod
    def _inum(ns):
        # each namespace struct embeds `struct ns_common ns` whose `inum` is the inode id
        try:
            return int(ns.ns.inum)
        except Exception:
            return 0

    def _generator(self, tasks):
        for task in tasks:
            try:
                nsp = task.nsproxy
                mnt = self._inum(nsp.mnt_ns)
                net = self._inum(nsp.net_ns)
                try:
                    pidns = self._inum(nsp.pid_ns_for_children)
                except Exception:
                    pidns = 0
            except Exception:
                continue
            comm = utility.array_to_string(task.comm)
            yield (0, (int(task.pid), comm, str(mnt), str(pidns), str(net)))

    def run(self):
        return renderers.TreeGrid(
            [("PID", int), ("Comm", str), ("MntNs", str), ("PidNs", str), ("NetNs", str)],
            self._generator(pslist.PsList.list_tasks(self.context, self.config["kernel"])))
