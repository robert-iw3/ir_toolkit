"""Volatility 3 plugin: tasks holding io_uring rings.

io_uring performs file/network I/O without the syscalls most EDR/eBPF hooks watch, so it is a
growing anti-EDR technique. A file whose f_op is io_uring_fops is a ring.

EXPERIMENTAL / opt-in - NOT in the default plugin set. The fd enumeration resolves each file's
path (a dentry walk), which is slow on a large image, so this is bounded by a hard fd budget
and must not be run on the hot path until rewritten to compare f_op without path resolution.
"""
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.framework.symbols.linux import LinuxUtilities
from volatility3.plugins.linux import pslist

# Hard cap on total fd lookups so a manual run always terminates in bounded time.
_FD_BUDGET = 4000


class IoUring(interfaces.plugins.PluginInterface):
    """Per-task io_uring ring count (experimental, opt-in)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _generator(self, vmlinux, tasks):
        try:
            iou_fops = vmlinux.get_absolute_symbol_address("io_uring_fops")
        except Exception:
            return                      # no symbol -> cannot detect cheaply; skip entirely
        budget = _FD_BUDGET
        for task in tasks:
            if budget <= 0:
                break
            rings = 0
            try:
                for _fd, filp, _path in LinuxUtilities.files_descriptors_for_process(
                        self.context, vmlinux.symbol_table_name, task):
                    budget -= 1
                    if budget <= 0:
                        break
                    try:
                        if int(filp.f_op) == iou_fops:
                            rings += 1
                    except Exception:
                        continue
            except Exception:
                continue
            if rings:
                yield (0, (int(task.pid), utility.array_to_string(task.comm), "", rings))

    def run(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        return renderers.TreeGrid(
            [("PID", int), ("Comm", str), ("Path", str), ("Rings", int)],
            self._generator(vmlinux, pslist.PsList.list_tasks(self.context, self.config["kernel"])))
