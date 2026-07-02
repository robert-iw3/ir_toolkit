"""Volatility 3 plugin: tasks holding io_uring rings.

io_uring performs file/network I/O without the syscalls most EDR/eBPF hooks watch, so it is a
growing anti-EDR technique. A file whose f_op is io_uring_fops is a ring.

Walks each task's fd array and compares f_op to io_uring_fops directly - it does NOT resolve
file paths (a dentry walk), which is what made the naive version too slow on a large image.
A total-fd budget bounds the worst case regardless.
"""
from volatility3.framework import constants, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.objects import utility
from volatility3.plugins.linux import pslist

# Hard cap on total fd inspections so the plugin always terminates in bounded time.
_FD_BUDGET = 200000


class IoUring(interfaces.plugins.PluginInterface):
    """Per-task io_uring ring count (path-free)."""

    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 0)

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
            return                      # symbol absent -> cannot detect cheaply; skip
        file_type = vmlinux.symbol_table_name + constants.BANG + "file"
        budget = _FD_BUDGET
        for task in tasks:
            if budget <= 0:
                break
            try:
                files = task.files
                if not files or int(files) == 0:
                    continue
                fdt = files.fdt
                max_fds = int(fdt.max_fds)
                if max_fds <= 0 or max_fds > (1 << 20):
                    continue
                n = min(max_fds, budget)
                budget -= n
                fds = utility.array_of_pointers(
                    fdt.fd, count=n, subtype=file_type, context=self.context)
                rings = 0
                for filp in fds:
                    try:
                        if filp and int(filp) != 0 and int(filp.f_op) == iou_fops:
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
