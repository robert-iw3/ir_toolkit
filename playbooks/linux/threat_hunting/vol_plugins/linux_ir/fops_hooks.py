"""Volatility 3 plugin: VFS operation hooks on the /proc root (file/PID hiding).

Rootkits hide PIDs and files by overwriting a function pointer in the /proc root directory's
file_operations (its readdir / iterate_shared) or inode_operations so the listing is filtered.
A VFS handler that resolves to no loaded module is such a hook - the signal this plugin emits
(anomaly-only; a normal handler resolves to a real module+symbol and is not reported).

Targets the exported `proc_root_operations` (file_operations) and `proc_root.proc_iops`
(inode_operations) symbols directly - present across kernels, no fs/dentry traversal. Iterates
whatever function-pointer members each struct actually has (distro-agnostic; field sets differ
between versions). Bounded (~dozens of pointer reads); degrades to empty on unknown layout.
"""
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.linux.utilities import modules as km

# Members that are not VFS handlers - pointers/scalars we must not treat as hookable callbacks.
_SKIP_MEMBERS = frozenset(("owner", "fop_flags"))


class FopsHooks(interfaces.plugins.PluginInterface):
    """Unresolved VFS handlers on /proc root (rootkit file/PID hiding)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _check_ops(self, vmlinux, known, layer, ops_obj, ops_type_name, label):
        """Yield (Object, Op, Module) rows for each function-pointer member of an ops struct whose
        handler is mapped but resolves to no module (a hook). ops_obj is the concrete struct
        object. A member that is null or an unmapped/scalar value is not a live handler - skipped."""
        try:
            members = list(vmlinux.get_type(ops_type_name).members.keys())
        except Exception:
            return
        for name in members:
            if name in _SKIP_MEMBERS:
                continue
            try:
                val = int(getattr(ops_obj, name))
            except Exception:
                continue
            if not val or not layer.is_valid(val, 1):
                continue                     # null / scalar field / smear - not a handler
            try:
                mi, sym = km.Modules.module_lookup_by_address(
                    self.context, vmlinux.name, known, val)
            except Exception:
                mi, sym = None, None
            if not mi and not sym:
                yield (0, (label, name, "-"))

    def _generator(self, vmlinux):
        try:
            known = km.Modules.run_modules_scanners(
                context=self.context, kernel_module_name=vmlinux.name,
                caller_wanted_gatherers=km.ModuleGatherers.all_gatherers_identifier)
            layer = self.context.layers[vmlinux.layer_name]
        except Exception:
            return
        # /proc root directory file_operations (readdir/iterate_shared hook = PID hiding).
        try:
            fops = vmlinux.object_from_symbol("proc_root_operations")
            yield from self._check_ops(vmlinux, known, layer, fops,
                                       "file_operations", "proc_root_operations")
        except Exception:
            pass
        # /proc root inode_operations (lookup hook = file hiding).
        try:
            proc_root = vmlinux.object_from_symbol("proc_root")
            iops_ptr = proc_root.proc_iops
            if iops_ptr and layer.is_valid(int(iops_ptr), 1):
                iops = iops_ptr.dereference()
                yield from self._check_ops(vmlinux, known, layer, iops,
                                           "inode_operations", "proc_root.proc_iops")
        except Exception:
            pass

    def run(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        return renderers.TreeGrid(
            [("Object", str), ("Op", str), ("Module", str)],
            self._generator(vmlinux))
