"""Volatility 3 plugin: read kernel usermodehelper / persistence globals from the image.

modprobe_path / core_pattern / poweroff_cmd / uevent_helper are run as root on a trigger;
repointing one at an attacker binary is a common privesc / container-escape / persistence
primitive. No stock vol3 plugin exposes these, so the IR engine ships this one.
"""
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements


class KernelGlobals(interfaces.plugins.PluginInterface):
    """Kernel usermodehelper / persistence path globals."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    # char[] globals whose value is a program path or command run by the kernel.
    _GLOBALS = ("modprobe_path", "core_pattern", "poweroff_cmd", "uevent_helper")

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _read_cstr(self, vmlinux, name, maxlen=256):
        """Null-terminated string at a kernel symbol, or None if the symbol is absent."""
        try:
            addr = vmlinux.get_absolute_symbol_address(name)
        except Exception:
            return None
        try:
            data = self.context.layers[vmlinux.layer_name].read(addr, maxlen)
        except Exception:
            return ""
        return data.split(b"\x00", 1)[0].decode("utf-8", errors="replace")

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        for name in self._GLOBALS:
            val = self._read_cstr(vmlinux, name)
            if val is None:
                continue          # symbol not present on this kernel
            yield (0, (name, val))

    def run(self):
        # Column must not lower-case to a Python keyword (vol's JSON renderer builds a
        # namedtuple from the column names) - so "Name", not "Global".
        return renderers.TreeGrid(
            [("Name", str), ("Value", str)], self._generator())
