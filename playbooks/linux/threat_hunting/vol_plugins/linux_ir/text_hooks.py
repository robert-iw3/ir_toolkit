"""Volatility 3 plugin: inline-hook detection on sensitive kernel functions.

Reads the first bytes of high-value syscall/handler symbols and flags a prologue that begins
with a trampoline (jmp/int3/indirect-jmp) - an inline hook installed by hand, without ftrace
(so linux.tracing.ftrace does not see it). A relative call (0xE8, the ftrace __fentry__ stub)
is normal and not flagged.
"""
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

# Handlers rootkits commonly hook for hiding / interception. Missing symbols are skipped.
_TARGETS = (
    "__x64_sys_getdents64", "__x64_sys_getdents", "__x64_sys_kill", "__x64_sys_read",
    "__x64_sys_openat", "__x64_sys_bpf", "__x64_sys_finit_module", "__x64_sys_init_module",
    "ip_rcv", "tcp4_seq_show", "udp4_seq_show", "packet_rcv",
)


def _is_trampoline(b):
    if not b:
        return False, ""
    op = b[0]
    if op in (0xE9, 0xEB, 0xCC):                 # near/short jmp, int3
        return True, b[:6].hex()
    if op == 0xFF and len(b) > 1 and b[1] == 0x25:  # jmp [rip+disp]
        return True, b[:6].hex()
    return False, ""


class TextHooks(interfaces.plugins.PluginInterface):
    """Inline hooks on sensitive kernel .text symbols."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _generator(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[vmlinux.layer_name]
        for name in _TARGETS:
            try:
                addr = vmlinux.get_absolute_symbol_address(name)
                data = layer.read(addr, 8)
            except Exception:
                continue
            hooked, pro = _is_trampoline(data)
            if hooked:
                yield (0, (name, pro, True))

    def run(self):
        return renderers.TreeGrid(
            [("Symbol", str), ("Prologue", str), ("Hooked", bool)], self._generator())
