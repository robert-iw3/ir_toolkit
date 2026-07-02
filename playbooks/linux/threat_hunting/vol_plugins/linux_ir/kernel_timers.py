"""Volatility 3 plugin: armed kernel timers whose callback is unbacked code.

Rootkits arm a timer_list on the per-CPU timer wheel so their code runs periodically with no
owning process. A callback that resolves to no loaded module AND no kernel symbol is unbacked /
injected code - the signal this plugin emits (anomaly-only; a normal timer resolves to a real
module+symbol and is not reported).

Walks each CPU's timer_bases wheel directly (Volatility has no per-cpu helper): per-CPU base
address = timer_bases_offset + __per_cpu_offset[cpu]. Bounded by an hlist guard and the fixed
576-bucket * 3-base wheel, so cost is constant per CPU. x86-64 validated; degrades to empty
(never raises) on any structure/layout it does not understand.
"""
from volatility3.framework import constants, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.symbols.linux.utilities import modules as km

_HLIST_GUARD = 8192          # cap per-bucket walk against a smeared/looped list


class KernelTimers(interfaces.plugins.PluginInterface):
    """Unbacked timer-wheel callbacks (kernel persistence)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64"]),
        ]

    def _generator(self, vmlinux):
        try:
            known = km.Modules.run_modules_scanners(
                context=self.context, kernel_module_name=vmlinux.name,
                caller_wanted_gatherers=km.ModuleGatherers.all_gatherers_identifier)
            ncpu = int(vmlinux.object_from_symbol("nr_cpu_ids"))
            if ncpu <= 0 or ncpu > 8192:
                return
            pco_sym = vmlinux.get_symbol("__per_cpu_offset")
            pco = vmlinux.object(object_type="array", offset=pco_sym.address,
                                 subtype=vmlinux.get_type("pointer"), count=ncpu)
            tb_off = vmlinux.get_symbol("timer_bases").address
            tl_type = vmlinux.symbol_table_name + constants.BANG + "timer_list"
            layer = self.context.layers[vmlinux.layer_name]
        except Exception:
            return                       # unknown layout -> emit nothing, never crash
        seen = set()
        for cpu in range(ncpu):
            try:
                base_addr = tb_off + int(pco[cpu])
                bases = vmlinux.object(object_type="array", offset=base_addr,
                                       subtype=vmlinux.get_type("timer_base"), count=3)
            except Exception:
                continue
            for tb in bases:
                try:
                    vectors = tb.vectors
                except Exception:
                    continue
                for head in vectors:
                    try:
                        node = head.first
                    except Exception:
                        continue
                    guard = 0
                    while node and int(node) != 0 and guard < _HLIST_GUARD:
                        guard += 1
                        addr = int(node)                   # entry is at offset 0 of timer_list
                        if not layer.is_valid(addr, 1):
                            break                          # smeared bucket pointer - stop this list
                        try:
                            timer = self.context.object(tl_type, layer_name=vmlinux.layer_name,
                                                        offset=addr)
                            fn = int(timer.function)
                            nxt = timer.entry.next
                        except Exception:
                            break
                        # A real (even injected) callback is mapped in the kernel layer; an unmapped
                        # .function value is smear, not a finding. Mapped + resolves to no module AND
                        # no symbol = unbacked/injected periodic code.
                        if fn and layer.is_valid(fn, 1) and addr not in seen:
                            seen.add(addr)
                            try:
                                mi, sym = km.Modules.module_lookup_by_address(
                                    self.context, vmlinux.name, known, fn)
                            except Exception:
                                mi, sym = None, None
                            if not mi and not sym:
                                yield (0, (format(fn, "#x"), "-", "-"))
                        node = nxt

    def run(self):
        vmlinux = self.context.modules[self.config["kernel"]]
        return renderers.TreeGrid(
            [("Address", str), ("Symbol", str), ("Module", str)],
            self._generator(vmlinux))
